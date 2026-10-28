#!/usr/bin/env python3
"""Read-only, dependency-free AWS permission probe for this AgentCore CTF.

Gets fresh temporary credentials from the configured IMDSv2 endpoint, signs a
small set of AWS API requests with SigV4, and prints no credential or data body.
Only a successful request proves access to the particular action and resource.
"""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

TIMEOUT = 6
MAX_REPLY = 8 * 1024 * 1024
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def no_proxy_call(url, *, method="GET", headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    with NO_PROXY.open(req, timeout=3) as res:
        return res.read(MAX_REPLY).decode("utf-8", "replace")


def metadata_credentials():
    base = os.environ.get("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://169.254.169.254")
    parsed = urllib.parse.urlsplit(base)
    if (parsed.scheme != "http" or not parsed.netloc or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("metadata endpoint must be an HTTP origin")
    base = base.rstrip("/")
    token = no_proxy_call(base + "/latest/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "120"})
    headers = {"X-aws-ec2-metadata-token": token}
    body = no_proxy_call(base + "/latest/meta-data/iam/security-credentials/", headers=headers).strip()
    try:
        obj = json.loads(body)
    except ValueError:
        role = body.splitlines()[0].strip()
        if not role or "/" in role or ".." in role:
            raise ValueError("unrecognized IMDS role name")
        obj = json.loads(no_proxy_call(base + "/latest/meta-data/iam/security-credentials/" + urllib.parse.quote(role), headers=headers))
    if obj.get("Code", "Success") != "Success":
        raise ValueError("metadata service did not return successful credentials")
    keys = ("AccessKeyId", "SecretAccessKey", "Token")
    if not all(isinstance(obj.get(k), str) and obj[k] for k in keys):
        raise ValueError("metadata service returned an incomplete credential set")
    return {k: obj[k] for k in keys}, obj.get("Expiration", "unknown")


def hmac256(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def canonical_query(query):
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    encoded = [(urllib.parse.quote(k, safe="-_.~"), urllib.parse.quote(v, safe="-_.~")) for k, v in pairs]
    return "&".join(k + "=" + v for k, v in sorted(encoded))


def signed_request(creds, region, service, method, url, *, data=None, extra=None):
    """Return HTTP code, bytes, headers. Never place credentials in the URL."""
    now = dt.datetime.now(dt.timezone.utc)
    date = now.strftime("%Y%m%d")
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username:
        raise ValueError("AWS API request requires an HTTPS URL")
    body = data if data is not None else b""
    headers = {
        "host": parsed.netloc,
        "x-amz-date": timestamp,
        "x-amz-security-token": creds["Token"],
        "x-amz-content-sha256": hashlib.sha256(body).hexdigest(),
    }
    headers.update({k.lower(): v for k, v in (extra or {}).items()})
    names = ";".join(sorted(headers))
    canonical_headers = "".join(k + ":" + " ".join(headers[k].strip().split()) + "\n" for k in sorted(headers))
    uri = urllib.parse.quote(urllib.parse.unquote(parsed.path or "/"), safe="/-_.~")
    canonical = "\n".join((method, uri, canonical_query(parsed.query), canonical_headers, names, headers["x-amz-content-sha256"]))
    scope = "/".join((date, region, service, "aws4_request"))
    string_to_sign = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope, hashlib.sha256(canonical.encode()).hexdigest()))
    key = hmac256(("AWS4" + creds["SecretAccessKey"]).encode(), date)
    for part in (region, service, "aws4_request"):
        key = hmac256(key, part)
    sig = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={creds['AccessKeyId']}/{scope}, SignedHeaders={names}, Signature={sig}"
    req = urllib.request.Request(url, data=(body if method in ("POST", "PUT") else None), headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
            return res.status, res.read(MAX_REPLY), res.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_REPLY), exc.headers


def error_code(blob, headers):
    h = headers.get("x-amzn-errortype", "") or headers.get("x-amz-error-code", "")
    if h:
        return h.split(":", 1)[0].split("#")[-1]
    try:
        obj = json.loads(blob)
        if isinstance(obj, dict):
            return str(obj.get("__type") or obj.get("code") or obj.get("Code") or "").split("#")[-1]
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        root = ET.fromstring(blob)
        for el in root.iter():
            if el.tag.split("}")[-1] == "Code":
                return el.text or ""
    except ET.ParseError:
        pass
    return "HTTPError"


def category(status, blob, headers):
    if 200 <= status < 300:
        return "ALLOWED", ""
    code = error_code(blob, headers)
    if any(x in code.lower() for x in ("expiredtoken", "invalidclienttoken", "signaturedoesnotmatch", "unrecognizedclient", "invalidsignature")):
        return "AUTH_ERROR", code
    if status in (401, 403) or "accessdenied" in code.lower() or code == "UnauthorizedOperation":
        return "DENIED", code
    if status == 404 or "notfound" in code.lower() or "nosuch" in code.lower():
        return "NOT_FOUND", code
    if status == 429 or "throttl" in code.lower():
        return "THROTTLED", code
    if status >= 500:
        return "SERVICE_ERROR", code
    return "INCONCLUSIVE", code


class Probe:
    def __init__(self, creds, region):
        self.creds = creds
        self.region = region
        self.results = []

    def call(self, label, service, method, url, *, data=None, headers=None, emit=True, sign_region=None):
        try:
            status, blob, response_headers = signed_request(self.creds, sign_region or self.region, service, method, url, data=data, extra=headers)
            verdict, code = category(status, blob, response_headers)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            verdict, code, status, blob = "TRANSPORT", type(exc).__name__, 0, b""
        self.results.append({"action": label, "verdict": verdict, "http": status, "code": code})
        if emit:
            self.show_last()
        if verdict != "ALLOWED":
            return None
        return blob

    def show_last(self):
        item = self.results[-1]
        print(f"[{item['verdict']:<13}] {item['action']}" +
              (f" ({item['code']}; HTTP {item['http']})" if item['code'] else ""))

    def json_rpc(self, label, endpoint, service, target, payload):
        raw = self.call(label, service, "POST", f"https://{endpoint}.{self.region}.amazonaws.com/",
                        data=json.dumps(payload, separators=(",", ":")).encode(),
                        headers={"content-type": "application/x-amz-json-1.1", "x-amz-target": target})
        try:
            return json.loads(raw) if raw else None
        except (ValueError, UnicodeDecodeError):
            print("  successful HTTP response was not JSON; cannot inspect it")
            return None

    def query(self, label, endpoint, service, action, version, **params):
        body = urllib.parse.urlencode({"Action": action, "Version": version, **params}).encode()
        raw = self.call(label, service, "POST", f"https://{endpoint}/", data=body,
                        headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
                        sign_region="us-east-1" if service == "iam" else self.region)
        try:
            return ET.fromstring(raw) if raw else None
        except ET.ParseError:
            print("  successful HTTP response was not XML; cannot inspect it")
            return None


def xml_text(root, name):
    if root is None:
        return ""
    return next((el.text or "" for el in root.iter() if el.tag.split("}")[-1] == name), "")


def xml_members(root):
    return [el for el in root.iter() if el.tag.split("}")[-1] == "member"] if root is not None else []


def policy_summary(label, raw_document):
    try:
        document = json.loads(urllib.parse.unquote(raw_document))
    except (ValueError, TypeError):
        print("  policy document unreadable:", label)
        return
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for item in statements[:20]:
        actions = item.get("Action", item.get("NotAction", []))
        resources = item.get("Resource", item.get("NotResource", []))
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        print("  POLICY", label, item.get("Effect", "?"), "actions=" + ",".join(actions[:20]),
              "resources=" + ",".join(resources[:3]), "conditions=" + str(bool(item.get("Condition"))))
    if len(statements) > 20:
        print("  POLICY", label, "more statements omitted:", len(statements) - 20)


def env_log_group():
    headers = os.environ.get("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "")
    match = re.search(r"(?:^|,)x-aws-log-group=([^,]+)", headers)
    return urllib.parse.unquote(match.group(1)) if match else ""


def env_log_stream():
    headers = os.environ.get("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "")
    match = re.search(r"(?:^|,)x-aws-log-stream=([^,]+)", headers)
    return urllib.parse.unquote(match.group(1)) if match else ""


def runtime_id_from_env():
    url = urllib.parse.unquote(os.environ.get("AGENTCORE_RUNTIME_URL", ""))
    match = re.search(r"runtime/([a-zA-Z][a-zA-Z0-9_]*-[a-zA-Z0-9]{10})", url)
    return match.group(1) if match else ""


def ecr_image_uri(obj, account, region):
    uri = ((obj.get("agentRuntimeArtifact") or {}).get("containerConfiguration") or {}).get("containerUri", "")
    match = re.fullmatch(rf"{re.escape(account)}\.dkr\.ecr\.{re.escape(region)}\.amazonaws\.com/([^@]+?)(?::([^/:]+)|@(sha256:[0-9a-f]{{64}}))?", uri)
    return (match.group(1), match.group(2) or match.group(3) or "") if match else ("", "")


def registry_tags(probe, auth, repo, account):
    if not auth or not account:
        return
    data = auth.get("authorizationData") or []
    token = data[0].get("authorizationToken", "") if data else ""
    if not token:
        return
    url = f"https://{account}.dkr.ecr.{probe.region}.amazonaws.com/v2/{urllib.parse.quote(repo, safe='/')}/tags/list?n=10"
    try:
        req = urllib.request.Request(url, headers={"Authorization": "Basic " + token})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            status, body, headers = response.status, response.read(MAX_REPLY), response.headers
    except urllib.error.HTTPError as exc:
        status, body, headers = exc.code, exc.read(MAX_REPLY), exc.headers
    except (OSError, urllib.error.URLError) as exc:
        status, body, headers = 0, b"", {}
    verdict, code = category(status, body, headers)
    probe.results.append({"action": "ECR registry tags " + repo, "verdict": verdict, "http": status, "code": code})
    print(f"[{verdict:<13}] ECR registry tags {repo}" + (f" ({code}; HTTP {status})" if code else ""))
    if verdict == "ALLOWED":
        try:
            tags = json.loads(body).get("tags") or []
            print("  tag count in response:", len(tags), "sample:", ", ".join(tags[:5]))
        except (ValueError, AttributeError):
            print("  registry replied but tag list could not be parsed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--ecr-repo", action="append", default=[], help="Known ECR repository name; repeatable")
    parser.add_argument("--ecr-tag", help="Image tag for BatchGetImage (optional)")
    parser.add_argument("--runtime-id", default=runtime_id_from_env(), help="AgentCore runtime ID; inferred from AGENTCORE_RUNTIME_URL")
    parser.add_argument("--log-group", default=env_log_group())
    parser.add_argument("--log-stream", default=env_log_stream())
    parser.add_argument("--s3-bucket", action="append", default=[], help="Known bucket name; repeatable")
    parser.add_argument("--s3-object", action="append", default=[], metavar="BUCKET/KEY", help="Known object; HeadObject only")
    parser.add_argument("--secret-id", action="append", default=[], help="Known secret name/ARN; metadata only")
    parser.add_argument("--parameter", action="append", default=[], help="Known SSM name; value is never printed")
    parser.add_argument("--json-out", help="Write status-only results to this local file (mode 0600)")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", args.region):
        parser.error("invalid AWS Region")
    try:
        creds, expiry = metadata_credentials()
    except Exception as exc:
        print("[STOP] IMDSv2 credentials unavailable:", type(exc).__name__, file=sys.stderr)
        return 2
    print("[INFO] metadata credentials loaded in memory; expiration:", expiry, "region:", args.region)
    p = Probe(creds, args.region)
    identity = p.query("sts:GetCallerIdentity (identity, not a permission test)", f"sts.{args.region}.amazonaws.com", "sts", "GetCallerIdentity", "2011-06-15")
    arn, account = xml_text(identity, "Arn"), xml_text(identity, "Account")
    if arn:
        print("  principal:", arn)
    role_name = ""
    match = re.match(r"arn:aws:sts::\d{12}:assumed-role/([^/]+)/", arn)
    if match:
        role_name = match.group(1)
    if role_name:
        p.query("iam:GetRole (own role)", "iam.amazonaws.com", "iam", "GetRole", "2010-05-08", RoleName=role_name)
        attached = p.query("iam:ListAttachedRolePolicies (own role)", "iam.amazonaws.com", "iam", "ListAttachedRolePolicies", "2010-05-08", RoleName=role_name, MaxItems="10")
        inline = p.query("iam:ListRolePolicies (own role)", "iam.amazonaws.com", "iam", "ListRolePolicies", "2010-05-08", RoleName=role_name, MaxItems="10")
        for member in xml_members(attached)[:10]:
            policy_arn = xml_text(member, "PolicyArn")
            if not policy_arn:
                continue
            policy = p.query("iam:GetPolicy " + policy_arn, "iam.amazonaws.com", "iam", "GetPolicy", "2010-05-08", PolicyArn=policy_arn)
            version = xml_text(policy, "DefaultVersionId")
            if version:
                document = p.query("iam:GetPolicyVersion " + policy_arn, "iam.amazonaws.com", "iam", "GetPolicyVersion", "2010-05-08", PolicyArn=policy_arn, VersionId=version)
                if document is not None:
                    policy_summary(policy_arn, xml_text(document, "Document"))
        for member in xml_members(inline)[:10]:
            name = member.text or ""
            if name:
                document = p.query("iam:GetRolePolicy " + name, "iam.amazonaws.com", "iam", "GetRolePolicy", "2010-05-08", RoleName=role_name, PolicyName=name)
                if document is not None:
                    policy_summary(name, xml_text(document, "PolicyDocument"))
    p.call("bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore", "POST",
           f"https://bedrock-agentcore-control.{args.region}.amazonaws.com/runtimes/?maxResults=1", data=b"", headers={"content-type": "application/json"})
    repo_from_runtime, tag_from_runtime = "", ""
    if args.runtime_id:
        raw = p.call("bedrock-agentcore:GetAgentRuntime " + args.runtime_id, "bedrock-agentcore", "GET",
                     f"https://bedrock-agentcore-control.{args.region}.amazonaws.com/runtimes/{urllib.parse.quote(args.runtime_id, safe='')}/")
        if raw and account:
            try:
                repo_from_runtime, tag_from_runtime = ecr_image_uri(json.loads(raw), account, args.region)
            except (ValueError, AttributeError):
                pass
            if repo_from_runtime:
                print("  ECR image referenced by runtime:", repo_from_runtime, tag_from_runtime)
    p.call("bedrock:ListFoundationModels", "bedrock", "GET", f"https://bedrock.{args.region}.amazonaws.com/foundation-models")
    p.json_rpc("xray:GetSamplingRules", "xray", "xray", "XRay.GetSamplingRules", {})

    auth = p.json_rpc("ecr:GetAuthorizationToken (token suppressed)", "api.ecr", "ecr", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken", {})
    repos = list(dict.fromkeys(args.ecr_repo + ([repo_from_runtime] if repo_from_runtime else [])))
    if not repos:
        print("[TARGET_NEEDED] ECR repository name: supply --ecr-repo NAME; token alone does not prove pull access")
    for repo in repos:
        if not re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", repo):
            print("[SKIPPED] malformed ECR repository:", repo)
            continue
        p.json_rpc("ecr:DescribeRepositories " + repo, "api.ecr", "ecr", "AmazonEC2ContainerRegistry_V20150921.DescribeRepositories", {"repositoryNames": [repo]})
        images = p.json_rpc("ecr:ListImages " + repo, "api.ecr", "ecr", "AmazonEC2ContainerRegistry_V20150921.ListImages", {"repositoryName": repo, "maxResults": 10})
        tag = args.ecr_tag or tag_from_runtime
        if not tag and images:
            tag = next((i.get("imageTag", "") for i in images.get("imageIds", []) if i.get("imageTag")), "")
        if tag:
            image_id = {"imageDigest": tag} if tag.startswith("sha256:") else {"imageTag": tag}
            label = "ecr:BatchGetImage " + repo + ":" + tag
            request_body = json.dumps({"repositoryName": repo, "imageIds": [image_id]}, separators=(",", ":")).encode()
            response = p.call(label, "ecr", "POST", f"https://api.ecr.{args.region}.amazonaws.com/", data=request_body,
                              headers={"content-type": "application/x-amz-json-1.1", "x-amz-target": "AmazonEC2ContainerRegistry_V20150921.BatchGetImage"}, emit=False)
            if response is None:
                p.show_last()
            else:
                try:
                    manifest = json.loads(response)
                except ValueError:
                    manifest = None
                if not isinstance(manifest, dict):
                    p.results[-1]["verdict"] = "INCONCLUSIVE"
                    p.results[-1]["code"] = "unparseable-response"
                    p.show_last()
                    continue
                fetched = manifest.get("images") or []
                if not fetched:
                    p.results[-1]["verdict"] = "NO_IMAGE"
                    p.show_last()
                    print("  API returned 200 but no image:", [f.get("failureCode") for f in manifest.get("failures", [])])
                else:
                    p.show_last()
                    print("  image manifest accessible; payload suppressed")
                    try:
                        layers = json.loads(fetched[0]["imageManifest"]).get("layers") or []
                        digest = layers[0].get("digest") if layers else None
                    except (KeyError, ValueError, TypeError):
                        digest = None
                    if digest and re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                        layer = p.json_rpc("ecr:GetDownloadUrlForLayer " + repo, "api.ecr", "ecr", "AmazonEC2ContainerRegistry_V20150921.GetDownloadUrlForLayer", {"repositoryName": repo, "layerDigest": digest})
                        if layer is not None:
                            print("  layer URL issued (URL suppressed; layer not downloaded)")
        else:
            print("[TARGET_NEEDED] ecr:BatchGetImage " + repo + ": supply --ecr-tag TAG or a runtime image tag")
        registry_tags(p, auth, repo, account)

    group, stream = args.log_group, args.log_stream
    if group:
        p.json_rpc("logs:DescribeLogStreams " + group, "logs", "logs", "Logs_20140328.DescribeLogStreams", {"logGroupName": group, "limit": 1})
        if stream:
            p.json_rpc("logs:GetLogEvents " + group + "/" + stream, "logs", "logs", "Logs_20140328.GetLogEvents", {"logGroupName": group, "logStreamName": stream, "limit": 1, "startFromHead": False})
    else:
        print("[TARGET_NEEDED] CloudWatch log group: supply --log-group NAME")

    for bucket in args.s3_bucket:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
            print("[SKIPPED] malformed bucket name:", bucket)
            continue
        host = f"{bucket}.s3.{args.region}.amazonaws.com"
        p.call("s3:ListBucket " + bucket + " (one-key request)", "s3", "GET", f"https://{host}/?list-type=2&max-keys=1")
    for name in args.s3_object:
        if "/" not in name:
            print("[SKIPPED] --s3-object requires BUCKET/KEY")
            continue
        bucket, key = name.split("/", 1)
        if not bucket or not key:
            continue
        host = f"{bucket}.s3.{args.region}.amazonaws.com"
        p.call("s3:GetObject " + name + " (HEAD only)", "s3", "HEAD", f"https://{host}/{urllib.parse.quote(key, safe='/')}")
    for name in args.secret_id:
        p.json_rpc("secretsmanager:DescribeSecret " + name, "secretsmanager", "secretsmanager", "secretsmanager.DescribeSecret", {"SecretId": name})
    for name in args.parameter:
        p.json_rpc("ssm:GetParameter " + name + " (value suppressed)", "ssm", "ssm", "AmazonSSM.GetParameter", {"Name": name, "WithDecryption": False})

    counts = {key: sum(x["verdict"] == key for x in p.results) for key in sorted({x["verdict"] for x in p.results})}
    print("[SUMMARY]", " ".join(f"{key}={count}" for key, count in counts.items()))
    if args.json_out:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(args.json_out, flags, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump({"region": args.region, "principal": arn, "results": p.results}, output, indent=2)
        print("[INFO] status-only report:", args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
