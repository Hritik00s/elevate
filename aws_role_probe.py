#!/usr/bin/env python3
"""Read-only, dependency-free IMDS and AWS probe for this AgentCore CTF.

Recursively walks discoverable IMDS paths, saves their responses in one private
JSON file, and optionally tests specific AWS API actions using fresh credentials.
IMDS response bodies (including credentials) are never printed by default.
"""

import argparse
import base64
from collections import deque
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

TIMEOUT = 6
MAX_REPLY = 8 * 1024 * 1024
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ECR_URI = re.compile(r"(?:\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com|public\.ecr\.aws)/[a-z0-9._/-]+(?::[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})?")
FLAG_CANDIDATE = re.compile(r"(?i)\b(?:[A-Z0-9_]*FLAG|CTF)\{[^}\r\n]{1,160}\}")
CHILD_SEGMENT = re.compile(r"[A-Za-z0-9_~:@%+.-]+")


def no_proxy_call(url, *, method="GET", headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    with NO_PROXY.open(req, timeout=3) as res:
        return res.read(MAX_REPLY).decode("utf-8", "replace")


def imds_origin():
    base = os.environ.get("AWS_EC2_METADATA_SERVICE_ENDPOINT", "")
    if not base:
        raise ValueError("AWS_EC2_METADATA_SERVICE_ENDPOINT is unset")
    parsed = urllib.parse.urlsplit(base)
    if (parsed.scheme != "http" or not parsed.netloc or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("metadata endpoint must be an HTTP origin")
    return base.rstrip("/")


def imds_token(base, ttl=120):
    return no_proxy_call(base + "/latest/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": str(min(21600, ttl))})


def metadata_credentials():
    base = imds_origin()
    token = imds_token(base)
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


def imds_fetch(base, token, path, max_bytes):
    url = base + urllib.parse.quote(path, safe="/-_.~:@")
    request = urllib.request.Request(url, headers={"X-aws-ec2-metadata-token": token})
    try:
        with NO_PROXY.open(request, timeout=3) as response:
            data = response.read(max_bytes + 1)
            return response.status, data[:max_bytes], len(data) > max_bytes, ""
    except urllib.error.HTTPError as exc:
        data = exc.read(max_bytes + 1)
        return exc.code, data[:max_bytes], len(data) > max_bytes, ""
    except (OSError, urllib.error.URLError) as exc:
        return 0, b"", False, transport_reason(exc)


def imds_children(data):
    """Interpret a directory listing, never arbitrary JSON or user-data, as paths."""
    try:
        listing = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if listing.lstrip().startswith(("{", "[", "<", "#!", "Content-Type:", "MIME-Version:")):
        return None
    lines = [line.strip() for line in listing.splitlines() if line.strip()]
    if len(lines) > 1000:
        return None
    children = []
    for name in lines:
        parts = name.rstrip("/").split("/")
        if not parts or any(not CHILD_SEGMENT.fullmatch(x) or x in (".", "..") for x in parts):
            return None
        children.append((name, name.endswith("/")))
    return children


def imds_walk(base, token, *, out_path, max_nodes=4096, max_depth=32, max_seconds=180,
              max_bytes=2 * 1024 * 1024, all_versions=False, extra_paths=()):
    """Walk directory listings under latest, plus root and known sibling paths."""
    pending = deque([("/", 0, True), ("/latest/", 1, True),
                     ("/latest/meta-data/", 2, True), ("/latest/dynamic/", 2, True),
                     ("/latest/user-data", 2, False),
                     # Some runtimes expose IAM credentials without advertising iam/.
                     ("/latest/meta-data/iam/", 3, True),
                     ("/latest/meta-data/iam/info", 4, False),
                     ("/latest/meta-data/iam/security-credentials/", 4, True),
                     ("/latest/meta-data/identity-credentials/ec2/info", 5, False),
                     ("/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", 6, False),
                     ("/latest/meta-data/tags/instance/", 4, True)])
    pending.extend((path, path.count("/"), path.endswith("/")) for path in extra_paths)
    seen = {"/latest/api/token"}
    records = {"/latest/api/token": {"http": 200, "method": "PUT", "kind": "token_endpoint", "body": "[redacted]"}}
    print("[IMDS 200] /latest/api/token TOKEN (PUT; body redacted)")
    ecr_matches, flag_matches = {}, {}
    skipped_depth = 0
    start = time.monotonic()
    while pending and len(seen) < max_nodes and time.monotonic() - start < max_seconds:
        path, depth, is_dir = pending.popleft()
        if depth > max_depth:
            skipped_depth += 1
            continue
        if path in seen:
            continue
        seen.add(path)
        status, data, truncated, error = imds_fetch(base, token, path, max_bytes)
        record = {"http": status, "bytes": len(data), "truncated": truncated}
        if error:
            record["error"] = error
        if status == 200:
            try:
                record["body"] = data.decode("utf-8")
                record["encoding"] = "utf-8"
            except UnicodeDecodeError:
                record["body"] = base64.b64encode(data).decode("ascii")
                record["encoding"] = "base64"
            children = imds_children(data) if is_dir and not truncated else None
            if children is not None:
                record["kind"] = "directory"
                record["children"] = [name for name, _ in children]
                for name, child_is_dir in children:
                    if path == "/" and not all_versions and name.rstrip("/") != "latest":
                        continue  # Historical version aliases duplicate the latest tree.
                    if path == "/":
                        name, child_is_dir = name.rstrip("/") + "/", True
                    elif re.fullmatch(r"/(?:latest|\d{4}-\d{2}-\d{2}|1\.0)/", path) and name.rstrip("/") in ("meta-data", "dynamic", "api"):
                        name, child_is_dir = name.rstrip("/") + "/", True
                    pending.append((path + name, depth + 1, child_is_dir))
            else:
                record["kind"] = "leaf"
                decoded = data.decode("utf-8", "replace")
                for value in ECR_URI.findall(decoded):
                    ecr_matches.setdefault(value, set()).add(path)
                for value in FLAG_CANDIDATE.findall(decoded):
                    flag_matches.setdefault(value, set()).add(path)
        records[path] = record
        display = "DIR" if record.get("kind") == "directory" else "LEAF"
        print(f"[IMDS {status or error}] {path} {display} bytes={len(data)}" +
              (" TRUNCATED" if truncated else ""))
    limits = []
    if pending:
        if len(seen) >= max_nodes:
            limits.append("node limit")
        if time.monotonic() - start >= max_seconds:
            limits.append("time limit")
    if skipped_depth:
        limits.append("depth limit")
    truncated_paths = [path for path, record in records.items() if record.get("truncated")]
    if truncated_paths:
        limits.append("response size limit")
    report = {
        "scope": "discoverable latest tree plus known unlisted IAM, identity, and tag paths; historical aliases only with --imds-all-versions",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "paths": records,
        "ecr_images": {k: sorted(v) for k, v in ecr_matches.items()},
        "flag_candidates": {k: sorted(v) for k, v in flag_matches.items()},
        "limits": limits,
        "skipped_depth": skipped_depth,
        "truncated_paths": truncated_paths,
        "unvisited_queued_paths": len(pending),
    }
    parent = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(out_path, flags, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(report, output, indent=2, ensure_ascii=False)
    for value, paths in sorted(ecr_matches.items()):
        print("[ECR_IMAGE]", value, "from", ",".join(sorted(paths)))
    for value, paths in sorted(flag_matches.items()):
        print("[FLAG_CANDIDATE]", value, "from", ",".join(sorted(paths)))
    print(f"[IMDS_SUMMARY] visited={len(seen)} remaining={len(pending)} limits={','.join(limits) or 'none'} report={out_path}")
    return report


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


def transport_reason(exc):
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, socket.gaierror):
        return f"DNS(errno={reason.errno})"
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "TIMEOUT"
    if isinstance(reason, ssl.SSLError):
        return f"TLS({getattr(reason, 'reason', 'error')})"
    if isinstance(reason, ConnectionRefusedError):
        return "CONNECTION_REFUSED"
    if isinstance(reason, ConnectionResetError):
        return "CONNECTION_RESET"
    tunnel = re.search(r"Tunnel connection failed:\s*(\d{3})", str(reason))
    if tunnel:
        return f"PROXY_TUNNEL_HTTP_{tunnel.group(1)}"
    if isinstance(reason, OSError):
        return f"{type(reason).__name__}(errno={reason.errno})"
    return type(reason).__name__


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
            verdict, code, status, blob = "TRANSPORT", transport_reason(exc), 0, b""
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
        transport_code = transport_reason(exc)
    verdict, code = category(status, body, headers)
    if status == 0:
        verdict, code = "TRANSPORT", transport_code
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
    parser.add_argument("--imds-only", action="store_true", help="Walk IMDS only; skip AWS API permission probes")
    parser.add_argument("--no-imds-scan", action="store_true", help="Skip recursive IMDS walk; run AWS API probes only")
    parser.add_argument("--imds-out", default="/tmp/elt/imds_dump.json", help="Single private JSON file containing all fetched IMDS responses")
    parser.add_argument("--imds-all-versions", action="store_true", help="Also traverse historical API version aliases exposed at the metadata root")
    parser.add_argument("--imds-extra-path", action="append", default=[], help="Probe an additional known but unlisted /latest/... path; repeatable")
    parser.add_argument("--imds-max-nodes", type=int, default=4096)
    parser.add_argument("--imds-max-depth", type=int, default=32)
    parser.add_argument("--imds-max-seconds", type=int, default=180)
    parser.add_argument("--imds-max-bytes", type=int, default=2 * 1024 * 1024, help="Maximum bytes retained per response")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", args.region):
        parser.error("invalid AWS Region")
    if args.imds_only and args.no_imds_scan:
        parser.error("--imds-only conflicts with --no-imds-scan")
    if min(args.imds_max_nodes, args.imds_max_depth, args.imds_max_seconds, args.imds_max_bytes) <= 0:
        parser.error("IMDS limits must be positive")
    for path in args.imds_extra_path:
        if (not path.startswith("/latest/") or "?" in path or "#" in path
                or any(part in (".", "..") for part in path.split("/"))):
            parser.error("--imds-extra-path must be an absolute /latest/... path without query or traversal")
    if not args.no_imds_scan:
        try:
            base = imds_origin()
            token = imds_token(base, args.imds_max_seconds + 60)
            imds_walk(base, token, out_path=args.imds_out, max_nodes=args.imds_max_nodes,
                      max_depth=args.imds_max_depth, max_seconds=args.imds_max_seconds,
                      max_bytes=args.imds_max_bytes, all_versions=args.imds_all_versions,
                      extra_paths=args.imds_extra_path)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            detail = str(exc) if isinstance(exc, ValueError) else transport_reason(exc)
            print("[IMDS_STOP] recursive scan unavailable:", detail, file=sys.stderr)
            if args.imds_only:
                return 2
    if args.imds_only:
        return 0
    try:
        creds, expiry = metadata_credentials()
    except Exception as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print("[STOP] IMDSv2 credentials unavailable:", detail, file=sys.stderr)
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
        if repo == "REPOSITORY_NAME":
            print("[TARGET_NEEDED] replace the literal REPOSITORY_NAME placeholder with a real repository name")
            continue
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
