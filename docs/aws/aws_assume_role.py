#!/usr/bin/env python3

# Usage:
# 
# eval "$(python3 - <<'PY'
# <this script contents>
# PY
# )"

import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

def assume_role_with_web_identity(
    role_arn,
    web_identity_token,
    session_name,
    duration_seconds,
    region = None,
):
    endpoint = (
        f"https://sts.{region}.amazonaws.com/"
        if region
        else "https://sts.amazonaws.com/"
    )

    payload = {
        "Action": "AssumeRoleWithWebIdentity",
        "Version": "2011-06-15",
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": str(duration_seconds),
        "WebIdentityToken": web_identity_token,
    }

    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as response:
            xml_response = response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        print(f"STS HTTP Error ({e.code} {e.reason}):\n{error_body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"STS URL Error: {e.reason}", file=sys.stderr)
        sys.exit(1)

    root = ET.fromstring(xml_response)

    return root.find(".//{*}AccessKeyId").text, root.find(".//{*}SecretAccessKey").text, root.find(".//{*}SessionToken").text

if __name__ == "__main__":
    ROLE_ARN = os.environ.get("AWS_ROLE_ARN")
    REGION = os.environ.get("AWS_REGION")

    if not ROLE_ARN:
        print("Error: AWS_ROLE_ARN environment variable must be set.", file=sys.stderr)
        sys.exit(1)
    
    SESSION_NAME = os.environ.get("AWS_SESSION_NAME")
    if not SESSION_NAME:
        SESSION_NAME="TC_Build_Unknown"

    # 1. Obtain OIDC token
    token_envvar = os.environ.get("AWS_TOKEN_ENVVAR_NAME")
    if not token_envvar:
        print("Error: AWS_TOKEN_ENVVAR_NAME environment variable is required", file=sys.stderr)
        sys.exit(1)
    if token_envvar.startswith("env."):
        token_envvar = token_envvar[4:]
    token = os.environ.get(token_envvar)
    if not token:
        print(f"Error: environment variable '{token_envvar}' is empty", file=sys.stderr)
        sys.exit(1)
    exchange_duration_str = os.environ.get("AWS_ASSUME_DURATION_SECONDS")
    exchange_duration = None
    if exchange_duration_str:
        try:
            exchange_duration = int(exchange_duration_str)
        except ValueError as e:
            print(f"Error: cannot parse AWS_ASSUME_DURATION_SECONDS as int", file=sys.stderr)
            sys.exit(1)
    if not exchange_duration:
        exchange_duration = 3600

    # 2. Exchange token with AWS STS
    access_key_id, secret_access_key, session_token = assume_role_with_web_identity(
        role_arn=ROLE_ARN, web_identity_token=token, region=REGION,
        session_name=SESSION_NAME, duration_seconds=exchange_duration
    )

    # 3. Print for eval
    print(f"AWS_ACCESS_KEY_ID={access_key_id}; export AWS_ACCESS_KEY_ID;")
    print(f"AWS_SECRET_ACCESS_KEY={secret_access_key}; export AWS_SECRET_ACCESS_KEY;")
    print(f"AWS_SESSION_TOKEN={session_token}; export AWS_SESSION_TOKEN;")