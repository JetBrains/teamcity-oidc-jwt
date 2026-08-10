#!/bin/bash
set -euo pipefail

# Logs Docker in to Nebius Container Registry using an OIDC token issued by this
# plugin. No long-lived Docker credentials are stored anywhere.
#
# Source this script from your build step, so that DOCKER_CONFIG stays exported
# for the `docker` commands that follow and the credentials are wiped when the
# step ends:
#
#     . ./docker-login.sh
#     docker build -t "$NEBIUS_REGISTRY_FQDN/my-image:$BUILD_NUMBER" .
#     docker push "$NEBIUS_REGISTRY_FQDN/my-image:$BUILD_NUMBER"
#
# This script expects you to provide the following envvars:
# export NEBIUS_REGISTRY_FQDN="cr.eu-north1.nebius.cloud/e00abc123def"
#
# ...plus a token source, either
# - `OIDC Token (in build parameters)`, which sets TEAMCITY_BUILD_OIDC_TOKEN
#   for you, or
# - `OIDC Token (on demand via HTTP request)`, which additionally needs:
# export TC_BUILD_CREDENTIALS="%system.teamcity.auth.userId%:%system.teamcity.auth.password%"
# export TC_SERVER_URL="%teamcity.serverUrl%"

# Public Nebius federation endpoint. Override for other installations.
NEBIUS_AUTH_URL="${NEBIUS_AUTH_URL:-https://auth.eu.nebius.com/oauth2/token/exchange}"

(return 0 2>/dev/null) || cat >&2 <<'EOF'
warning: this script is meant to be sourced (`. ./docker-login.sh`).
         Running it directly logs in and then immediately wipes the credentials
         on exit, so the `docker` commands in your build step will fail.
EOF

for tool in jq curl docker; do
    command -v "$tool" > /dev/null || { echo "$tool was not found, exiting" >&2; exit 1; }
done

: "${NEBIUS_REGISTRY_FQDN:?must be set, e.g. cr.eu-north1.nebius.cloud/e00abc123def}"

# `docker login` takes the host, while image tags use the host and the path.
NEBIUS_REGISTRY_HOST="${NEBIUS_REGISTRY_FQDN%%/*}"

nebius_work_dir=$(mktemp -d)

# Keep the registry credentials out of the agent's shared ~/.docker/config.json.
export DOCKER_CONFIG="$nebius_work_dir/docker"
mkdir -p "$DOCKER_CONFIG"

nebius_docker_cleanup() {
    docker logout "$NEBIUS_REGISTRY_HOST" > /dev/null 2>&1 || true
    rm -rf "$nebius_work_dir"
}
trap nebius_docker_cleanup EXIT

# Tokens are written to files instead of being passed as arguments so that they
# never show up in the process list.
umask 077

if [ -n "${TEAMCITY_BUILD_OIDC_TOKEN:-}" ]; then
    printf '%s' "$TEAMCITY_BUILD_OIDC_TOKEN" > "$nebius_work_dir/subject_token.jwt"
else
    : "${TC_BUILD_CREDENTIALS:?set it, or enable the 'OIDC Token (in build parameters)' build feature}"
    : "${TC_SERVER_URL:?set it, or enable the 'OIDC Token (in build parameters)' build feature}"

    curl --silent --show-error --fail -u "$TC_BUILD_CREDENTIALS" \
        "$TC_SERVER_URL/app/oidc-jwt/issue" \
        --output "$nebius_work_dir/subject_token.jwt"
fi

# Exchange the TeamCity JWT for a Nebius IAM access token (RFC 8693).
# Note: the endpoint only accepts application/x-www-form-urlencoded.
nebius_http_code=$(curl --silent --show-error \
    --request POST "$NEBIUS_AUTH_URL" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
    --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
    --data-urlencode "subject_token@$nebius_work_dir/subject_token.jwt" \
    --output "$nebius_work_dir/exchange.json" \
    --write-out '%{http_code}')

if [ "$nebius_http_code" != "200" ]; then
    # The error body carries requestId and traceId, quote them in support requests.
    echo "Token exchange failed with HTTP $nebius_http_code:" >&2
    cat "$nebius_work_dir/exchange.json" >&2
    echo >&2
    exit 1
fi

# The resulting access token is valid for 12 hours.
jq -er '.access_token' < "$nebius_work_dir/exchange.json" \
    | docker login "$NEBIUS_REGISTRY_HOST" --username iam --password-stdin
