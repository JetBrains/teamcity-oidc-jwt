#!/bin/bash
set -euo pipefail

# This script expects you to
# - have `OIDC Token (on demand via HTTP request)` with a properly configured audience
# - provide the following envvars:
# export TC_BUILD_CREDENTIALS="%system.teamcity.auth.userId%:%system.teamcity.auth.password%"
# export TC_SERVER_URL="%teamcity.serverUrl%"
# export GCP_PROJECT_NUMBER="PROJECT_NUMBER"
# export GCP_WIF_POOL_ID="POOL_ID"
# export GCP_WIF_PROVIDER_ID="PROVIDER_ID"

GCP_WIF_PROVIDER="projects/$GCP_PROJECT_NUMBER/locations/global/workloadIdentityPools/$GCP_WIF_POOL_ID/providers/$GCP_WIF_PROVIDER_ID"

# Note: jq can be replaced with e.g. `python3 -c "import sys,json;j=json.load(sys.stdin);print(j[sys.argv[1][1:]])"`
json_value() {
    local value; value=$(jq -r "$2" <<<"$1")
    [ "$value" != null ] || { echo "$3: $1" >&2; exit 1; }
    printf '%s' "$value"
}

for tool in jq curl; do
    command -v "$tool" > /dev/null || { echo "$tool was not found, exiting" >&2; exit 1; }
done

tc_token=$(curl -s -u "$TC_BUILD_CREDENTIALS" "$TC_SERVER_URL/app/oidc-jwt/issue")
req=$(curl -s -X POST "https://sts.googleapis.com/v1/token" -H "Content-Type: application/json; charset=utf-8" \
        -d '{"audience": "//iam.googleapis.com/'"$GCP_WIF_PROVIDER"'", "subject_token": "'"$tc_token"'", "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange","scope": "https://www.googleapis.com/auth/cloud-platform","requested_token_type": "urn:ietf:params:oauth:token-type:access_token","subject_token_type": "urn:ietf:params:oauth:token-type:jwt"}')
federated_token=$(json_value "$req" '.access_token' "Failed to get federated token")

# You can use the federated token to access GCP APIs directly
BUCKET_NAME="test-bucket-please-ignore"
curl -s -H "Authorization: Bearer ${federated_token}" \
  "https://storage.googleapis.com/storage/v1/b/${BUCKET_NAME}/o"

# Or impersonate a service account and get its access/identity tokens
federated_to_access() {
    # See https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
    local sa_email="$1"
    local scope=${2:-https://www.googleapis.com/auth/cloud-platform}
    local req=$(curl -s -X POST -H "Authorization: Bearer $federated_token" -H "Content-Type: application/json; charset=utf-8" \
        -d '{"scope": ["'"$scope"'","https://www.googleapis.com/auth/userinfo.email"],"lifetime": "3600s"}' \
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${sa_email}:generateAccessToken")
    access_token=$(json_value "$req" '.accessToken' "Failed to get access token")
    access_expire=$(echo "$req" | json_value '.expireTime' "Failed to get expire time")
}

federated_to_identity() {
    # See https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateIdToken
    local sa_email="$1"
    local audience="$2"
    local req=$(curl -s -X POST -H "Authorization: Bearer $federated_token" -H "Content-Type: application/json; charset=utf-8" \
            -d '{"audience": "'"$audience"'","includeEmail": true}' \
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${sa_email}:generateIdToken")
    identity_token=$(json_value "$req" '.token' "Failed to get identity token")
}
