#! /bin/bash

username="$1"
password="$2"

set -x

base_url='http://localhost:9000/irods-rest/0.9.5'
creds=$(echo -n ${username}:${password} | base64)
bearer_token=$(curl -X POST -H "authorization: Basic $creds" "${base_url}/auth")

curl -H "authorization: Bearer $bearer_token" "${base_url}/collections?op=stat&lpath=/tempZone/home/kory" -v | jq
curl -H "authorization: Bearer $bearer_token" "${base_url}/collections?op=list&lpath=/tempZone/home/kory" -v | jq
curl -H "authorization: Bearer $bearer_token" "${base_url}/query?op=execute&query=select%20DATA_NAME" -v | jq
curl -H "authorization: Bearer $bearer_token" "${base_url}/query?op=bogus" -v | jq
