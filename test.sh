#! /bin/bash

username="$1"
password="$2"

set -x

base_url='http://localhost:9000/irods-rest/0.9.5'
creds=$(echo -n ${username}:${password} | base64)
bearer_token=$(curl -X POST -s -H "authorization: Basic $creds" "${base_url}/auth")
curl_opts='-s'

curl -H "authorization: Bearer $bearer_token" "${base_url}/collections?op=stat&lpath=/tempZone/home/kory" $curl_opts | jq
curl -H "authorization: Bearer $bearer_token" "${base_url}/collections?op=list&lpath=/tempZone/home/kory" $curl_opts | jq

curl -H "authorization: Bearer $bearer_token" "${base_url}/query?op=execute&query=select%20COLL_NAME,%20DATA_NAME" ${curl_opts} | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/query" \
    --data-urlencode 'op=execute' \
    --data-urlencode 'query=select COLL_NAME, DATA_NAME' \
    ${curl_opts} | jq
curl -H "authorization: Bearer $bearer_token" "${base_url}/query?op=bogus" ${curl_opts} | jq

curl -H "authorization: Bearer $bearer_token" "${base_url}/resources?op=stat&name=demoResc" ${curl_opts} | jq
curl -H "authorization: Bearer $bearer_token" "${base_url}/resources?op=create&name=repl_resc&type=replication" ${curl_opts} | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/resources" \
    --data-urlencode 'op=create' \
    --data-urlencode 'name=ufs0_resc' \
    --data-urlencode 'type=unixfilesystem' \
    --data-urlencode "host=$(hostname)" \
    --data-urlencode 'vault-path=/tmp/ufs0_resc' \
    ${curl_opts} | jq
curl -H "authorization: Bearer $bearer_token" "${base_url}/resources?op=stat&name=repl_resc" ${curl_opts} | jq
curl -H "authorization: Bearer $bearer_token" "${base_url}/resources?op=stat&name=ufs0_resc" ${curl_opts} | jq

curl -H "authorization: Bearer $bearer_token" "${base_url}/metadata?op=atomic_execute" ${curl_opts} -d \
    '{
        "entity_name": "/tempZone/home/kory",
        "entity_type": "collection",
        "operations": [
            {
                "operation": "add",
                "attribute": "source",
                "value": "irods-rest-beast",
                "units": "c++"
            }
        ]
    }' | jq

curl -H "authorization: Bearer $bearer_token" "${base_url}/metadata?op=atomic_execute" ${curl_opts} -d \
    '{
        "entity_name": "/tempZone/home/kory",
        "entity_type": "file",
        "operations": [
            {
                "operation": "add",
                "attribute": "source",
                "value": "irods-rest-beast",
                "units": "c++"
            }
        ]
    }' | jq

curl -G -H "authorization: Bearer $bearer_token" "${base_url}/rules" \
    --data-urlencode 'op=execute' \
    --data-urlencode 'rep-instance=irods_rule_engine_plugin-irods_rule_language-instance' \
    --data-urlencode 'rule-text=delay("<EF>60</EF><INST_NAME>irods_rule_engine_plugin-irods_rule_language-instance</INST_NAME>") { writeLine("serverLog", "REST API!!!"); }' \
    ${curl_opts} | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/rules" \
    --data-urlencode 'op=list_rule_engines' \
    ${curl_opts} | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/rules" \
    --data-urlencode 'op=list_delay_rules' \
    ${curl_opts} | jq

curl -G -H "authorization: Bearer $bearer_token" "${base_url}/data-objects" \
    --data-urlencode 'op=touch' \
    --data-urlencode 'lpath=/tempZone/home/kory/file.irods-rest-beast' \
    $curl_opts | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/data-objects" \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=/tempZone/home/kory/file.irods-rest-beast' \
    $curl_opts | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/data-objects" \
    --data-urlencode 'op=remove' \
    --data-urlencode 'no-trash=1' \
    --data-urlencode 'lpath=/tempZone/home/kory/file.irods-rest-beast' \
    $curl_opts | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/data-objects" \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=/tempZone/home/kory/file.irods-rest-beast' \
    $curl_opts | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/data-objects"\
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=/tempZone/home/kory/goo' \
    $curl_opts | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/data-objects" \
    --data-urlencode 'op=set-permission' \
    --data-urlencode 'lpath=/tempZone/home/kory/goo' \
    --data-urlencode 'entity-name=rods' \
    --data-urlencode 'permission=read_object' \
    $curl_opts | jq
curl -G -H "authorization: Bearer $bearer_token" "${base_url}/data-objects" \
    --data-urlencode 'op=read' \
    --data-urlencode 'lpath=/tempZone/home/kory/foo' \
    --data-urlencode 'count=1000' \
    $curl_opts | jq
