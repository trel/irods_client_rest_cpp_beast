# iRODS HTTP API

## Authentication

### Basic

_Command:_
```bash
curl -X POST --user <username>:<password> http://localhost:<port>/irods-http/<version>
```

_Returns:_ A string representing a bearer token that can be used to carry out operations as the authenticated user.

### Open ID Connect (OIDC)

Coming soon ...

## Collections

### Operation: create

_HTTP Method_: POST

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=create' \
    --data-urlencode 'lpath=<path/to/collection>' \
```

_Returns:_
```json
{
}
```

### Operation: remove

_HTTP Method_: POST

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=remove' \
    --data-urlencode 'lpath=<path/to/collection>' \
```

_Returns:_
```json
{
}
```

### Operation: stat

_HTTP Method_: GET

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=<path/to/collection>'
```

_Returns:_
```json
{
}
```

### Operation: list

_HTTP Method_: GET

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=list' \
    --data-urlencode 'lpath=<path/to/collection>'
```

_Returns:_
```json
{
}
```

### Operation: set_permission

_HTTP Method_: POST

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=set_permission' \
    --data-urlencode 'lpath=<path/to/collection>' \
    --data-urlencode 'entity-name=<user_or_group>' \
    --data-urlencode 'permission=<permission_string>'
```

_Returns:_
```json
{
}
```

### Operation: rename

_HTTP Method_: POST

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=rename' \
    --data-urlencode 'old-lpath=<path/to/old_collection>' \
    --data-urlencode 'new-lpath=<path/to/new_collection>'
```

_Returns:_
```json
{
}
```

## Data Objects



## Information



## Metadata

Atomically applies several metadata operations in sequence on a single iRODS entity.

_HTTP Method:_ POST

_Parameters:_
- op
- data

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/metadata \
    --data-urlencode 'op=atomic_execute' \
    --data-urlencode 'data=<json_input>'
```

_Returns:_
```json
{
    "irods_response": {
        "error_code": <integer>
    },
    "info": <json_object>
}
```

## Query

### Operation: query

Runs the user provided GenQuery string and returns a JSON payload containing the results.

_HTTP Method_: GET

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/query \
    --data-urlencode 'op=query' \
    --data-urlencode "query=select COLL_NAME, DATA_NAME where DATA_REPL_STATUS = '1'"
```

_Returns:_
```json
{
    "irods_response": {
        "error_code": 0
    },
    "rows": [
        ["/path/to/collection_1", "data_object_name_1"],
        ["/path/to/collection_2", "data_object_name_2"],
        ["...", "..."],
        ["/path/to/collection_N", "data_object_name_N"]
    ]
}
```

## Resources



## Rules

### Operation: list_rule_engines

Lists the available rule engine plugin instances of the connected iRODS server.

_HTTP Method:_ GET

_Parameters:_
- op

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/rules \
    --data-urlencode 'op=list_rule_engines'
```

_Returns:_
```json
{
    "irods_response": {
        "error_code": <integer>
    },
    "rule_engine_plugin_instances": [
        "rep-instance-1",
        "rep-instance-2",
        "...",
        "rep-instance-N"
    ]
}
```

### Operation: execute

Executes rule code on the connected iRODS server.

_HTTP Method:_ POST

_Parameters:_
- op
- rep-instance
- rule-text

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/rules \
    --data-urlencode 'op=execute' \
    --data-urlencode 'rep-instance=<instance_name>' \
    --data-urlencode 'rule-text=<rule_code>'
```

_Returns:_
```json
{
    "irods_response": {
        "error_code": <integer>
    },
    "rule_engine_plugin_instances": [
        "rep-instance-1",
        "rep-instance-2",
        "...",
        "rep-instance-N"
    ]
}
```

## Tickets



## Users and Groups



## Zones

### Operation: report

Returns a JSON payload describing the connected iRODS zone.

_HTTP Method_: GET

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/zones \
    --data-urlencode 'op=report' # Is "stat" a better term? It certainly falls in line with the other endpoints.
```

_Returns:_
```json
{
}
```
