# iRODS HTTP API

## Authentication

### Scheme: Basic

_Command:_
```bash
curl -X POST --user <username>:<password> http://localhost:<port>/irods-http/<version>
```

_Returns:_ A string representing a bearer token that can be used to carry out operations as the authenticated user.

### Scheme: Open ID Connect (OIDC)

Coming soon ...

## Collections

### Operation: create

Creates a new collection.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=create' \
    --data-urlencode 'lpath=</path/to/collection>'
```

_Returns:_
```json
{
}
```

### Operation: remove

Removes a collection.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=remove' \
    --data-urlencode 'lpath=</path/to/collection>'
```

_Returns:_
```json
{
}
```

### Operation: stat

Returns information about a collection.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=</path/to/collection>'
```

_Returns:_
```json
{
}
```

### Operation: list

Returns the contents of a collection.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath
- recurse

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=list' \
    --data-urlencode 'lpath=</path/to/collection>' \
    --data-urlencode 'recurse=0'
```

_Returns:_
```json
{
}
```

### Operation: set_permission

Sets the permission of a user or group on a collection.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- entity-name
- permission

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=set_permission' \
    --data-urlencode 'lpath=</path/to/collection>' \
    --data-urlencode 'entity-name=<user_or_group>' \
    --data-urlencode 'permission=<permission_string>'
```

_Returns:_
```json
{
}
```

### Operation: rename

Renames or moves a collection.

_HTTP Method:_ POST

_Parameters:_
- op
- old-lpath
- new-lpath

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/collections \
    --data-urlencode 'op=rename' \
    --data-urlencode 'old-lpath=</path/to/old_collection>' \
    --data-urlencode 'new-lpath=</path/to/new_collection>'
```

_Returns:_
```json
{
}
```

## Data Objects

### Operation: touch

Updates the mtime of an existing data object or creates a new data object if it does not exist.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=touch' \
    --data-urlencode 'lpath=</path/to/data_object>'
```

_Returns:_
```json
{
}
```

### Operation: remove

Removes a data object.

The data object will be moved to the trash collection if `no-trash=1` is passed.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- no-trash (default: 0)

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=remove' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'no-trash=<integer>'
```

_Returns:_
```json
{
}
```

### Operation: stat

Returns information about a data object.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=</path/to/data_object>'
```

_Returns:_
```json
{
}
```

### Operation: read

Returns the contents of a data object.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath
- offset
- count

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=read' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'offset=<integer>' \
    --data-urlencode 'count=<integer>' \
```

_Returns:_
```json
{
}
```

### Operation: set_permission

Sets the permission of a user or group on a data object.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- entity-name
- permission

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=set_permission' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'entity-name=<user_or_group>' \
    --data-urlencode 'permission=<permission_string>'
```

_Returns:_
```json
{
}
```

### Operation: rename

Renames or moves a data object.

_HTTP Method:_ POST

_Parameters:_
- op
- old-lpath
- new-lpath

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=rename' \
    --data-urlencode 'old-lpath=</path/to/old_data_object>' \
    --data-urlencode 'new-lpath=</path/to/new_data_object>'
```

_Returns:_
```json
{
}
```

### Operation: replicate

Replicates an existing replica from one resource to another resource.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- src-resource
- dst-resource
- src-replica?
- dst-replica?

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=replicate' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'src-resource=<string>' \
    --data-urlencode 'dst-resource=<string>'
```

_Returns:_
```json
{
}
```

### Operation: trim

Trims an existing replica.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- resource
- replica?

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=trim' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'resource=<string>'
```

_Returns:_
```json
{
}
```

### Operation: read

Reads the contents of a data object.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath
- resource
- replica?
- offset
- count

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=read' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'offset=<integer>' \
    --data-urlencode 'count=<integer>'
```

_Returns:_
```json
{
}
```

### Operation: write

Writes bytes to a data object.

To write to a data object in parallel, see [Operation: parallel-write-init](#operation-parallel-write-init).

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- resource
- replica?
- offset
- count
- bytes
- parallel-write-handle

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=write' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'offset=<integer>' \
    --data-urlencode 'count=<integer>' \
    --data-urlencode 'bytes=<binary_data>'
```

_Returns:_
```json
{
}
```

### Operation: parallel-write-init

Initializes server-side state used for writing to a data object in parallel.

Returns a parallel-write-handle that can be used for parallel write operations.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- resource
- replica?
- stream-count

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=parallel-write-init' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'stream-count=<integer>'
```

_Returns:_
```json
{
    "parallel_write_handle": "<string>"
}
```

### Operation: parallel-write-shutdown

Instructs the server to shutdown and release any resources used for parallel write operations.

This operation MUST be called to complete the parallel write operation. Failing to call this operation will result in intermediate replicas and the server leaking memory.

_HTTP Method:_ POST

_Parameters:_
- op
- parallel-write-handle

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/data-objects \
    --data-urlencode 'op=parallel-write-shutdown' \
    --data-urlencode 'parallel-write-handle=<integer>'
```

_Returns:_
```json
{
}
```

## Information

Returns general information about the iRODS HTTP API server.

_HTTP Method:_ GET

_Command:_
```bash
curl http://localhost:<port>/irods-http/<version>/info
```

_Returns:_
```json
{
    "binary_name": "<string>",
    "api_version": "<string>",
    "commit": "<string>",
    "irods_server": {
        "host": "<string>",
        "port": "<integer>",
        "zone": "<string>"
    }
}
```

## Metadata

Atomically applies several metadata operations in sequence on a single iRODS entity.

If an error occurs, all metadata operations are rolled back.

_HTTP Method:_ POST

_Parameters:_
- op
- json

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/metadata \
    --data-urlencode 'op=atomic_execute' \
    --data-urlencode 'json=<json_input>'
```

_Returns:_
```json
{
    "irods_response": {
        "error_code": "<integer>"
    },
    "info": "<json_object>"
}
```

## Query

### Operation: query

Runs the user provided GenQuery string and returns the results.

_HTTP Method:_ GET

_Parameters:_
- op
- query

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
        "error_code": "<integer>"
    },
    "rule_engine_plugin_instances": [
        "rep-instance-1",
        "rep-instance-2",
        "...",
        "rep-instance-N"
    ]
}
```

### Operation: list_delay_rules

_Maybe this operation should be handled by /query since all this operation does is run GenQuery?_

Lists all delay rules queued in the zone.

_HTTP Method:_ GET

_Parameters:_
- op

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/rules \
    --data-urlencode 'op=list_delay_rules'
```

_Returns:_
```json
{
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
        "error_code": "<integer>"
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

### Operation: create

Creates a new ticket for a collection or data object.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- type
- use-count
- write-data-object-count
- write-byte-count
- seconds-until-expiration
- users
- groups
- hosts

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/tickets \
    --data-urlencode 'op=create' \
    --data-urlencode 'lpath=</path/to/data_object>' \
    --data-urlencode 'type=<string>' \
    --data-urlencode 'use-count=<integer>' \
    --data-urlencode 'write-data-object-count=<integer>' \
    --data-urlencode 'write-byte-count=<integer>' \
    --data-urlencode 'seconds-until-expiration=<integer>' \
    --data-urlencode 'users=<string>' \
    --data-urlencode 'groups=<string>' \
    --data-urlencode 'hosts=<string>'
```

_Returns:_
```json
{
}
```

### Operation: remove

Removes a ticket.

_HTTP Method:_ POST

_Parameters:_
- op
- name

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/tickets \
    --data-urlencode 'op=remove' \
    --data-urlencode 'name=<string>'
```

_Returns:_
```json
{
}
```

## Users and Groups



## Zones

### Operation: report

Returns information about the iRODS zone.

_HTTP Method:_ GET

_Parameters:_
- op

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version>/zones \
    --data-urlencode 'op=report'
```

_Returns:_
```json
{
}
```
