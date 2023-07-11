# API Documentation

This document covers all endpoint operations.

If you discover that some topic related to the behavior of the endpoint operation isn't documented, please open an issue in the repository.

## Authentication Operations

### Scheme: Basic

_Command:_
```bash
curl -X POST --user <username>:<password> http://localhost:<port>/irods-http-api/<version>
```

_Returns:_ A string representing a bearer token that can be used to carry out operations as the authenticated user.

### Scheme: OpenID Connect (OIDC)

Coming soon ...

## Collection Operations

### create

Creates a new collection.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create' \
    --data-urlencode 'lpath=</full/logical/path/to/collection>'
```

_Returns:_
```
{
}
```

### remove

Removes a collection.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'lpath=</full/logical/path/to/collection>'
```

_Returns:_
```
{
}
```

### stat

Returns information about a collection.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=</full/logical/path/to/collection>' \
    -G
```

_Returns:_
```
{
}
```

### list

Returns the contents of a collection.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath
- recurse

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=list' \
    --data-urlencode 'lpath=</full/logical/path/to/collection>' \
    --data-urlencode 'recurse=0' \
    -G
```

_Returns:_
```
{
}
```

### set_permission

Sets the permission of a user or group on a collection.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- entity-name
- permission

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=set_permission' \
    --data-urlencode 'lpath=</full/logical/path/to/collection>' \
    --data-urlencode 'entity-name=<user_or_group>' \
    --data-urlencode 'permission=<permission_string>'
```

_Returns:_
```
{
}
```

### rename

Renames or moves a collection.

_HTTP Method:_ POST

_Parameters:_
- op
- old-lpath
- new-lpath

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/collections \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=rename' \
    --data-urlencode 'old-lpath=</full/logical/path/to/old_collection>' \
    --data-urlencode 'new-lpath=</full/logical/path/to/new_collection>'
```

_Returns:_
```
{
}
```

## Data Object Operations

### touch

Updates the mtime of an existing data object or creates a new data object if it does not exist.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=touch' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>'
```

_Returns:_
```
{
}
```

### remove

Removes a data object.

The data object will be permanently deleted if `no-trash=1` is passed.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- unregister
- no-trash (default: 0)

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>' \
    --data-urlencode 'no-trash=<integer>'
```

_Returns:_
```
{
}
```

### stat

Returns information about a data object.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>' \
    -G
```

_Returns:_
```
{
}
```

### set_permission

Sets the permission of a user or group on a data object.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- entity-name
- permission

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=set_permission' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>' \
    --data-urlencode 'entity-name=<user_or_group>' \
    --data-urlencode 'permission=<permission_string>'
```

_Returns:_
```
{
}
```

### rename

Renames or moves a data object.

_HTTP Method:_ POST

_Parameters:_
- op
- old-lpath
- new-lpath

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=rename' \
    --data-urlencode 'old-lpath=</full/logical/path/to/old_data_object>' \
    --data-urlencode 'new-lpath=</full/logical/path/to/new_data_object>'
```

_Returns:_
```
{
}
```

### replicate

Replicates an existing replica from one resource to another resource.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- src-resource
- dst-resource
- src-replica-number?
- dst-replica-number?

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=replicate' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>' \
    --data-urlencode 'src-resource=<string>' \
    --data-urlencode 'dst-resource=<string>'
```

_Returns:_
```
{
}
```

### trim

Trims an existing replica.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- resource
- replica-number?

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=trim' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>' \
    --data-urlencode 'resource=<string>'
```

_Returns:_
```
{
}
```

### read

Reads bytes from a data object.

_HTTP Method:_ GET

_Parameters:_
- op
- lpath
- resource
- replica-number?
- offset
- count

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=read' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>' \
    --data-urlencode 'offset=<integer>' \
    --data-urlencode 'count=<integer>' \
    -G
```

_Returns:_
```
{
}
```

### write

Writes bytes to a data object.

To write to a data object in parallel, see [parallel-write-init](#operation-parallel-write-init).

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- resource
- replica-number?
- offset
- count
- bytes
- parallel-write-handle

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=write' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>' \
    --data-urlencode 'offset=<integer>' \
    --data-urlencode 'count=<integer>' \
    --data-urlencode 'bytes=<binary_data>' \
    -G
```

_Returns:_
```
{
}
```

### parallel-write-init

Initializes server-side state used for writing to a data object in parallel.

Returns a parallel-write-handle that can be used for parallel write operations.

_HTTP Method:_ POST

_Parameters:_
- op
- lpath
- resource
- replica-number?
- stream-count

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=parallel-write-init' \
    --data-urlencode 'lpath=</full/logical/path/to/data_object>' \
    --data-urlencode 'stream-count=<integer>' \
    -G
```

_Returns:_
```
{
    "parallel_write_handle": <string>
}
```

### parallel-write-shutdown

Instructs the server to shutdown and release any resources used for parallel write operations.

This operation MUST be called to complete the parallel write operation. Failing to call this operation will result in intermediate replicas and the server leaking memory.

_HTTP Method:_ POST

_Parameters:_
- op
- parallel-write-handle

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/data-objects \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=parallel-write-shutdown' \
    --data-urlencode 'parallel-write-handle=<integer>' \
    -G
```

_Returns:_
```
{
}
```

## Information Operations

Returns general information about the iRODS HTTP API server.

_HTTP Method:_ GET

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/info
```

_Returns:_
```
{
    "binary_name": <string>,
    "api_version": <string>,
    "commit": <string>
}
```

## Metadata Operations

### atomic_execute

Atomically applies several metadata operations in sequence on a single iRODS entity.

If an error occurs, all metadata operations are rolled back.

See [rc_atomic_apply_metadata_operations](https://docs.irods.org/4.3.0/doxygen/atomic__apply__metadata__operations_8h.html#a13e3e69c5b21a64b971aeeae82e6629e) for more information.

_HTTP Method:_ POST

_Parameters:_
- op
- json

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/metadata \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=execute' \
    --data-urlencode 'json=<json_input>'
```

_Returns:_
```
{
    "irods_response": {
        "error_code": <integer>
    },
    "error_info": <json_object>
}
```

## Query Operations

### execute_genquery

Executes a GenQuery string and returns the results.

_HTTP Method:_ GET

_Parameters:_
- op
- query
- offset
- count
- parser

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/query \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=execute_genquery' \
    --data-urlencode "query=select COLL_NAME, DATA_NAME where DATA_REPL_STATUS = '1'" \
    --data-urlencode 'offset=16' \
    --data-urlencode 'count=32' \
    -G
```

_Returns:_
```
{
    "irods_response": {
        "error_code": 0
    },
    "rows": [
        ["/full/logical/path/to/collection_1", "data_object_name_1"],
        ["/full/logical/path/to/collection_2", "data_object_name_2"],
        [                               "...",                "..."],
        ["/full/logical/path/to/collection_N", "data_object_name_N"]
    ]
}
```

### execute_specific_query

Executes a specific query and returns the results.

_HTTP Method:_ GET

_Parameters:_
- op
- name
- args: A comma-separated list of input arguments.
- args-delimiter: A single character that will be used to split the list of arguments. Defaults to `,`.
- offset
- count

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/query \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=execute_specific_query' \
    --data-urlencode 'name=ShowCollAcls' \
    --data-urlencode 'args=</full/logical/path/to/collection>' \
    -G
```

_Returns:_
```
{
    "irods_response": {
        "error_code": <integer>
    },
    "rows": [
        [<strings>],
        ...
    ]
}
```


## Resource Operations

### create

Creates a new resource.

_HTTP Method:_ POST

_Parameters:_
- op
- name
- type
- host
- vault-path
- context

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create' \
    --data-urlencode 'name=ufs0' \
    --data-urlencode 'type=unixfilesystem' \
    --data-urlencode 'host=example.org' \
    --data-urlencode 'vault-path=/tmp/ufs0_vault'
```

_Returns:_
```
{
}
```

### remove

Removes a resource.

_HTTP Method:_ POST

_Parameters:_
- op
- name

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'name=ufs0'
```

_Returns:_
```
{
}
```

### modify

Modifies properties of a resource.

_Status:_ Not implemented

_HTTP Method:_ POST

_Parameters:_
- op
- name
- property
- value

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=modify' \
    --data-urlencode 'name=ufs0' \
    --data-urlencode 'property=type' \
    --data-urlencode 'value=replication'
```

_Returns:_
```
{
}
```

### add_child

Creates a parent-child relationship between two resources.

_HTTP Method:_ POST

_Parameters:_
- op
- parent-name
- child-name
- context

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=add_child' \
    --data-urlencode 'parent-name=repl_resc' \
    --data-urlencode 'child-name=ufs0'
```

_Returns:_
```
{
}
```

### remove_child

Removes the parent-child relationship between two resources.

_HTTP Method:_ POST

_Parameters:_
- op
- parent-name
- child-name

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_child' \
    --data-urlencode 'parent-name=repl_resc' \
    --data-urlencode 'child-name=ufs0'
```

_Returns:_
```
{
}
```

### rebalance

Rebalances a resource hierarchy.

_HTTP Method:_ POST

_Parameters:_
- op
- name

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=rebalance' \
    --data-urlencode 'name=repl_resc'
```

_Returns:_
```
{
}
```

### stat

Returns information about a resource.

_HTTP Method:_ POST

_Parameters:_
- op
- name

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/resources \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'name=ufs0' \
    -G
```

_Returns:_
```
{
}
```

## Rule Operations

### list_rule_engines

Lists the available rule engine plugin instances of the connected iRODS server.

_HTTP Method:_ GET

_Parameters:_
- op

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/rules \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=list_rule_engines' \
    -G
```

_Returns:_
```
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

### list_delay_rules

_Maybe this operation should be handled by /query since all this operation does is run GenQuery?_

Lists all delay rules queued in the zone.

_HTTP Method:_ GET

_Parameters:_
- op

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/rules \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=list_delay_rules' \
    -G
```

_Returns:_
```
{
}
```

### execute

Executes rule code.

_HTTP Method:_ POST

_Parameters:_
- op
- rep-instance
- rule-text

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/rules \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=execute' \
    --data-urlencode 'rep-instance=<instance_name>' \
    --data-urlencode 'rule-text=<rule_code>'
```

_Returns:_
```
{
}
```

## Ticket Operations

### create

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
curl http://localhost:<port>/irods-http-api/<version>/tickets \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create' \
    --data-urlencode 'lpath=</full/logical/path/to/collection_or_data_object>' \
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
```
{
}
```

### remove

Removes a ticket.

_HTTP Method:_ POST

_Parameters:_
- op
- name

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/tickets \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'name=<string>'
```

_Returns:_
```
{
}
```

## User and Group Operations

### create_user

Creates a new user.

_HTTP Method:_ POST

_Parameters:_
- op
- name
- zone
- user-type
- remote-user (TODO: see #31)

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create' \
    --data-urlencode 'name=alice' \
    --data-urlencode 'zone=tempZone' \
    --data-urlencode 'user-type=groupadmin'
```

_Returns:_
```
{
}
```

### remove_user

Removes a user.

_HTTP Method:_ POST

_Parameters:_
- op
- name
- zone

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove' \
    --data-urlencode 'name=alice' \
    --data-urlencode 'zone=tempZone'
```

_Returns:_
```
{
}
```

### set_password

Changes a user's password.

_Status:_ Not implemented

_HTTP Method:_ POST

_Parameters:_
- op
- name
- zone
- password

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=set_password' \
    --data-urlencode 'name=alice' \
    --data-urlencode 'zone=tempZone' \
    --data-urlencode 'password=<string>'
```

_Returns:_
```
{
}
```

### set_user_type

Changes a user's type.

_Status:_ Not implemented

_HTTP Method:_ POST

_Parameters:_
- op
- name
- zone
- user-type

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=set_user_type' \
    --data-urlencode 'name=alice' \
    --data-urlencode 'zone=tempZone' \
    --data-urlencode 'user-type=rodsuser'
```

_Returns:_
```
{
}
```

### add_user_auth

Adds a new form of iRODS authentication for a user.

_Status:_ Not implemented

_HTTP Method:_ POST

_Parameters:_
- op
- name
- zone
- auth-info

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=add_user_auth' \
    --data-urlencode 'name=alice' \
    --data-urlencode 'zone=tempZone' \
    --data-urlencode 'auth-info=<string>'
```

_Returns:_
```
{
}
```

### remove_user_auth

Removes a form of iRODS authentication for a user.

_Status:_ Not implemented

_HTTP Method:_ POST

_Parameters:_
- op
- name
- zone
- auth-info

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_user_auth' \
    --data-urlencode 'name=alice' \
    --data-urlencode 'zone=tempZone' \
    --data-urlencode 'auth-info=<string>'
```

_Returns:_
```
{
}
```

### create_group

Creates a new group.

_HTTP Method:_ POST

_Parameters:_
- op
- name

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=create_group' \
    --data-urlencode 'name=lab1'
```

_Returns:_
```
{
}
```

### remove_group

Removes a group.

_HTTP Method:_ POST

_Parameters:_
- op
- name

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_group' \
    --data-urlencode 'name=lab1'
```

_Returns:_
```
{
}
```

### add_to_group

Adds a user to a group.

_HTTP Method:_ POST

_Parameters:_
- op
- group
- user

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=add_to_group' \
    --data-urlencode 'group=lab1' \
    --data-urlencode 'user=alice'
```

_Returns:_
```
{
}
```

### remove_from_group

Removes a user from a group.

_HTTP Method:_ POST

_Parameters:_
- op
- group
- user

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=remove_from_group' \
    --data-urlencode 'group=lab1' \
    --data-urlencode 'user=alice'
```

_Returns:_
```
{
}
```

### users

Lists all users in the zone.

_HTTP Method:_ GET

_Parameters:_
- op

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=users' \
    -G
```

_Returns:_
```
{
    "irods_response": {
        "error_code": <integer>
    },
    "users": [
        {
            "name": <string>,
            "zone": <string>
        }
    ]
}
```

### groups

Lists all groups in the zone.

_HTTP Method:_ GET

_Parameters:_
- op

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=groups' \
    -G
```

_Returns:_
```
{
    "irods_response": {
        "error_code": <integer>
    },
    "users": [
        <strings>
    ]
}
```

### members

Lists all users in a group.

_Status:_ Not implemented

_HTTP Method:_ GET

_Parameters:_
- op
- group

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=users' \
    --data-urlencode 'group=<string>' \
    -G
```

_Returns:_
```
{
    "irods_response": {
        "error_code": 0
    },
    "users": [
        {
            "name": "user1",
            "zone": "tempZone"
        },
        {
            "name": "user2",
            "zone": "tempZone"
        }
    ]
}
```

### is_member_of_group

Returns whether a user is a member of a group.

_Status:_ Not implemented

_HTTP Method:_ GET

_Parameters:_
- op
- user

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=is_member_of_group' \
    --data-urlencode 'user=alice' \
    -G
```

_Returns:_
```
{
    "irods_response": {
        "error_code": 0
    },
    "is_member": <boolean>
}
```

### stat

Returns information about a user or group.

_HTTP Method:_ GET

_Parameters:_
- op
- name
- zone

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/users-groups \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=stat' \
    --data-urlencode 'name=alice' \
    --data-urlencode 'zone=otherZone' \
    -G
```

_Returns:_
```
{
    "irods_response": {
        "error_code": 0
    },
    "exists": <boolean>,
    "id": <integer>,
    "local_unique_name": <string>,
    "type": <string>
}
```

## Zone Operations

### report

Returns information about the iRODS zone.

_HTTP Method:_ GET

_Parameters:_
- op

_Command:_
```bash
curl http://localhost:<port>/irods-http-api/<version>/zones \
    -H 'Authorization: Bearer <token>' \
    --data-urlencode 'op=report' \
    -G
```

_Returns:_
```
{
}
```
