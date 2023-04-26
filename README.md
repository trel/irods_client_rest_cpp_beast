# iRODS HTTP API

A project that presents an iRODS 4.3.1+ server as HTTP v1.1.

## Package Dependencies

- iRODS development package
- iRODS externals package for boost
- iRODS externals package for nlohmann-json
- iRODS externals package for spdlog 
- Curl development package
- OpenSSL development package

## Compiling

To compile the server, follow the normal CMake steps.

The following example uses **Ninja** to compile the server.
```bash
mkdir build # Preferably outside of the repository
cd build
cmake -GNinja /path/to/repository
ninja
```

## Configuration

```js
{
    // Defines HTTP options that affect how the client-facing component of the
    // server behaves.
    "http_server": {
        // The hostname or IP address to bind.
        // "0.0.0.0" instructs the server to listen on all network interfaces.
        "host": "0.0.0.0",

        // The port used to accept incoming client requests.
        "port": 9000,

        // The minimum log level needed before logging activity.
        "log_level": "warn",

        // Defines options that affect how client requests are handled.
        "requests": {
            // The number of threads dedicated to servicing client requests.
            // When adjusting this value, consider adjusting "background_io/threads"
            // and "irods_client/connection_pool/size" as well.
            "threads": 3,

            // The maximum size allowed for the body of a request.
            "max_rbuffer_size_in_bytes": 8388608,

            // The maximum size allowed for the body of a response.
            "max_wbuffer_size_in_bytes": 8388608,

            // The amount of time allowed to service all requests. If the timeout
            // is exceeded, the client's connection is terminated immediately.
            "connection_timeout_in_seconds": 30
        },

        // Defines options that affect tasks running in the background.
        // These options are primarily related to long-running tasks.
        "background_io": {
            // The number of threads dedicated to background I/O.
            "threads": 3,

            // The buffer size used for read operations.
            "rbuffer_size_in_bytes": 8192,

            // The buffer size used for write operations.
            "wbuffer_size_in_bytes": 8192
        }
    }

    // Defines iRODS connection information.
    "irods_client": {
        // The hostname or IP of the target iRODS server.
        "host": "<host>",

        // The port of the target iRODS server.
        "port": 1247,

        // The zone of the target iRODS server.
        "zone": "<zone>",

        // The credentials for the rodsadmin user that will act as a proxy
        // for all authenticated users.
        "proxy_rodsadmin": {
            "username": "<username>",
            "password": "<password>"
        },

        // Defines options for the connection pool.
        "connection_pool": {
            // The number of connections in the pool.
            "size": 6,

            // The amount of time that must pass before a connection is
            // renewed (i.e. replaced).
            "refresh_timeout_in_seconds": 600
        }
    }
}
```

## Run

To run the server, do the following:
```bash
./irods_http_api /path/to/config/file.json
```

To stop the server, you can use **CTRL-C** or send **SIGINT** or **SIGTERM** to the process.

## Docker

Coming soon ...

## API

### Authentication

#### Basic

_Command:_
```bash
curl -X POST --user <username>:<password> http://localhost:<port>/irods-http/<version>
```

_Returns:_ A string representing a bearer token that can be used to carry out operations as the authenticated user.

#### Open ID Connect (OIDC)

Coming soon ...

### Collections

#### Operation: create

_HTTP Method_: POST

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version> \
    --data-urlencode 'op=create' \
    --data-urlencode 'lpath=<path/to/collection>' \
```

_Returns:_
```json
{
}
```

#### Operation: remove

_HTTP Method_: POST

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version> \
    --data-urlencode 'op=remove' \
    --data-urlencode 'lpath=<path/to/collection>' \
```

_Returns:_
```json
{
}
```

#### Operation: stat

_HTTP Method_: GET

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version> \
    --data-urlencode 'op=stat' \
    --data-urlencode 'lpath=<path/to/collection>'
```

_Returns:_
```json
{
}
```

#### Operation: list

_HTTP Method_: GET

_Command:_
```bash
curl -G -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version> \
    --data-urlencode 'op=list' \
    --data-urlencode 'lpath=<path/to/collection>'
```

_Returns:_
```json
{
}
```

#### Operation: set_permission

_HTTP Method_: POST

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version> \
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

#### Operation: rename

_HTTP Method_: POST

_Command:_
```bash
curl -H 'Authorization: Bearer <token>' http://localhost:<port>/irods-http/<version> \
    --data-urlencode 'op=rename' \
    --data-urlencode 'old-lpath=<path/to/old_collection>' \
    --data-urlencode 'new-lpath=<path/to/new_collection>'
```

_Returns:_
```json
{
}
```

### Data Objects



### Information



### Metadata



### Query



### Resources



### Rules



### Tickets



### Users and Groups



### Zones


