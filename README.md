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

## Run

To run the server, do the following:
```bash
./irods_http_api /path/to/config/file.json
```

To stop the server, you can use **CTRL-C** or send **SIGINT** or **SIGTERM** to the process.

## Documentation

Documentation can be found in the [wiki](https://github.com/irods/irods_client_http_api/wiki).
