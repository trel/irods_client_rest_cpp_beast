# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project **only** adheres to the following _(as defined at [Semantic Versioning](https://semver.org/spec/v2.0.0.html))_:

> Given a version number MAJOR.MINOR.PATCH, increment the:
> 
> - MAJOR version when you make incompatible API changes
> - MINOR version when you add functionality in a backward compatible manner
> - PATCH version when you make backward compatible bug fixes

## [0.5.0] - 2024-11-13

This release includes a user-mapping plugin system that enables dynamic user-mapping between OpenID Connect users and iRODS users. It also includes improved security through token validation.

User-mapping functionality from previous versions of the HTTP API is now provided through the user-mapping plugin system. See [Mapping OpenID Users to iRODS](https://github.com/irods/irods_client_http_api/tree/0.5.0?tab=readme-ov-file#mapping-openid-users-to-irods) for details.

### Changed

- Improve documentation for `tls_certificates_directory` OIDC property (#243).
- Provide clear message on OIDC connection error (#244).
- Collapse management of version number to single point of control (#269).
- Improve handling of inaccessible configuration file on startup (#337).

### Fixed

- Disable SIGPIPE signal for iRODS connections (#333).
- Server no longer enters infinite loop when listening socket is already bound (#335).
- Server verifies OIDC-mapped iRODS username exists in catalog before returning bearer token (#338).
- Server terminates on startup if configuration received from OIDC Provider does not contain required information (#356).
- Leave space for null-terminating byte in destination buffer when using `std::string::copy` (#365).

### Added

- Implement validation of OIDC ID tokens in client mode (#107).
- Implement validation of OAuth Token Introspection response (#270).
- Implement user-mapping plugin system (#293).
- Implement local validation of JWT Access Tokens (#343, #359).

## [0.4.0] - 2024-08-26

This release includes several enhancements including more exposure of the iRODS API, logging of IP addresses, an improved multipart/form-data parser, and improved stability.

### Changed

- Log IP address of clients (#73).
- Remove **experimental** from package name (#159).
- Distribute long-running write operations across thread-pool (#196).
- Replace support for GenQuery2 API plugin with native iRODS 4.3.2 implementation (#272).
- Improve documentation (#285, #286, #294, #309, #310, #312, #323).
- Improve testing (#287).
- Stat of resource no longer interprets resource status string (#299).
- Remove unnecessary log functions (#324).
- Rename namespace alias for logger to avoid name collisions with C++ standard library (#325).
- Rename configuration property to better express its intent (#328).

### Removed

- Stat of data object no longer includes `registered` property in JSON object (#180).

### Fixed

- Rewrite multipart/form-data parser to handle embedded CRLFs (#273).
- Server no longer segfaults during OIDC bearer token resolution (#300).

### Added

- Implement support for modifying properties of resources (#133).
- Implement support for applying expiration to new tickets (#134).
- Implement support for adding and removing SpecificQueries (#276).
- Implement support for adding, removing, and modifying zones (#277).
