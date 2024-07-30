include(GNUInstallDirs)

set(
  IRODS_HTTP_PLUGINS_DIRECTORY
  "${CMAKE_INSTALL_LIBDIR}/irods_http_api/plugins"
)

add_subdirectory(user_mapping)
