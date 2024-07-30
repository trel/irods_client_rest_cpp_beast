set(
  IRODS_USER_MAPPING_PLUGINS
  local_file
  user_claim
)

foreach(plugin IN LISTS IRODS_USER_MAPPING_PLUGINS)
  string(TOUPPER ${plugin} PLUGIN_UPPERCASE)
  set(plugin_target "irods_http_api_plugin-${plugin}")
  set(plugin_name "irods_http_api_plugin-${plugin}")

  add_library(
    ${plugin_target}
    MODULE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/${plugin}.cpp"
  )
  set_property(TARGET ${plugin_target} PROPERTY LIBRARY_OUTPUT_NAME ${plugin_name})
  target_link_libraries(
    ${plugin_target}
    PRIVATE
    irods_common
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
    fmt::fmt
    ${CMAKE_DL_LIBS}
  )
  target_include_directories(
    ${plugin_target}
    PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  )
  target_compile_definitions(
    ${plugin_target}
    PRIVATE
    ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  )

  install(
    TARGETS
    ${plugin_target}
    LIBRARY
    DESTINATION "${IRODS_HTTP_PLUGINS_DIRECTORY}/user_mapping"
  )
endforeach()
