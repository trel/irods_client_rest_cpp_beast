option(IRODS_ENABLE_GENQUERY2 "Enables GenQuery2 support. GenQuery2 package must be installed." NO)

set(IRODS_HTTP_SHARED_API_OPERATIONS shared_api_operations)

add_library(
  ${IRODS_HTTP_SHARED_API_OPERATIONS}
  OBJECT
  shared_api_operations.cpp)

target_compile_definitions(
  ${IRODS_HTTP_SHARED_API_OPERATIONS}
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS}
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE})

target_include_directories(
  ${IRODS_HTTP_SHARED_API_OPERATIONS}
  PRIVATE
  ${IRODS_INCLUDE_DIRS}
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
  ${IRODS_EXTERNALS_FULLPATH_FMT}/include
  ${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include
  ${CMAKE_BINARY_DIR}/src # For version.hpp
  ${CMAKE_SOURCE_DIR}/src # For log.hpp
  ${CMAKE_SOURCE_DIR}/src/endpoints)

target_link_libraries(
  ${IRODS_HTTP_SHARED_API_OPERATIONS}
  PRIVATE
  CURL::libcurl
  nlohmann_json::nlohmann_json)

add_subdirectory(authentication)
add_subdirectory(collections)
#add_subdirectory(config)
add_subdirectory(data_objects)
add_subdirectory(information)
add_subdirectory(query)
add_subdirectory(resources)
add_subdirectory(rules)
add_subdirectory(tickets)
add_subdirectory(users_groups)
add_subdirectory(zones)
