set(IRODS_HTTP_ENDPOINT query)

add_library(
  ${IRODS_HTTP_ENDPOINT}
  OBJECT
  impl.cpp)

target_compile_definitions(
  ${IRODS_HTTP_ENDPOINT}
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS}
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE})

if (IRODS_ENABLE_GENQUERY2)
  target_compile_definitions(${IRODS_HTTP_ENDPOINT} PRIVATE IRODS_ENABLE_GENQUERY2)
endif()

target_include_directories(
  ${IRODS_HTTP_ENDPOINT}
  PRIVATE
  ${IRODS_INCLUDE_DIRS}
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
  ${IRODS_EXTERNALS_FULLPATH_FMT}/include
  ${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include
  ${CMAKE_BINARY_DIR}/src # For version.hpp
  ${CMAKE_SOURCE_DIR}/src # For log.hpp
  ${CMAKE_SOURCE_DIR}/src/endpoints) # For common.hpp

target_link_libraries(
  ${IRODS_HTTP_ENDPOINT}
  PRIVATE
  CURL::libcurl
  nlohmann_json::nlohmann_json)
