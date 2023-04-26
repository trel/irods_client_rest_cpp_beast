include(GetGitRevisionDescription)

get_git_head_revision(IRODS_HTTP_GIT_REFSPEC IRODS_HTTP_GIT_SHA1)
configure_file(
  ${CMAKE_SOURCE_DIR}/src/version.hpp.in
  ${CMAKE_BINARY_DIR}/src/version.hpp
  @ONLY)

add_subdirectory(endpoints)

set(EXECUTABLE_NAME ${IRODS_HTTP_BINARY_NAME})

add_executable(${EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)

target_compile_definitions(
  ${EXECUTABLE_NAME}
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS}
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  # Needed so that beast::string_view can be passed to fmtlib.
  # Likely defines the following:
  #
  #  using string_view = std::string_view;
  #
  BOOST_BEAST_USE_STD_STRING_VIEW
  # The following macro requires that the application never attempt to
  # change log levels concurrently across threads.
  SPDLOG_NO_ATOMIC_LEVELS
  # Defines a macro which is used to construct the URL paths to individual
  # endpoint handlers (e.g. /irods-http/1.0.0/collections).
  IRODS_HTTP_API_BASE_URL="/irods-http/${IRODS_HTTP_API_VERSION}")

target_include_directories(
  ${EXECUTABLE_NAME}
  PRIVATE
  ${IRODS_INCLUDE_DIRS}
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
  ${IRODS_EXTERNALS_FULLPATH_FMT}/include
  ${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include
  CURL::libcurl
  ${CMAKE_CURRENT_BINARY_DIR} # For version.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/endpoints)

target_link_libraries(
  ${EXECUTABLE_NAME}
  PRIVATE
  irods_client
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_program_options.so
  ${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so
  CURL::libcurl
  $<TARGET_OBJECTS:authentication>
  $<TARGET_OBJECTS:collections>
  #$<TARGET_OBJECTS:config>
  $<TARGET_OBJECTS:data_objects>
  $<TARGET_OBJECTS:information>
  $<TARGET_OBJECTS:metadata>
  $<TARGET_OBJECTS:query>
  $<TARGET_OBJECTS:resources>
  $<TARGET_OBJECTS:rules>
  $<TARGET_OBJECTS:tickets>
  $<TARGET_OBJECTS:users_groups>
  $<TARGET_OBJECTS:zones>)
