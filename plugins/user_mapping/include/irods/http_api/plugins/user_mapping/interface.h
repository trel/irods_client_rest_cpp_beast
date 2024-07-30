#ifndef IRODS_HTTP_API_USER_MAPPER_INTERFACE_H
#define IRODS_HTTP_API_USER_MAPPER_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/// Initializes the user mapping plugin.
///
/// \param[in] _args A C-string containing the JSON representing the configuration for the plugin.
///                  The structure of the JSON depends on the requirements specified by the plugin.
///
/// \pre \p _args must be a non-null C-string that represents a JSON structure.
///
/// \returns A code representing the result of the operation.
/// \retval  zero if initialization of the plugin was successful.
/// \retval  non-zero if initialization of the plugin was not successful.
int user_mapper_init(const char* _args);

/// Matches the given information to a user.
///
/// \param[in]  _param A C-string containing the JSON representing information from an
///                    authenticated OpenID User. This can either take the form of an
///                    OpenID Access Token or ID Token.
/// \param[out] _match A pointer to a C-string. Gives the irods username of the matched user.
///                    Returns a nullptr if no match is found.
///
/// \pre The mapping plugin must have successfully been initialized beforehand.
/// \pre \p _param must be a non-null C-string that represents a JSON structure.
/// \pre \p _match must be a non-null pointer to a C-string.
///
/// \returns A code representing the result of the operation.
/// \retval  zero if matching of the plugin was successful.
/// \retval  non-zero if an error occurred while matching.
int user_mapper_match(const char* _param, char** _match);

/// Executes clean-up for the user mapping plugin.
///
/// \pre The mapping plugin must have successfully been initialized beforehand.
///
/// \returns A code representing the result of the operation.
/// \retval  zero if closing of the plugin was successful.
/// \retval  non-zero if closing of the plugin was not successful.
int user_mapper_close();

/// Frees a C-string generated from the user mapping plugin.
///
/// \param[in] _data A C-string originating from the user mapping plugin.
void user_mapper_free(char* _data);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_HTTP_API_USER_MAPPER_INTERFACE_H
