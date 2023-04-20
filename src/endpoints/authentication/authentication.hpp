#ifndef IRODS_HTTP_API_ENDPOINT_AUTHENTICATION_HPP
#define IRODS_HTTP_API_ENDPOINT_AUTHENTICATION_HPP

#include "common.hpp"

namespace irods::http::endpoint
{
    auto authentication(const request_type& _request) -> response_type;
} // namespace irods::http::endpoint

#endif // IRODS_HTTP_API_ENDPOINT_AUTHENTICATION_HPP
