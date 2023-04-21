#ifndef IRODS_HTTP_API_HANDLERS_HPP
#define IRODS_HTTP_API_HANDLERS_HPP

#include "common.hpp"

namespace irods::http::handler
{
    auto authentication(const request_type& _request) -> response_type;

    auto collections(const request_type& _request) -> response_type;

    auto config(const request_type& _request) -> response_type;

    auto data_objects(const request_type& _request) -> response_type;

    auto metadata(const request_type& _request) -> response_type;

    auto query(const request_type& _request) -> response_type;

    auto resources(const request_type& _request) -> response_type;

    auto rules(const request_type& _request) -> response_type;

    auto tickets(const request_type& _request) -> response_type;

    auto users_gropus(const request_type& _request) -> response_type;
} // namespace irods::http::handler

#endif // IRODS_HTTP_API_HANDLERS_HPP
