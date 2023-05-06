#ifndef IRODS_HTTP_API_HANDLERS_HPP
#define IRODS_HTTP_API_HANDLERS_HPP

#include "common.hpp"

namespace irods::http::handler
{
    auto authentication(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto collections(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto config(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto data_objects(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto information(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto metadata(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto query(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto resources(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto rules(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto tickets(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto users_groups(session_pointer_type _session_ptr, request_type& _request) -> void;

    auto zones(session_pointer_type _session_ptr, request_type& _request) -> void;
} // namespace irods::http::handler

#endif // IRODS_HTTP_API_HANDLERS_HPP
