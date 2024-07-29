#ifndef IRODS_HTTP_API_MULTIPART_FORM_DATA_HPP
#define IRODS_HTTP_API_MULTIPART_FORM_DATA_HPP

#include "irods/private/http_api/common.hpp"

#include <optional>
#include <string_view>

namespace irods::http
{
	auto get_multipart_form_data_boundary(const std::string_view _data) -> std::optional<std::string_view>;

	auto parse_multipart_form_data(const std::string_view _boundary, const std::string_view _data)
		-> query_arguments_type;
} // namespace irods::http

#endif // IRODS_HTTP_API_MULTIPART_FORM_DATA_HPP
