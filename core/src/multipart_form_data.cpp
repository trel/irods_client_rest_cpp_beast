#include "irods/private/http_api/multipart_form_data.hpp"

#include "irods/private/http_api/log.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/beast/http/rfc7230.hpp>

#include <fmt/format.h>

namespace irods::http
{
	auto get_multipart_form_data_boundary(const std::string_view _data) -> std::optional<std::string_view>
	{
		namespace logging = irods::http::log;

		// The ext_list type does not treat "multipart/form-data" as a single string.
		// I'm not sure if this is by design, but we have to skip the multipart/ prefix so that
		// ext_list can extract the boundary argument.

		const auto pos = _data.find("form-data");

		if (pos == std::string_view::npos) {
			return std::nullopt;
		}

		boost::beast::http::ext_list list{_data.substr(pos)};
		const auto iter = list.find("form-data");

		if (iter == std::end(list)) {
			logging::error("{}: Missing [boundary] parameter in [multipart/form-data] value.", __func__);
			return std::nullopt;
		}

		for (auto&& param : iter->second) {
			if (param.first == "boundary") {
				logging::debug("{}: Parameter => (name={}, value={})", __func__, param.first, param.second);
				return param.second;
			}
		}

		return std::nullopt;
	} // get_multipart_form_data_boundary

	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters, readability-function-cognitive-complexity)
	auto parse_multipart_form_data(const std::string_view _boundary, const std::string_view _data)
		-> query_arguments_type
	{
		namespace logging = irods::http::log;

		if (_data.empty()) {
			return {};
		}

		const auto boundary_start = fmt::format("--{}", _boundary);
		const auto boundary_end = fmt::format("{}--", boundary_start);

		enum class parser_state
		{
			find_boundary_start,
			read_boundary_start,
			read_header,
			read_body
		};

		query_arguments_type args;
		auto pstate = parser_state::find_boundary_start;
		std::string_view::size_type pos = 0;
		std::string param_name;

		while (true) {
			switch (pstate) {
				using enum parser_state;

				case find_boundary_start: {
					const auto bs_pos = _data.find(boundary_start, pos);
					if (std::string_view::npos == bs_pos) {
						logging::error(
							"{}: Expected boundary start [{}]. Malformed message structure.", __func__, boundary_start);
						return args;
					}
					pos = bs_pos;

					// Did we actually find a boundary end marker?
					if (boundary_end == _data.substr(pos, boundary_end.size())) {
						logging::trace("{}: Found boundary end [{}]. Done.", __func__, boundary_end);
						return args;
					}

					// We found a boundary start marker.
					pstate = read_boundary_start;
					break;
				}

				case read_boundary_start: {
					// Check that the boundary start ends with a CRLF sequence.
					const auto crlf_pos = pos + boundary_start.size();
					if ("\r\n" != _data.substr(crlf_pos, 2)) {
						logging::error(
							"{}: Expected CRLF [\\r\\n] after boundary start. Malformed message structure.", __func__);
						return args;
					}

					pos = crlf_pos + 2;
					pstate = read_header;
					break;
				}

				case read_header: {
					// Extract the header name.
					auto colon_pos = _data.find(':', pos);
					if (std::string_view::npos == colon_pos) {
						logging::error("{}: Expected colon [:] in header line. Malformed message structure.", __func__);
						return args;
					}
					const auto hdr_n = _data.substr(pos, colon_pos - pos);
					logging::debug("{}: Header name = [{}]", __func__, hdr_n);
					auto header_name = boost::trim_copy(std::string{hdr_n});

					// Extract the header value.
					pos = colon_pos + 1;
					auto crlf_pos = _data.find("\r\n", pos);
					if (std::string_view::npos == crlf_pos) {
						logging::error(
							"{}: Expected CRLF [\\r\\n] in header line. Malformed message structure.", __func__);
						return args;
					}
					const auto hdr_v = _data.substr(pos, crlf_pos - pos);
					logging::debug("{}: Header value = [{}]", __func__, hdr_v);

					// Capture the parameter name.
					if (boost::iequals(header_name, "content-disposition")) {
						// See https://www.rfc-editor.org/rfc/rfc2045 for details about the
						// structure of MIME types.
						boost::beast::http::ext_list list{hdr_v};
						const auto type_iter = list.find("form-data");

						if (type_iter != std::end(list)) {
							for (auto&& param : type_iter->second) {
								if (param.first == "name") {
									logging::debug(
										"{}: Parameter => (name={}, value={})", __func__, param.first, param.second);
									param_name = param.second;
									break;
								}
							}
						}
					}

					// Move the read position forward. At this point, the parser
					// may be looking at the CRLF separating the list of headers
					// and the HTTP message body.
					pos = crlf_pos + 2;
					if ("\r\n" == _data.substr(pos, 2)) {
						// All headers have been read, move on to the message body.
						pos += 2;
						pstate = read_body;
					}

					break;
				}

				case read_body: {
					// Find the end of the message body.
					// It should be located just before the next boundary.
					const auto bs_pos = _data.find(boundary_start, pos);
					if (std::string_view::npos == bs_pos) {
						logging::error("{}: Expected boundary start/end. Malformed message structure.", __func__);
						return args;
					}

					// Move the read position back by two bytes to account for the CRLF.
					const auto crlf_pos = bs_pos - 2;
					if ("\r\n" != _data.substr(crlf_pos, 2)) {
						logging::error(
							"{}: Expected CRLF [\\r\\n] before message body. Malformed message structure.", __func__);
						return args;
					}

					const auto msg_body = _data.substr(pos, crlf_pos - pos);
					args.insert_or_assign(std::move(param_name), std::string{msg_body});
					param_name = {}; // Guards against use-after-move errors.

					pos = bs_pos;
					pstate = find_boundary_start;
					break;
				}
			}
		}

		return args;
	} // parse_multipart_form_data
} // namespace irods::http
