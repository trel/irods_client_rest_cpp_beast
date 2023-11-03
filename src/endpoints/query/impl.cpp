#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_query.hpp>
#include <irods/procApiRequest.h>
#include <irods/query_builder.hpp>
#include <irods/rodsErrorTable.h>

#ifdef IRODS_ENABLE_GENQUERY2
#  include <irods/plugins/api/genquery2_common.h>
#endif // IRODS_ENABLE_GENQUERY2

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

#define IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(name) \
  auto name(                                              \
	  irods::http::session_pointer_type _sess_ptr,        \
	  irods::http::request_type& _req,                    \
	  irods::http::query_arguments_type& _args)           \
	  ->void

namespace
{
	using handler_type =
		void (*)(irods::http::session_pointer_type, irods::http::request_type&, irods::http::query_arguments_type&);

	//
	// Handler function prototypes
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_execute_genquery);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_execute_specific_query);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list_genquery_columns);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list_specific_queries);

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_add_specific_query);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove_specific_query);

	//
	// Operation to Handler mappings
	//

	// clang-format off
	const std::unordered_map<std::string, handler_type> handlers_for_get{
		{"execute_genquery", op_execute_genquery},
		{"execute_specific_query", op_execute_specific_query},
		{"list_genquery_columns", op_list_genquery_columns},
		{"list_specific_queries", op_list_specific_queries}
	};

	const std::unordered_map<std::string, handler_type> handlers_for_post{
		{"add_specific_query", op_add_specific_query},
		{"remove_specific_query", op_remove_specific_query}
	};
	// clang-format on
} // anonymous namespace

namespace irods::http::handler
{
	// NOLINTNEXTLINE(performance-unnecessary-value-param)
	IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(query)
	{
		if (_req.method() == verb_type::get) {
			auto url = irods::http::parse_url(_req);

			const auto op_iter = url.query.find("op");
			if (op_iter == std::end(url.query)) {
				log::error("{}: Missing [op] parameter.", __func__);
				return _sess_ptr->send(irods::http::fail(status_type::bad_request));
			}

			if (const auto iter = handlers_for_get.find(op_iter->second); iter != std::end(handlers_for_get)) {
				return (iter->second)(_sess_ptr, _req, url.query);
			}

			return _sess_ptr->send(fail(status_type::bad_request));
		}

		if (_req.method() == verb_type::post) {
			auto args = irods::http::to_argument_list(_req.body());

			const auto op_iter = args.find("op");
			if (op_iter == std::end(args)) {
				log::error("{}: Missing [op] parameter.", __func__);
				return _sess_ptr->send(irods::http::fail(status_type::bad_request));
			}

			if (const auto iter = handlers_for_post.find(op_iter->second); iter != std::end(handlers_for_post)) {
				return (iter->second)(_sess_ptr, _req, args);
			}

			return _sess_ptr->send(fail(status_type::bad_request));
		}

		log::error("{}: Incorrect HTTP method.", __func__);
		return _sess_ptr->send(irods::http::fail(status_type::method_not_allowed));
	} // query
} // namespace irods::http::handler

namespace
{
	//
	// Operation handler implementations
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_execute_genquery)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;
		log::info("{}: client_info.username = [{}]", __func__, client_info.username);

		irods::http::globals::background_task(
			[fn = __func__, _sess_ptr, req = std::move(_req), args = std::move(_args), client_info]() mutable {
				auto query_iter = args.find("query");
				if (query_iter == std::end(args)) {
					log::error("{}: Missing [query] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(http::status::bad_request));
				}

				std::string parser = "genquery1";
				const auto parser_iter = args.find("parser");
				if (parser_iter != std::end(args)) {
					if (parser_iter->second != "genquery1" && parser_iter->second != "genquery2") {
						log::error("{}: Invalid argument for [parser] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(http::status::bad_request));
					}

					parser = parser_iter->second;
				}

				http::response<http::string_body> res{http::status::ok, req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(req.keep_alive());

				try {
					json::array_t row;
					json::array_t rows;

					auto conn = irods::get_connection(client_info.username);

					if ("genquery2" == parser) {
#ifdef IRODS_ENABLE_GENQUERY2
						genquery2_input input{};
						input.query_string = query_iter->second.data();

						auto sql_only_iter = args.find("sql-only");
						if (sql_only_iter != std::end(args) && "1" == sql_only_iter->second) {
							input.sql_only = 1;
						}

						auto zone_iter = args.find("zone");
						if (zone_iter != std::end(args)) {
							input.zone = zone_iter->second.data();
						}

						char* output{};
						irods::at_scope_exit free_output{[&output] { std::free(output); }};

						const auto ec = procApiRequest(
							static_cast<RcComm*>(conn),
							IRODS_APN_GENQUERY2,
							&input,
							nullptr,
							reinterpret_cast<void**>(&output),
							nullptr);

						if (ec < 0) {
							res.result(http::status::bad_request);
							res.body() = json{{"irods_response", {{"status_code", ec}}}}.dump();
						}

						if (0 == input.sql_only) {
							// The string below contains a format placeholder for the "rows" property
							// because this avoids the need to parse the GenQuery2 results into an nlohmann
							// JSON object just to serialize it for the response.
							constexpr const auto* json_fmt_string =
								R"_({{"irods_response":{{"status_code":0}},"rows":{}}})_";
							res.body() = fmt::format(json_fmt_string, output);
						}
						else {
							constexpr const auto* json_fmt_string =
								R"_({{"irods_response":{{"status_code":0}},"sql":"{}"}})_";
							res.body() = fmt::format(json_fmt_string, output);
						}
#else
						res.result(http::status::bad_request);
						res.body() = json{{"irods_response",
					                       {{"status_code", 0},
					                        {"status_message", "GenQuery2 not enabled. Use GenQuery1 parser."}}}}
					                     .dump();
#endif // IRODS_ENABLE_GENQUERY2
					}
					else {
						int offset = 0;
						if (const auto iter = args.find("offset"); iter != std::end(args)) {
							try {
								offset = std::stoi(iter->second);
							}
							catch (const std::exception& e) {
								log::error("{}: Could not convert [offset] parameter value into an integer. ", fn);
								return _sess_ptr->send(irods::http::fail(http::status::bad_request));
							}
						}
						offset = std::max(0, offset);

						static const auto max_row_count =
							irods::http::globals::configuration()
								.at(json::json_pointer{"/irods_client/max_number_of_rows_per_catalog_query"})
								.get<int>();
						int count = max_row_count;
						if (const auto iter = args.find("count"); iter != std::end(args)) {
							try {
								count = std::stoi(iter->second);
							}
							catch (const std::exception& e) {
								log::error("{}: Could not convert [count] parameter value into an integer. ", fn);
								return _sess_ptr->send(irods::http::fail(http::status::bad_request));
							}
						}
						count = std::clamp(count, 1, max_row_count);

						int offset_counter = 0;
						int count_counter = 0;

						for (auto&& r : irods::query{static_cast<RcComm*>(conn), query_iter->second}) {
							if (offset_counter < offset) {
								++offset_counter;
								continue;
							}

							for (auto&& c : r) {
								row.push_back(c);
							}

							rows.push_back(row);
							row.clear();

							if (++count_counter == count) {
								break;
							}
						}

						res.body() = json{
							{"irods_response",
					         {
								 {"status_code", 0},
							 }},
							{"rows",
					         rows}}.dump();
					}
				}
				catch (const irods::exception& e) {
					res.result(http::status::bad_request);
					res.body() =
						json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
							.dump();
				}
				catch (const std::exception& e) {
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_execute_genquery

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_execute_specific_query)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;
		log::info("{}: client_info.username = [{}]", __func__, client_info.username);

		const auto name_iter = _args.find("name");
		if (name_iter == std::end(_args)) {
			log::error("{}: Missing [name] parameter.", __func__);
			return _sess_ptr->send(irods::http::fail(http::status::bad_request));
		}

		int offset = 0;
		if (const auto iter = _args.find("offset"); iter != std::end(_args)) {
			try {
				offset = std::stoi(iter->second);
			}
			catch (const std::exception& e) {
				log::error("{}: Could not convert [offset] parameter value into an integer. ", __func__);
				return _sess_ptr->send(irods::http::fail(http::status::bad_request));
			}
		}
		offset = std::max(0, offset);

		static const auto max_row_count =
			irods::http::globals::configuration()
				.at(json::json_pointer{"/irods_client/max_number_of_rows_per_catalog_query"})
				.get<int>();
		int count = max_row_count;
		if (const auto iter = _args.find("count"); iter != std::end(_args)) {
			try {
				count = std::stoi(iter->second);
			}
			catch (const std::exception& e) {
				log::error("{}: Could not convert [count] parameter value into an integer. ", __func__);
				return _sess_ptr->send(irods::http::fail(http::status::bad_request));
			}
		}
		count = std::clamp(count, 1, max_row_count);

		std::vector<std::string> args;

		if (const auto iter = _args.find("args"); iter != std::end(_args) && !iter->second.empty()) {
			if (const auto delim_iter = _args.find("args-delimiter");
			    delim_iter != std::end(_args) && !delim_iter->second.empty()) {
				boost::split(args, iter->second, boost::is_any_of(delim_iter->second));
			}
			else {
				boost::split(args, iter->second, boost::is_any_of(","));
			}
		}

		http::response<http::string_body> res{http::status::ok, _req.version()};
		res.set(http::field::server, irods::http::version::server_name);
		res.set(http::field::content_type, "application/json");
		res.keep_alive(_req.keep_alive());

		irods::http::globals::background_task([fn = __func__,
		                                       _sess_ptr,
		                                       client_info,
		                                       name = name_iter->second,
		                                       res = std::move(res),
		                                       offset,
		                                       count,
		                                       args = std::move(args)]() mutable {
			static_cast<void>(fn);

			try {
				json::array_t row;
				json::array_t rows;

				{
					irods::experimental::query_builder qb;

					qb.type(irods::experimental::query_type::specific);
					qb.bind_arguments(args);
					//qb.row_offset(offset);
					//qb.row_limit(count);
					//qb.zone_hint("");

					int offset_counter = 0;
					int count_counter = 0;

					auto conn = irods::get_connection(client_info.username);

					for (auto&& r : qb.build<RcComm>(conn, name)) {
						if (offset_counter < offset) {
							++offset_counter;
							continue;
						}

						for (auto&& c : r) {
							row.push_back(c);
						}

						rows.push_back(row);
						row.clear();

						if (++count_counter == count) {
							break;
						}
					}
				}

				res.body() = json{
					{"irods_response",
				     {
						 {"status_code", 0},
					 }},
					{"rows",
				     rows}}.dump();
			}
			catch (const irods::exception& e) {
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_execute_genquery

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list_genquery_columns)
	{
		(void) _req;
		(void) _args;
		log::error("{}: Operation not implemented.", __func__);
		return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
	} // op_list_genquery_columns

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list_specific_queries)
	{
		(void) _req;
		(void) _args;
		log::error("{}: Operation not implemented.", __func__);
		return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
	} // op_list_specific_queries

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_add_specific_query)
	{
		(void) _req;
		(void) _args;
		log::error("{}: Operation not implemented.", __func__);
		return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
	} // op_add_specific_query

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove_specific_query)
	{
		(void) _req;
		(void) _args;
		log::error("{}: Operation not implemented.", __func__);
		return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
	} // op_remove_specific_query
} // anonymous namespace
