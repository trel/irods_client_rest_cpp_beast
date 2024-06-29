#include "irods/private/http_api/handlers.hpp"

#include "irods/private/http_api/common.hpp"
#include "irods/private/http_api/globals.hpp"
#include "irods/private/http_api/log.hpp"
#include "irods/private/http_api/session.hpp"
#include "irods/private/http_api/version.hpp"

#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>
#include <irods/ticketAdmin.h>
#include <irods/ticket_administration.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace adm     = irods::experimental::administration;
namespace logging = irods::http::log;

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
	//
	// Handler function prototypes
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_stat);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_create);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove);

	//
	// Operation to Handler mappings
	//

	// clang-format off
	const std::unordered_map<std::string, irods::http::handler_type> handlers_for_get{
		{"list", op_list},
		{"stat", op_stat}
	};

	const std::unordered_map<std::string, irods::http::handler_type> handlers_for_post{
		{"create", op_create},
		{"remove", op_remove}
	};
	// clang-format on
} // anonymous namespace

namespace irods::http::handler
{
	// NOLINTNEXTLINE(performance-unnecessary-value-param)
	IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(tickets)
	{
		execute_operation(_sess_ptr, _req, handlers_for_get, handlers_for_post);
	} // tickets
} // namespace irods::http::handler

namespace
{
	//
	// Operation handler implementations
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list)
	{
#if 0
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            logging::info("{}: client_info.username = [{}]", fn, client_info.username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
            }
            catch (const irods::exception& e) {
				logging::error("{}: {}", fn, e.client_display_what());
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"status_code", e.code()},
                        {"status_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
				logging::error("{}: {}", fn, e.what());
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            return _sess_ptr->send(std::move(res));
        });
#else
		(void) _req;
		(void) _args;
		logging::error("{}: Operation not implemented.", __func__);
		return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
#endif
	} // op_list

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_stat)
	{
#if 0
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            logging::info("{}: client_info.username = [{}]", fn, client_info.username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
            }
            catch (const irods::exception& e) {
				logging::error("{}: {}", fn, e.client_display_what());
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"status_code", e.code()},
                        {"status_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
				logging::error("{}: {}", fn, e.what());
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            return _sess_ptr->send(std::move(res));
        });
#else
		(void) _req;
		(void) _args;
		logging::error("{}: Operation not implemented.", __func__);
		return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
#endif
	} // op_stat

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_create)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task([fn = __func__,
		                                       client_info,
		                                       _sess_ptr,
		                                       _req = std::move(_req),
		                                       _args = std::move(_args)] {
			logging::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto lpath_iter = _args.find("lpath");
				if (lpath_iter == std::end(_args)) {
					logging::error("{}: Missing [lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				auto ticket_type = adm::ticket::ticket_type::read;
				const auto type_iter = _args.find("type");
				if (type_iter != std::end(_args)) {
					if (type_iter->second == "write") {
						ticket_type = adm::ticket::ticket_type::write;
					}
					else if (type_iter->second != "read") {
						logging::error("{}: Invalid value for [type] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}
				}

				auto conn = irods::get_connection(client_info.username);
				auto ticket = adm::ticket::client::create_ticket(conn, ticket_type, lpath_iter->second);

				auto constraint_iter = _args.find("use-count");
				if (constraint_iter != std::end(_args)) {
					const auto count = std::stoi(constraint_iter->second);
					adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::use_count_constraint{count});
				}
				else {
					adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::use_count_constraint{0});
				}

				constraint_iter = _args.find("write-data-object-count");
				if (constraint_iter != std::end(_args)) {
					const auto count = std::stoi(constraint_iter->second);
					adm::ticket::client::set_ticket_constraint(
						conn, ticket, adm::ticket::n_writes_to_data_object_constraint{count});
				}
				else {
					adm::ticket::client::set_ticket_constraint(
						conn, ticket, adm::ticket::n_writes_to_data_object_constraint{0});
				}

				constraint_iter = _args.find("write-byte-count");
				if (constraint_iter != std::end(_args)) {
					const auto count = std::stoi(constraint_iter->second);
					adm::ticket::client::set_ticket_constraint(
						conn, ticket, adm::ticket::n_write_bytes_constraint{count});
				}
				else {
					adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::n_write_bytes_constraint{0});
				}

				constraint_iter = _args.find("seconds-until-expiration");
				if (constraint_iter != std::end(_args)) {
					// TODO(#283): This is similar to what the ticket administration library would provide.
					const auto secs = std::stoll(constraint_iter->second);
					if (secs <= 0) {
						logging::error(
							"{}: Invalid value for [seconds-until-expiration] parameter. Must be greater than 0.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					using std::chrono::seconds;
					using std::chrono::system_clock;

					const auto expiration_ts = system_clock::now() + seconds{secs};
					auto seconds_since_epoch = std::to_string(system_clock::to_time_t(expiration_ts));

					char mod[] = "mod"; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
					char expire[] = "expire"; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
					char empty[] = ""; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)

					TicketAdminInput input{};
					input.arg1 = mod;
					input.arg2 = ticket.data();
					input.arg3 = expire;
					input.arg4 = seconds_since_epoch.data();
					input.arg5 = empty;

					if (const auto ec = rcTicketAdmin(static_cast<RcComm*>(conn), &input); ec < 0) {
						THROW(ec, "Ticket operation failed");
					}
				}

				constraint_iter = _args.find("users");
				if (constraint_iter != std::end(_args)) {
					std::vector<std::string> users;
					boost::split(users, constraint_iter->second, boost::is_any_of(","));
					for (const auto& user : users) {
						adm::ticket::client::add_ticket_constraint(conn, ticket, adm::ticket::user_constraint{user});
					}
				}

				constraint_iter = _args.find("groups");
				if (constraint_iter != std::end(_args)) {
					std::vector<std::string> groups;
					boost::split(groups, constraint_iter->second, boost::is_any_of(","));
					for (const auto& group : groups) {
						adm::ticket::client::add_ticket_constraint(conn, ticket, adm::ticket::group_constraint{group});
					}
				}

				constraint_iter = _args.find("hosts");
				if (constraint_iter != std::end(_args)) {
					std::vector<std::string> hosts;
					boost::split(hosts, constraint_iter->second, boost::is_any_of(","));
					for (const auto& host : hosts) {
						adm::ticket::client::add_ticket_constraint(conn, ticket, adm::ticket::host_constraint{host});
					}
				}

				res.body() = json{
					{"irods_response",
				     {
						 {"status_code", 0},
					 }},
					{"ticket",
				     ticket}}.dump();
			}
			catch (const irods::exception& e) {
				logging::error("{}: {}", fn, e.client_display_what());
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				logging::error("{}: {}", fn, e.what());
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_create

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				logging::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto name_iter = _args.find("name");
					if (name_iter == std::end(_args)) {
						logging::error("{}: Missing [name] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					auto conn = irods::get_connection(client_info.username);
					adm::ticket::client::delete_ticket(conn, name_iter->second);

					res.body() = json{
						{"irods_response",
				         {
							 {"status_code", 0},
						 }}}.dump();
				}
				catch (const irods::exception& e) {
					logging::error("{}: {}", fn, e.client_display_what());
					res.body() = json{{"irods_response",
				                       {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
				                     .dump();
				}
				catch (const std::exception& e) {
					logging::error("{}: {}", fn, e.what());
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_remove
} // anonymous namespace
