#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>
#include <irods/ticket_administration.hpp>

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

namespace adm = irods::experimental::administration;
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

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_stat);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_create);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove);

	//
	// Operation to Handler mappings
	//

	// clang-format off
	const std::unordered_map<std::string, handler_type> handlers_for_get{
		{"list", op_list},
		{"stat", op_stat}
	};

	const std::unordered_map<std::string, handler_type> handlers_for_post{
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
            log::info("{}: client_info.username = [{}]", fn, client_info.username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"status_code", e.code()},
                        {"status_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            return _sess_ptr->send(std::move(res));
        });
#else
		(void) _req;
		(void) _args;
		log::error("{}: Operation not implemented.", __func__);
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
            log::info("{}: client_info.username = [{}]", fn, client_info.username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
            }
            catch (const irods::exception& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"status_code", e.code()},
                        {"status_message", e.client_display_what()}
                    }}
                }.dump();
            }
            catch (const std::exception& e) {
                res.result(http::status::internal_server_error);
            }

            res.prepare_payload();

            return _sess_ptr->send(std::move(res));
        });
#else
		(void) _req;
		(void) _args;
		log::error("{}: Operation not implemented.", __func__);
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
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto lpath_iter = _args.find("lpath");
				if (lpath_iter == std::end(_args)) {
					log::error("{}: Missing [lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				auto ticket_type = adm::ticket::ticket_type::read;
				const auto type_iter = _args.find("type");
				if (type_iter != std::end(_args)) {
					if (type_iter->second == "write") {
						ticket_type = adm::ticket::ticket_type::write;
					}
					else if (type_iter->second != "read") {
						log::error("{}: Missing [type] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}
				}

				auto conn = irods::get_connection(client_info.username);
				const auto ticket = adm::ticket::client::create_ticket(conn, ticket_type, lpath_iter->second);

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
					// TODO Not yet supported by the ticket administration library.
					log::warn("{}: Ignoring [seconds-until-expiration]. Not implemented at this time.", fn);
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
				log::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto name_iter = _args.find("name");
					if (name_iter == std::end(_args)) {
						log::error("{}: Missing [name] parameter.", fn);
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
	} // op_remove
} // anonymous namespace
