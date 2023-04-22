#include "common.hpp"
#include "handlers.hpp"
#include "log.hpp"

//#include <irods/atomic_apply_metadata_operations.h>
//#include <irods/base64.hpp>
//#include <irods/client_connection.hpp>
//#include <irods/execCmd.h>
//#include <irods/execMyRule.h>
//#include <irods/filesystem.hpp>
//#include <irods/irods_at_scope_exit.hpp>
//#include <irods/irods_configuration_keywords.hpp>
//#include <irods/irods_exception.hpp>
//#include <irods/irods_query.hpp>
//#include <irods/msParam.h>
//#include <irods/process_stash.hpp>
//#include <irods/rcConnect.h>
//#include <irods/rcMisc.h>
//#include <irods/resource_administration.hpp>
#include <irods/rodsClient.h>
//#include <irods/rodsErrorTable.h>
//#include <irods/rodsKeyWdDef.h>
//#include <irods/ruleExecDel.h>
//#include <irods/touch.h>
//#include <irods/ticket_administration.hpp>
//#include <irods/user_administration.hpp>
//
//#include <irods/transport/default_transport.hpp>
//#include <irods/dstream.hpp>

#include <curl/curl.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <memory>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// clang-format off
namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http  = beast::http;  // from <boost/beast/http.hpp>
namespace net   = boost::asio;  // from <boost/asio.hpp>
namespace log   = irods::http::log;

using tcp             = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
using request_handler = irods::http::response_type(*)(const irods::http::request_type&);

const std::unordered_map<std::string_view, request_handler> req_handlers{
    {"/irods-rest/0.9.5/authenticate", irods::http::handler::authentication},
    {"/irods-rest/0.9.5/collections",  irods::http::handler::collections},
    //{"/irods-rest/0.9.5/config",     irods::http::handler::configuration},
    {"/irods-rest/0.9.5/data-objects", irods::http::handler::data_objects},
    {"/irods-rest/0.9.5/metadata",     irods::http::handler::metadata},
    {"/irods-rest/0.9.5/query",        irods::http::handler::query},
    {"/irods-rest/0.9.5/resources",    irods::http::handler::resources},
    {"/irods-rest/0.9.5/rules",        irods::http::handler::rules},
    {"/irods-rest/0.9.5/tickets",      irods::http::handler::tickets},
    {"/irods-rest/0.9.5/users-groups", irods::http::handler::users_groups},
    //{"/irods-rest/0.9.5/zones",        "/zones"}
};
// clang-format on

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template <class Body, class Allocator, class Send>
auto handle_request(http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send) -> void
{
    // Print the headers.
    for (auto&& h : req.base()) {
        log::debug("{}: Header: ({}, {})", __func__, h.name_string(), h.value());
    }

    // Print the components of the request URL.
    log::debug("{}: Method: {}", __func__, req.method_string());
    log::debug("{}: Version: {}", __func__, req.version());
    log::debug("{}: Target: {}", __func__, req.target());
    log::debug("{}: Keep Alive: {}", __func__, req.keep_alive());
    log::debug("{}: Has Content Length: {}", __func__, req.has_content_length());
    log::debug("{}: Chunked: {}", __func__, req.chunked());
    log::debug("{}: Needs EOF: {}", __func__, req.need_eof());

    // "host" is a placeholder that's used so that get_url_path() can parse the URL correctly.
    const auto path = irods::http::get_url_path(fmt::format("http://host{}", req.target()));
    if (!path) {
        send(std::move(irods::http::fail(http::status::bad_request)));
    }

    if (const auto iter = req_handlers.find(*path); iter != std::end(req_handlers)) {
        send((iter->second)(req));
        return;
    }

    send(std::move(irods::http::fail(http::status::not_found)));
}

// Report a failure.
auto fail(beast::error_code ec, char const* what) -> void
{
    log::error("{}: {}: {}", __func__, what, ec.message());
}

// Handles an HTTP server connection.
class session : public std::enable_shared_from_this<session>
{
    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        session& self_;

        explicit send_lambda(session& self)
            : self_(self)
        {
        }

        template <bool isRequest, class Body, class Fields>
        auto operator()(http::message<isRequest, Body, Fields>&& msg) const -> void
        {
            // The lifetime of the message has to extend
            // for the duration of the async operation so
            // we use a shared_ptr to manage it.
            auto sp = std::make_shared<
                http::message<isRequest, Body, Fields>>(std::move(msg));

            // Store a type-erased version of the shared
            // pointer in the class to keep it alive.
            self_.res_ = sp;

            // Write the response
            http::async_write(
                self_.stream_,
                *sp,
                beast::bind_front_handler(
                    &session::on_write,
                    self_.shared_from_this(),
                    sp->need_eof()));
        }
    }; // struct send_lambda

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;

public:
    // Take ownership of the stream
    session(tcp::socket&& socket) // TODO Mark explicit?
        : stream_(std::move(socket))
        , lambda_(*this)
    {
    } // session (constructor)

    // Start the asynchronous operation
    auto run() -> void
    {
        // We need to be executing within a strand to perform async operations
        // on the I/O objects in this session. Although not strictly necessary
        // for single-threaded contexts, this example code is written to be
        // thread-safe by default.
        net::dispatch(stream_.get_executor(),
                      beast::bind_front_handler(
                          &session::do_read,
                          shared_from_this()));
    } // run

    auto do_read() -> void
    {
        // Make the request empty before reading,
        // otherwise the operation behavior is undefined.
        req_ = {};

        // Set the timeout.
        stream_.expires_after(std::chrono::seconds(30));

        // Read a request
        http::async_read(stream_, buffer_, req_,
            beast::bind_front_handler(
                &session::on_read,
                shared_from_this()));
    } // do_read

    auto on_read(beast::error_code ec, std::size_t bytes_transferred) -> void
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if (ec == http::error::end_of_stream) {
            return do_close();
        }

        if (ec) {
            return fail(ec, "read");
        }

        // Send the response
        handle_request(std::move(req_), lambda_);
    } // on_read

    auto on_write(bool close, beast::error_code ec, std::size_t bytes_transferred) -> void
    {
        boost::ignore_unused(bytes_transferred);

        if (ec) {
            return fail(ec, "write");
        }

        if (close) {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return do_close();
        }

        // We're done with the response so delete it
        res_ = nullptr;

        // Read another request
        do_read();
    } // on_write

    auto do_close() -> void
    {
        // Send a TCP shutdown.
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully.
    } // do_close
}; // class session

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions.
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context& ioc_;
    tcp::acceptor acceptor_;

public:
    listener(net::io_context& ioc, tcp::endpoint endpoint)
        : ioc_(ioc)
        , acceptor_(net::make_strand(ioc))
    {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if (ec) {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            fail(ec, "listen");
            return;
        }
    } // listener (constructor)

    // Start accepting incoming connections.
    auto run() -> void
    {
        do_accept();
    } // run

private:
    auto do_accept() -> void
    {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(
                &listener::on_accept,
                shared_from_this()));
    } // do_accept

    auto on_accept(beast::error_code ec, tcp::socket socket) -> void
    {
        if (ec) {
            fail(ec, "accept");
            return; // To avoid infinite loop
        }

        // Create the session and run it
        std::make_shared<session>(std::move(socket))->run();

        // Accept another connection
        do_accept();
    } // on_accept
}; // class listener

int main(int argc, char* argv[])
{
    // TODO All of this needs to be wrapped in a try-catch block.

    // TODO For LONG running tasks, see the following:
    //
    //   - https://stackoverflow.com/questions/17648725/long-running-blocking-operations-in-boost-asio-handlers
    //   - https://www.open-std.org/JTC1/SC22/WG21/docs/papers/2012/n3388.pdf
    //

    // Check command line arguments.
    if (argc != 4) {
        std::cerr <<
            "Usage: http-server-async <address> <port> <threads>\n" <<
            "Example:\n" <<
            "    http-server-async 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }

    load_client_api_plugins();

    const auto address = net::ip::make_address(argv[1]);
    const auto port = static_cast<unsigned short>(std::atoi(argv[2]));
    const auto threads = std::max<int>(1, std::atoi(argv[3]));

    // The io_context is required for all I/O.
    net::io_context ioc{threads};

    // Create and launch a listening port.
    std::make_shared<listener>(ioc, tcp::endpoint{address, port})->run();

    // Run the I/O service on the requested number of threads.
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i) {
        v.emplace_back([&ioc] { ioc.run(); });
    }
    ioc.run();

    return EXIT_SUCCESS;
}
