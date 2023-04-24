#include "common.hpp"
#include "globals.hpp"
#include "handlers.hpp"
#include "log.hpp"

#include <irods/connection_pool.hpp>
#include <irods/rcConnect.h>
#include <irods/rcMisc.h>
#include <irods/rodsClient.h>

#include <curl/curl.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/config.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/program_options.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// clang-format off
namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http  = beast::http;  // from <boost/beast/http.hpp>
namespace net   = boost::asio;  // from <boost/asio.hpp>
namespace po    = boost::program_options;
namespace log   = irods::http::log;

using json            = nlohmann::json;
using request_handler = irods::http::response_type(*)(const irods::http::request_type&);
using tcp             = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

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
    //{"/irods-rest/0.9.5/zones",        irods::http::handler::zones},
    //{"/irods-rest/0.9.5/info",         irods::http::handler::information}
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

auto print_usage() -> void
{
    fmt::print(R"_(irods_http_api - Exposes the iRODS API over HTTP

Usage: irods_http_api [OPTION]... CONFIG_FILE_PATH

CONFIG_FILE_PATH must point to a file containing a JSON structure containing
configuration options.

Options:
  -h, --help     Display this help message and exit.
  -v, --version  Display version information and exit.
)_");

    char name[] = "irods_http_api"; // Keeps the compiler quiet.
    printReleaseInfo(name);
} // print_usage

auto print_version_info() -> void
{
    fmt::print("iRODS Version {}.{}.{}{: >16}irods_http_api\n", IRODS_VERSION_MAJOR, IRODS_VERSION_MINOR, IRODS_VERSION_PATCHLEVEL, "");
} // print_version_info

auto set_log_level(const json& _config) -> void
{
    const auto iter = _config.find("log_level");

    if (iter == std::end(_config)) {
        spdlog::set_level(spdlog::level::info);
    }

    const auto& lvl_string = iter->get_ref<const std::string&>();
    auto lvl_enum = spdlog::level::info;

    // clang-format off
    if      (lvl_string == "trace")    { lvl_enum = spdlog::level::trace; }
    else if (lvl_string == "info")     { lvl_enum = spdlog::level::info; }
    else if (lvl_string == "debug")    { lvl_enum = spdlog::level::debug; }
    else if (lvl_string == "warn")     { lvl_enum = spdlog::level::warn; }
    else if (lvl_string == "error")    { lvl_enum = spdlog::level::err; }
    else if (lvl_string == "critical") { lvl_enum = spdlog::level::critical; }
    else                               { log::warn("Invalid log_level. Setting to [info]."); }
    // clang-format on

    spdlog::set_level(lvl_enum);
} // set_log_level

auto init_irods_connection_pool(const json& _config) -> irods::connection_pool
{
    const auto& svr = _config.at("irods_server");
    const auto& rodsadmin = svr.at("rodsadmin");

    return {
        _config.at("irods_connection_pool_size").get<int>(),
        svr.at("host").get_ref<const std::string&>(),
        svr.at("port").get<int>(),
        rodsadmin.at("username").get_ref<const std::string&>(),
        svr.at("zone").get_ref<const std::string&>(),
        rodsadmin.at("username").get_ref<const std::string&>(),
        svr.at("zone").get_ref<const std::string&>(),
        svr.at("connection_refresh_timeout_in_seconds").get<int>(),
        [pw = rodsadmin.at("password").get<std::string>()](RcComm& _comm) mutable {
            if (const auto ec = clientLoginWithPassword(&_comm, pw.data()); ec != 0) {
                throw std::invalid_argument{fmt::format("Could not authenticate rodsadmin user: [{}]", ec)};
            }
        }};
} // init_irods_connection_pool

auto main(int _argc, char* _argv[]) -> int
{
    po::options_description opts_desc{""};
    opts_desc.add_options()
        ("config-file,f", po::value<std::string>(), "")
        ("help,h", "")
        ("version,v", "");

    po::positional_options_description pod;
    pod.add("config-file", 1);

    set_ips_display_name("irods_http_api");

    try {
        po::variables_map vm;
        po::store(po::command_line_parser(_argc, _argv).options(opts_desc).positional(pod).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            print_usage();
            return 0;
        }

        if (vm.count("version")) {
            print_version_info();
            return 0;
        }

        if (vm.count("config-file") == 0) {
            fmt::print(stderr, "Error: Missing [CONFIG_FILE_PATH] parameter.");
            return 1;
        }

        const auto config = json::parse(std::ifstream{vm["config-file"].as<std::string>()});
        irods::http::globals::config = &config;

        set_log_level(config);

        // TODO For LONG running tasks, see the following:
        //
        //   - https://stackoverflow.com/questions/17648725/long-running-blocking-operations-in-boost-asio-handlers
        //   - https://www.open-std.org/JTC1/SC22/WG21/docs/papers/2012/n3388.pdf
        //

        log::trace("Loading API plugins.");
        load_client_api_plugins();

        const auto address = net::ip::make_address(config.at("host").get_ref<const std::string&>());
        const auto port = config.at("port").get<std::uint16_t>();
        const auto request_handler_thread_count = std::max(config.at("request_handler_threads").get<int>(), 1);

        log::trace("Initializing iRODS connection pool.");
        auto conn_pool = init_irods_connection_pool(config);
        irods::http::globals::conn_pool = &conn_pool;

        // The io_context is required for all I/O.
        log::trace("Initializing HTTP components.");
        net::io_context ioc{request_handler_thread_count};
        irods::http::globals::req_handler_ioc = &ioc;

        // Create and launch a listening port.
        log::trace("Initializing listenin socket (host=[{}], port=[{}]).", address.to_string(), port);
        std::make_shared<listener>(ioc, tcp::endpoint{address, port})->run();

        // Capture SIGINT and SIGTERM to perform a clean shutdown.
        log::trace("Initializing signal handlers.");
        net::signal_set signals{ioc, SIGINT, SIGTERM};
        signals.async_wait([&ioc](const beast::error_code&, int _signal) {
            // Stop the io_context. This will cause run() to return immediately, eventually destroying the
            // io_context and all of the sockets in it.
            log::warn("Received signal [{}]. Shutting down.", _signal);
            ioc.stop();
        });

        // Launch the requested number of dedicated backgroup I/O threads.
        // These threads are used for long running tasks (e.g. reading/writing bytes, database, etc.)
        log::trace("Initializing thread pool for long running I/O tasks.");
        net::thread_pool io_threads(std::max(config.at("io_threads").get<int>(), 1));
        irods::http::globals::thread_pool_bg = &io_threads;

        // Run the I/O service on the requested number of threads.
        log::trace("Initializing thread pool for HTTP requests.");
        net::thread_pool request_handler_threads(request_handler_thread_count);
        for (auto i = request_handler_thread_count - 1; i > 0; --i) {
            net::post(request_handler_threads, [&ioc] { ioc.run(); });
        }
        log::trace("Server is ready.");
        ioc.run();

        request_handler_threads.stop();
        io_threads.stop();

        log::trace("Waiting for HTTP requests thread pool to shut down.");
        request_handler_threads.join();

        log::trace("Waiting for I/O thread pool to shut down.");
        io_threads.join();

        log::info("Shutdown complete.");

        return 0;
    }
    catch (const std::exception& e) {
        fmt::print(stderr, "Error: {}\n", e.what());
        return 1;
    }
} // main
