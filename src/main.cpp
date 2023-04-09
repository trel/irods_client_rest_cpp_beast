//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP server, asynchronous
//
//------------------------------------------------------------------------------

#include <curl/curl.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <boost/algorithm/string.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <string>
#include <string_view>
#include <utility>
#include <unordered_map>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

using request_handler = std::function<void(const http::request<http::string_body>&)>;

auto handle_auth(const http::request<http::string_body>& _req) -> void
{
    // TODO Authentication needs to be implemented as a pluggable interface.
    // Out of the box, the REST API will support Basic authentication. Later,
    // we add OIDC (and more, perhaps).

    // OIDC authentication for this REST API may require a mapping between a
    // value in the returned ID/access token and a user in iRODS. For example:
    //
    //   {
    //       // The claim to use.
    //       // This may require use of multiple claims.
    //       "claim": "email",
    //
    //       // The user mapping.
    //       "users": {
    //           "alice@ymail.com": {
    //               "username": "alice",
    //               "zone": "tempZone"
    //           }
    //           "bob@ymail.com": {
    //               "username": "bob#otherZone",
    //               "zone": "tempZone"
    //           }
    //       }
    //   }
    //
    // This assumes the OIDC Provider (OP) always defines an email claim. 

    if (_req.method() != http::verb::post) {
        fmt::print("{}: Incorrect HTTP method for authentication.\n", __func__);
        return;
    }

    const auto& hdrs = _req.base();
    const auto iter = hdrs.find("authorization");
    if (iter == std::end(hdrs)) {
        fmt::print("{}: Missing authorization header.\n", __func__);
        return;
    }

    fmt::print("{}: Authorization value: [{}]\n", __func__, iter->value());

    // TODO Parse the header value and determine if the user is allowed to access.
    // 
    // Q. For Basic authorization, is it better to store an iRODS connection in memory
    // for the duration of the user's session? Or, is it better to connect and then
    // disconnect for each request?
    // 
    // A. My first thought is it is probably better to connect/disconnect so that the
    // remote server's connections aren't exhausted (i.e. consider what else may be
    // happening on the remote server). However, using a connection pool along with
    // rc_switch_user is likely the correct answer. That and exposing server options
    // which allow an administrator to tune the number of connections and threads. By
    // exposing server options, we let the system administrator make the decision,
    // which is a good thing.
}

// This will eventually become a mapping of strings to functions.
// The incoming requests will be passed to the functions for further processing.
const std::unordered_map<std::string_view, request_handler> req_handlers{
    {"/irods-rest/0.9.4/auth",         handle_auth},
    //{"/irods-rest/0.9.4/collections",  "/collections"},
    //{"/irods-rest/0.9.4/config",       "/config"},
    //{"/irods-rest/0.9.4/data-objects", "/data-objects"},
    //{"/irods-rest/0.9.4/metadata",     "/metadata"},
    //{"/irods-rest/0.9.4/query",        "/query"},
    //{"/irods-rest/0.9.4/resources",    "/resources"},
    //{"/irods-rest/0.9.4/rules",        "/rules"},
    //{"/irods-rest/0.9.4/tickets",      "/tickets"},
    //{"/irods-rest/0.9.4/users",        "/users"},
    //{"/irods-rest/0.9.4/zones",        "/zones"}
};

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template <class Body, class Allocator, class Send>
void handle_request(
    http::request<Body, http::basic_fields<Allocator>>&& req,
    Send&& send)
{
    // Print the headers.
    for (auto&& h : req.base()) {
        fmt::print(fmt::runtime("header: ({}, {})\n"), h.name_string(), h.value());
    }

    // Print the components of the request URL.
    fmt::print("method            : {}\n", req.method_string());
    fmt::print("version           : {}\n", req.version());
    // TODO Use libcurl - curl_easy_unescape to decode URL (at least until Boost.URL is available).
    // See https://curl.se/libcurl/c/curl_easy_unescape.html.
    fmt::print("target            : {}\n", req.target());
    fmt::print("keep alive        : {}\n", req.keep_alive());
    fmt::print("has content length: {}\n", req.has_content_length());
    fmt::print("chunked           : {}\n", req.chunked());
    fmt::print("needs eof         : {}\n", req.need_eof());

    // Show how to decode URLs using libcurl.
    if (auto* curl = curl_easy_init(); curl) {
        int decoded_length = -1;
        if (auto* decoded = curl_easy_unescape(nullptr, "%63%75%72%6c", 12, &decoded_length); decoded) {
            fmt::print("decoded = [{}]\n", decoded);
            curl_free(decoded);
        }
        curl_easy_cleanup(curl);
    }

    // TODO Show how to parse URLs using libcurl.
    // See https://curl.se/libcurl/c/parseurl.html for an example.
    if (auto* curl = curl_url(); curl) {
        // Include a bogus prefix. We only care about the path and query parts of the URL.
        if (const auto ec = curl_url_set(curl, CURLUPART_URL, ("http://ignored" + std::string{req.target()}).c_str(), 0); ec) {
            fmt::print("error: {}\n", ec);
        }

        // Extract the path.
        // This is what we use to route requests to the various endpoints.
        char* path{};
        if (const auto ec = curl_url_get(curl, CURLUPART_PATH, &path, 0); ec == 0) {
            if (path) {
                fmt::print("path: [{}]\n", path);

                if (const auto iter = req_handlers.find(path); iter != std::end(req_handlers)) {
                    (iter->second)(req);
                }
                else {
                    fmt::print("path [{}] not supported.\n", path);
                }

                curl_free(path);
            }
        }
        else {
            fmt::print("error: {}\n", ec);
        }

        // Extract the query.
        // ChatGPT states that the values in the key value pairs must escape embedded equal signs.
        // This allows the HTTP server to parse the query string correctly. Therefore, we don't have
        // to protect against that case. The client must send the correct URL escaped input.
        char* query{};
        if (const auto ec = curl_url_get(curl, CURLUPART_QUERY, &query, CURLU_URLDECODE); ec == 0) {
            if (query) {
                fmt::print("query: [{}]\n", query);

                // I really wish Boost.URL was part of Boost 1.78. Things would be so much easier.
                // Sadly, we have to release an updated Boost external to get it.
                try {
                    std::vector<std::string> tokens;
                    boost::split(tokens, query, boost::is_any_of("&"));

                    for (auto&& t : tokens) {
                        fmt::print(fmt::runtime("key value pair string: [{}]\n"), t);
                    }

                    std::vector<std::pair<std::string, std::string>> kvps;
                    std::vector<std::string> kvp;
                    std::for_each(std::begin(tokens), std::end(tokens), [&kvps, &kvp](auto&& _t) {
                        boost::split(kvp, _t, boost::is_any_of("="));
                        if (kvp.size() == 2) {
                            kvps.emplace_back(std::move(kvp[0]), std::move(kvp[1]));
                        }
                        else if (kvp.size() == 1) {
                            kvps.emplace_back(std::move(kvp[0]), "");
                        }
                        kvp.clear();
                    });

                    for (auto&& [k, v] : kvps) {
                        fmt::print(fmt::runtime("key value pair: {{[{}], [{}]}}\n"), k, v);
                    }
                }
                catch (const std::exception& e) {
                    fmt::print("exception: {}\n", e.what());
                }

                curl_free(query);
            }
        }
        else {
            fmt::print("error: {}\n", ec);
        }
    }

    // Respond to request.
    http::response<http::empty_body> res{http::status::ok, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(req.keep_alive());
    return send(std::move(res));
}

//------------------------------------------------------------------------------

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

// Handles an HTTP server connection
class session : public std::enable_shared_from_this<session>
{
    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        session& self_;

        explicit
        send_lambda(session& self)
            : self_(self)
        {
        }

        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg) const
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
    };

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;

public:
    // Take ownership of the stream
    session(tcp::socket&& socket)
        : stream_(std::move(socket))
        , lambda_(*this)
    {
    }

    // Start the asynchronous operation
    void
    run()
    {
        // We need to be executing within a strand to perform async operations
        // on the I/O objects in this session. Although not strictly necessary
        // for single-threaded contexts, this example code is written to be
        // thread-safe by default.
        net::dispatch(stream_.get_executor(),
                      beast::bind_front_handler(
                          &session::do_read,
                          shared_from_this()));
    }

    void
    do_read()
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
    }

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return do_close();

        if(ec)
            return fail(ec, "read");

        // Send the response
        handle_request(std::move(req_), lambda_);
    }

    void
    on_write(
        bool close,
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return do_close();
        }

        // We're done with the response so delete it
        res_ = nullptr;

        // Read another request
        do_read();
    }

    void
    do_close()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
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
        if(ec)
        {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec)
        {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if(ec)
        {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(
            net::socket_base::max_listen_connections, ec);
        if(ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void
    run()
    {
        do_accept();
    }

private:
    void
    do_accept()
    {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(
                &listener::on_accept,
                shared_from_this()));
    }

    void
    on_accept(beast::error_code ec, tcp::socket socket)
    {
        if (ec) {
            fail(ec, "accept");
            return; // To avoid infinite loop
        }

        // Create the session and run it
        std::make_shared<session>(std::move(socket))->run();

        // Accept another connection
        do_accept();
    }
};

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    // Check command line arguments.
    if (argc != 4) {
        std::cerr <<
            "Usage: http-server-async <address> <port> <threads>\n" <<
            "Example:\n" <<
            "    http-server-async 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const threads = std::max<int>(1, std::atoi(argv[3]));

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // Create and launch a listening port
    std::make_shared<listener>(ioc, tcp::endpoint{address, port})->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });
    ioc.run();

    return EXIT_SUCCESS;
}
