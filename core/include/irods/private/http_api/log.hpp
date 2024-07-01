#ifndef IRODS_HTTP_API_LOG_HPP
#define IRODS_HTTP_API_LOG_HPP

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <string_view>
#include <utility>

namespace irods::http::log
{
	template <typename... Args>
	constexpr auto trace(fmt::format_string<Args...> _format, Args&&... _args) -> void
	{
		spdlog::trace(_format, std::forward<Args>(_args)...);
	} // trace

	template <typename... Args>
	constexpr auto info(fmt::format_string<Args...> _format, Args&&... _args) -> void
	{
		spdlog::info(_format, std::forward<Args>(_args)...);
	} // info

	template <typename... Args>
	constexpr auto debug(fmt::format_string<Args...> _format, Args&&... _args) -> void
	{
		spdlog::debug(_format, std::forward<Args>(_args)...);
	} // debug

	template <typename... Args>
	constexpr auto warn(fmt::format_string<Args...> _format, Args&&... _args) -> void
	{
		spdlog::warn(_format, std::forward<Args>(_args)...);
	} // warn

	template <typename... Args>
	constexpr auto error(fmt::format_string<Args...> _format, Args&&... _args) -> void
	{
		spdlog::error(_format, std::forward<Args>(_args)...);
	} // error

	template <typename... Args>
	constexpr auto critical(fmt::format_string<Args...> _format, Args&&... _args) -> void
	{
		spdlog::critical(_format, std::forward<Args>(_args)...);
	} // critical
} //namespace irods::http::log

#endif // IRODS_HTTP_API_LOG_HPP
