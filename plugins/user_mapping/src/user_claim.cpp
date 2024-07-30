#include "irods/http_api/plugins/user_mapping/interface.h"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace
{
	// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
	std::string claim_to_match;

	auto init(const nlohmann::json& _config) -> void
	{
		const auto claim{_config.find("irods_user_claim")};
		if (claim == std::end(_config)) {
			throw std::logic_error{"Unable to find [irods_user_claim] in provided config."};
		}

		claim_to_match = claim->get<std::string>();
	} // init

	auto match(const nlohmann::json& _params) -> std::optional<std::string>
	{
		if (auto claim{_params.find(claim_to_match)}; claim != std::end(_params)) {
			return claim->get<std::string>();
		}

		return std::nullopt;
	} // match
} // anonymous namespace

auto user_mapper_init(const char* _args) -> int
{
	// Check if any of the args are nullptr
	if (nullptr == _args) {
		return 1;
	}

	try {
		spdlog::debug("{}: Received _args [{}].", __func__, _args);
		init(nlohmann::json::parse(_args));
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		return 1;
	}
	return 0;
} // user_mapper_init

auto user_mapper_match(const char* _param, char** _match) -> int
{
	// Check if any of the args are nullptr
	if (nullptr == _param || nullptr == _match) {
		return 1;
	}

	spdlog::debug("{}: Attempting match of _param [{}].", __func__, _param);
	try {
		auto res{match(nlohmann::json::parse(_param))};

		if (res) {
			spdlog::debug("{}: Matched _param [{}] to user [{}].", __func__, _param, *res);
			char* matched_username{strdup(res->c_str())};

			*_match = matched_username;
			return 0;
		}

		*_match = nullptr;
		return 0;
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		*_match = nullptr;
		return 1;
	}
} // user_mapper_match

auto user_mapper_close() -> int
{
	return 0;
} // user_mapper_close

auto user_mapper_free(char* _data) -> void
{
	// NOLINTNEXTLINE(cppcoreguidelines-no-malloc, cppcoreguidelines-owning-memory)
	std::free(_data);
} // user_mapper_free
