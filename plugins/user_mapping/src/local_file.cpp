#include "irods/http_api/plugins/user_mapping/interface.h"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace
{
	struct user_profile
	{
		std::string irods_user_name;
		nlohmann::json attributes;
	};

	// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
	std::filesystem::path file_path; // Path to the file containing mappings.

	// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
	std::vector<user_profile> profile_list; // Represents the mappings of irods users to attributes.

	// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, cert-err58-cpp)
	std::shared_mutex list_mutex; // Ensures a write cannot happen while reads happen to profile_list and vice versa.

	// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
	std::mutex update_mutex; // Allows for only one thread to run 'update()' at a time.

	auto update() -> void;

	auto init(const nlohmann::json& _config) -> void
	{
		const auto path{_config.find("file_path")};
		if (path == std::end(_config)) {
			throw std::logic_error{"Unable to find [file_path] in configuration."};
		}

		// Save file string
		file_path = path->get<std::string>();

		// If something is invalid with the file, fail fast via update
		update();
	} // init

	auto update() -> void
	{
		static std::filesystem::file_time_type last_file_path_write;

		// If there have been no changes to file_path, there is no work to do
		if (std::filesystem::last_write_time(file_path) == last_file_path_write) {
			spdlog::trace("{}: Mapping file has not been modified, skipping update.", __func__);
			return;
		}

		spdlog::trace("{}: Mapping file modified, updating internal state.", __func__);

		std::ifstream file{file_path};
		if (!file) {
			throw std::runtime_error{"Failed to open [file_path]."};
		}

		auto json_data{nlohmann::json::parse(file)};

		// Create temp list to be swapped in later
		std::vector<user_profile> temp_list;
		temp_list.reserve(json_data.size());

		// Process into list:
		auto base_iter{json_data.items()};
		std::transform(
			std::begin(base_iter),
			std::end(base_iter),
			std::back_inserter(temp_list),
			[](const auto& _iter) -> user_profile {
				return {.irods_user_name = _iter.key(), .attributes = _iter.value()};
			});

		// Move new item list to old one, update last write time
		std::unique_lock update_profile_list_lock{list_mutex};
		profile_list = std::move(temp_list);
		last_file_path_write = std::filesystem::last_write_time(file_path);
	} // update

	auto match(const nlohmann::json& _params) -> std::optional<std::string>
	{
		// If there is an exception while updating, catch so we can still
		// provide matches with our current good state.
		try {
			// Only allow one thread to run update at a time
			if (std::unique_lock call_update_lock{update_mutex, std::try_to_lock}; call_update_lock) {
				update();
			}
		}
		catch (const std::exception& e) {
			spdlog::error("{}: {}", __func__, e.what());
		}

		std::shared_lock read_profile_list_lock{list_mutex};

		// Use provided mappings to see if there is a complete match to a user
		for (const auto& [irods_username, attributes] : profile_list) {
			auto attr_iter{attributes.items()};

			// Verify that each attribute specified is found in _params
			auto res{std::all_of(std::begin(attr_iter), std::end(attr_iter), [&_params](const auto& _iter) -> bool {
				const auto value_of_interest{_params.find(_iter.key())};
				if (value_of_interest == std::end(_params)) {
					return false;
				}

				return *value_of_interest == _iter.value();
			})};

			// If all specified attributes matched, _params maps to irods_username
			if (res) {
				return irods_username;
			}
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
