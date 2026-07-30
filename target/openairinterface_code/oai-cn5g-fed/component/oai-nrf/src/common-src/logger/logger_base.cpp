/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "logger_base.hpp"
#include <spdlog/sinks/rotating_file_sink.h>
#include <fmt/printf.h>

#include <iostream>
#include <sstream>
#include <string>
#include <memory>

using namespace oai::logger;

std::unordered_map<std::string, printf_logger> logger_registry::logger_map;
bool logger_registry::m_is_lttng_active{false};

void logger_registry::register_logger(
    const std::string& nf_name, const std::string& logger_name, bool log_stdout,
    bool log_rot_file) {
  // use the static mutex to lock this function
  // thread-safe since C++11
  static auto mutex = std::mutex();

  auto lock = std::unique_lock(mutex);

  auto logger = printf_logger(
      nf_name, logger_name, log_stdout, log_rot_file, m_is_lttng_active);

  logger_map.insert(std::make_pair<>(logger_name, logger));
}

const printf_logger& logger_registry::get_logger(const std::string& logger) {
  // const STL functions can be accessed by multiple threads simultaneously
  // no lock required
  const auto& it  = logger_map.find(logger);
  const auto& end = logger_map.end();

  if (it == end) {
    const auto& it_common = logger_map.find(LOGGER_COMMON);
    if (it_common == end)
      throw std::runtime_error(fmt::format("Logger {} does not exist", logger));
    return it_common->second;
  }
  return it->second;
}

void logger_registry::set_level(spdlog::level::level_enum level) {
  for (auto element : logger_map) {
    element.second.set_level(level);
  }
}
