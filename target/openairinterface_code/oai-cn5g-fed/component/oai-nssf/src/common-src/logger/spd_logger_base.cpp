/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "spd_logger_base.hpp"
#include <fmt/printf.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <string>

using namespace oai::logger;

spd_logger::spd_logger(
    const std::string& nf_name, const std::string& category, bool log_stdout,
    bool log_rot_file) {
  // static to use the same sinks for all loggers
  static std::vector<spdlog::sink_ptr> sinks;

  if (sinks.empty()) {
    if (log_stdout) {
      auto color_sink =
          std::make_shared<spdlog::sinks::ansicolor_stdout_sink_mt>();
      // because we redefine the names, we also redefine the colors
      color_sink->set_color(spdlog::level::warn, color_sink->magenta);
      color_sink->set_color(spdlog::level::err, color_sink->yellow_bold);
      color_sink->set_color(spdlog::level::critical, color_sink->red_bold);

      sinks.push_back(color_sink);
    }
    if (log_rot_file) {
      // TODO would be nice to configure logfile path, and max size maybe?
      std::string filename = nf_name + ".log";
      // 5MB rotating file limit with max 3 files
      sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
          filename, 5 * 1024 * 1024, 3));
    }
  }

  std::stringstream log_format{};
  log_format << "[%Y-%m-%dT%H:%M:%S.%f] [" << nf_name << "] [%n] [%l] %v";

  logger = std::make_shared<spdlog::logger>(
      category, std::begin(sinks), std::end(sinks));

  // Out of the box the level is debug
  logger->set_level(spdlog::level::debug);
}

void spd_logger::set_level(spdlog::level::level_enum level) {
  logger->set_level(level);
}