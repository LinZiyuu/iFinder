/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#pragma once

#include <cstdarg>
#include <memory>
#include <stdexcept>
#include <vector>

#ifndef SPDLOG_FMT_EXTERNAL
#define SPDLOG_FMT_EXTERNAL 1
#endif

#include <fmt/printf.h>
#include <spdlog/common.h>
#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

#include "nf-tp.hpp"

namespace oai::logger {

class lttng_logger {
 public:
  lttng_logger(
      const std::string& nf_name, const std::string& category, bool log_stdout,
      bool log_rot_file);
  void set_level(const spdlog::level::level_enum& level);
  bool should_log(const spdlog::level::level_enum& level) const;
  void lttng_trace_log(
      const spdlog::level::level_enum& lvl, const char* cstr_msg) const;

  template<typename... T>
  void log_printf(
      const spdlog::level::level_enum& lvl, const std::string& fmt,
      const T&... args) const {
    if (!should_log(lvl)) {
      return;
    }
    try {
      std::string formatted_message = fmt::sprintf(fmt, args...);
      const char* cstr_message      = formatted_message.c_str();

      lttng_trace_log(lvl, cstr_message);
    } catch (fmt::format_error& err) {
      std::string formatted_message =
          fmt::sprintf("Format error in format string {}: {}", fmt, err.what());
      const char* cstr_message = formatted_message.c_str();
      lttng_trace_log(spdlog::level::level_enum::critical, cstr_message);
    }
  }

 private:
  spdlog::level::level_enum m_level;
  std::string m_provider{};
  std::string m_event{};
};

}  // namespace oai::logger
