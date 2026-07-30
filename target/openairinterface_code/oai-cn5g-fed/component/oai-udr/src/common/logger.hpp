/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <cstdarg>
#include <stdexcept>
#include <vector>
#include "logger_base.hpp"

static const std::string CONFIG      = "config";
static const std::string UDR_APP     = "udr_app";
static const std::string UDR_SVR_LOG = "udr_server";
static const std::string UDR_NRF     = "udr_nrf";
static const std::string UDR_DB      = "udr_db";

class Logger : public oai::logger::logger_common {
 public:
  static void init(
      const std::string& name, const bool log_stdout, const bool log_rot_file) {
    oai::logger::logger_registry::register_logger(
        name, LOGGER_COMMON, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, CONFIG, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDR_APP, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDR_SVR_LOG, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDR_NRF, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDR_DB, log_stdout, log_rot_file);
  }
  static void set_level(spdlog::level::level_enum level) {
    oai::logger::logger_registry::set_level(level);
  }
  static bool should_log(spdlog::level::level_enum level) {
    return oai::logger::logger_registry::should_log(level);
  }

  static void set_lttng(bool isLttngActive) {
    oai::logger::logger_registry::set_lttng_is_active(isLttngActive);
  }

  static const oai::logger::printf_logger& config() {
    return oai::logger::logger_registry::get_logger(CONFIG);
  }
  static const oai::logger::printf_logger& udr_app() {
    return oai::logger::logger_registry::get_logger(UDR_APP);
  }
  static const oai::logger::printf_logger& udr_server() {
    return oai::logger::logger_registry::get_logger(UDR_SVR_LOG);
  }
  static const oai::logger::printf_logger& udr_nrf() {
    return oai::logger::logger_registry::get_logger(UDR_NRF);
  }
  static const oai::logger::printf_logger& udr_db() {
    return oai::logger::logger_registry::get_logger(UDR_DB);
  }
};
