/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <cstdarg>

#include "logger_base.hpp"

static const std::string CONFIG       = "config";
static const std::string AUSF_APP     = "ausf_app";
static const std::string AUSF_NRF     = "ausf_nrf";
static const std::string AUSF_CLIENT  = "ausf_client";
static const std::string AUSF_SVR_LOG = "ausf_server";

class Logger : public oai::logger::logger_common {
 public:
  static void init(
      const std::string& name, const bool log_stdout, const bool log_rot_file) {
    oai::logger::logger_common(name, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, CONFIG, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, SYSTEM, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, AUSF_APP, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, AUSF_NRF, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, AUSF_CLIENT, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, AUSF_SVR_LOG, log_stdout, log_rot_file);
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
  static const oai::logger::printf_logger& system() {
    return oai::logger::logger_registry::get_logger(SYSTEM);
  }
  static const oai::logger::printf_logger& ausf_app() {
    return oai::logger::logger_registry::get_logger(AUSF_APP);
  }
  static const oai::logger::printf_logger& ausf_nrf() {
    return oai::logger::logger_registry::get_logger(AUSF_NRF);
  }
  static const oai::logger::printf_logger& ausf_client() {
    return oai::logger::logger_registry::get_logger(AUSF_CLIENT);
  }
  static const oai::logger::printf_logger& ausf_server() {
    return oai::logger::logger_registry::get_logger(AUSF_SVR_LOG);
  }
};
