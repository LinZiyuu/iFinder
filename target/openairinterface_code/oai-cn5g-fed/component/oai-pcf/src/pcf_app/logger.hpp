/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "logger_base.hpp"

static const std::string PCF_APP    = "pcf_app";
static const std::string PCF_SBI    = "pcf_sbi";
static const std::string PCF_CLIENT = "pcf_client";
static const std::string PCF_DB     = "pcf_db";

class Logger {
 public:
  static void init(
      const std::string& name, bool log_stdout, bool log_rot_file) {
    oai::logger::logger_registry::register_logger(
        name, PCF_APP, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, PCF_SBI, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, PCF_CLIENT, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, LOGGER_COMMON, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, PCF_DB, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, SYSTEM, log_stdout, log_rot_file);
  }

  static bool should_log(spdlog::level::level_enum level) {
    return oai::logger::logger_registry::should_log(level);
  }

  static void set_level(spdlog::level::level_enum level) {
    oai::logger::logger_registry::set_level(level);
  }

  static void set_lttng(bool isLttngActive) {
    oai::logger::logger_registry::set_lttng_is_active(isLttngActive);
  }

  static const oai::logger::printf_logger& pcf_app() {
    return oai::logger::logger_registry::get_logger(PCF_APP);
  }

  static const oai::logger::printf_logger& pcf_sbi() {
    return oai::logger::logger_registry::get_logger(PCF_SBI);
  }

  static const oai::logger::printf_logger& pcf_client() {
    return oai::logger::logger_registry::get_logger(PCF_CLIENT);
  }

  static const oai::logger::printf_logger& pcf_db() {
    return oai::logger::logger_registry::get_logger(PCF_DB);
  }

  static const oai::logger::printf_logger& system() {
    return oai::logger::logger_registry::get_logger(SYSTEM);
  }
};
