/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "logger_base.hpp"

static const std::string Lmf_Config = "config";
static const std::string Lmf_App    = "lmf_app";
static const std::string Lmf_Nrf    = "lmf_nrf";
static const std::string Lmf_Client = "lmf_client";
static const std::string Lmf_Server = "lmf_server";
static const std::string Lmf_System = "system";

class Logger : public oai::logger::logger_common {
 public:
  static void init(
      const std::string& name, bool log_stdout, bool log_rot_file) {
    oai::logger::logger_common(name, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Lmf_Config, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Lmf_App, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Lmf_Nrf, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Lmf_Server, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Lmf_Client, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Lmf_System, log_stdout, log_rot_file);
  }

  static void set_level(spdlog::level::level_enum level) {
    oai::logger::logger_registry::set_level(level);
  }
  static bool should_log(spdlog::level::level_enum level) {
    return oai::logger::logger_registry::should_log(level);
  }

  static const oai::logger::printf_logger& config() {
    return oai::logger::logger_registry::get_logger(Lmf_Config);
  }

  static const oai::logger::printf_logger& lmf_app() {
    return oai::logger::logger_registry::get_logger(Lmf_App);
  }

  static const oai::logger::printf_logger& lmf_nrf() {
    return oai::logger::logger_registry::get_logger(Lmf_Nrf);
  }

  static const oai::logger::printf_logger& lmf_server() {
    return oai::logger::logger_registry::get_logger(Lmf_Server);
  }

  static const oai::logger::printf_logger& lmf_client() {
    return oai::logger::logger_registry::get_logger(Lmf_Client);
  }

  static const oai::logger::printf_logger& system() {
    return oai::logger::logger_registry::get_logger(Lmf_System);
  }
};
