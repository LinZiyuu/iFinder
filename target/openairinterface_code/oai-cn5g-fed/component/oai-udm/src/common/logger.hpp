/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <cstdarg>
#include <stdexcept>
#include <vector>

#include "logger_base.hpp"

static const std::string CONFIG         = "config";
static const std::string UDM_UEAU       = "udm_ueau";
static const std::string UDM_UECM       = "udm_uecm";
static const std::string UDM_EE         = "udm_ee";
static const std::string UDM_SDM        = "udm_sdm";
static const std::string UDM_NRF        = "udm_nrf";
static const std::string UDM_CLIENT     = "udm_client";
static const std::string UDM_API_SERVER = "udm_server";
static const std::string UDM_APP        = "udm_app";

class Logger : public oai::logger::logger_common {
 public:
  static void init(
      const std::string& name, const bool log_stdout, const bool log_rot_file) {
    oai::logger::logger_common(name, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, CONFIG, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDM_UEAU, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDM_UECM, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDM_EE, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDM_SDM, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDM_NRF, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDM_API_SERVER, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDM_CLIENT, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, UDM_APP, log_stdout, log_rot_file);
  }
  static void set_level(spdlog::level::level_enum level) {
    oai::logger::logger_registry::set_level(level);
  }

  static void set_lttng(bool isLttngActive) {
    oai::logger::logger_registry::set_lttng_is_active(isLttngActive);
  }

  static bool should_log(spdlog::level::level_enum level) {
    return oai::logger::logger_registry::should_log(level);
  }

  static const oai::logger::printf_logger& config() {
    return oai::logger::logger_registry::get_logger(CONFIG);
  }
  static const oai::logger::printf_logger& udm_ueau() {
    return oai::logger::logger_registry::get_logger(UDM_UEAU);
  }
  static const oai::logger::printf_logger& udm_uecm() {
    return oai::logger::logger_registry::get_logger(UDM_UECM);
  }
  static const oai::logger::printf_logger& udm_ee() {
    return oai::logger::logger_registry::get_logger(UDM_EE);
  }
  static const oai::logger::printf_logger& udm_sdm() {
    return oai::logger::logger_registry::get_logger(UDM_SDM);
  }
  static const oai::logger::printf_logger& udm_nrf() {
    return oai::logger::logger_registry::get_logger(UDM_NRF);
  }
  static const oai::logger::printf_logger& udm_server() {
    return oai::logger::logger_registry::get_logger(UDM_API_SERVER);
  }
  static const oai::logger::printf_logger& udm_client() {
    return oai::logger::logger_registry::get_logger(UDM_CLIENT);
  }
  static const oai::logger::printf_logger& udm_app() {
    return oai::logger::logger_registry::get_logger(UDM_APP);
  }
};
