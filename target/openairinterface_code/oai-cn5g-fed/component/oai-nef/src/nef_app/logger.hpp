/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "logger_base.hpp"

static const std::string Nef_App    = "nef_app";
static const std::string Nef_Sbi    = "nef_sbi";
static const std::string Nef_System = "system ";

class Logger {
 public:
  static void init(
      const std::string& name, bool log_stdout, bool log_rot_file) {
    oai::logger::logger_registry::register_logger(
        name, Nef_App, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Nef_Sbi, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Nef_System, log_stdout, log_rot_file);
  }

  static const oai::logger::printf_logger& nef_app() {
    return oai::logger::logger_registry::get_logger(Nef_App);
  }

  static const oai::logger::printf_logger& nef_sbi() {
    return oai::logger::logger_registry::get_logger(Nef_Sbi);
  }

  static const oai::logger::printf_logger& system() {
    return oai::logger::logger_registry::get_logger(Nef_System);
  }
};
