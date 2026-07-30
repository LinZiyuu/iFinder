/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "spd_logger_base.hpp"
#include "lttng_logger_base.hpp"
#include <cstdarg>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

static const std::string ASYNC_CMD           = "asc_cmd";
static const std::string LOGGER_COMMON       = "common";
static const std::string LOGGER_COMMON_NAS   = "nas";
static const std::string LOGGER_COMMON_NGAP  = "ngap";
static const std::string LOGGER_COMMON_PFCP  = "pfcp   ";
static const std::string SYSTEM              = "system ";
static const std::string LOGGER_COMMON_UTILS = "utils";

namespace oai::logger {

class printf_logger {
 private:
  bool m_is_lttng_active{false};
  std::shared_ptr<spd_logger> m_spd_logger{nullptr};
  std::shared_ptr<lttng_logger> m_lttng_logger{nullptr};

 public:
  explicit printf_logger(
      const std::string& nf_name, const std::string& category, bool log_stdout,
      bool log_rot_file, bool isLTTngActive = false)
      : m_is_lttng_active(isLTTngActive) {
    if (m_is_lttng_active) {
      m_lttng_logger = std::make_shared<lttng_logger>(
          nf_name, category, log_stdout, log_rot_file);
    } else {
      m_spd_logger = std::make_shared<spd_logger>(
          nf_name, category, log_stdout, log_rot_file);
    }
  }

  bool should_log(spdlog::level::level_enum level) {
    if (m_is_lttng_active) {
      return m_lttng_logger->should_log(level);
    } else {
      return m_spd_logger->should_log(level);
    }
  }

  void set_level(spdlog::level::level_enum level) {
    if (m_is_lttng_active) {
      m_lttng_logger->set_level(level);
    } else {
      m_spd_logger->set_level(level);
    }
  }

  template<typename... T>
  void trace(const std::string& fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::trace, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::trace, fmt, args...);
  }

  template<typename... T>
  void trace(const char* fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::trace, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::trace, fmt, args...);
  }

  template<typename... T>
  void debug(const std::string& fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::debug, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::debug, fmt, args...);
  }

  template<typename... T>
  void debug(const char* fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::debug, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::debug, fmt, args...);
  }

  template<typename... T>
  void info(const std::string& fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::info, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::info, fmt, args...);
  }

  template<typename... T>
  void info(const char* fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::info, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::info, fmt, args...);
  }

  template<typename... T>
  void startup(const std::string& fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::warn, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::warn, fmt, args...);
  }

  template<typename... T>
  void startup(const char* fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::warn, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::warn, fmt, args...);
  }

  template<typename... T>
  void warn(const std::string& fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::err, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::err, fmt, args...);
  }

  template<typename... T>
  void warn(const char* fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::err, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::err, fmt, args...);
  }

  template<typename... T>
  void error(const std::string& fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::critical, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::critical, fmt, args...);
  }

  template<typename... T>
  void error(const char* fmt, const T&... args) const {
    if (m_is_lttng_active)
      m_lttng_logger->log_printf(spdlog::level::critical, fmt, args...);
    else
      m_spd_logger->log_printf(spdlog::level::critical, fmt, args...);
  }
};

class logger_registry {
 public:
  static void register_logger(
      const std::string& nf_name, const std::string& logger_name,
      bool log_stdout, bool log_rot_file);

  static const printf_logger& get_logger(const std::string& logger);
  static void set_level(spdlog::level::level_enum level);
  static void set_lttng_is_active(bool isActive) {
#ifdef LOGGER_CAN_USE_LTTNG
    m_is_lttng_active = isActive;
#endif
  }
  static bool should_log(spdlog::level::level_enum level) {
    if (logger_map.empty()) {
      return false;
    }
    const auto& it = logger_map.begin();
    return it->second.should_log(level);
  }

 private:
  static std::unordered_map<std::string, printf_logger> logger_map;
  static bool m_is_lttng_active;
};

class logger_common {
 public:
  logger_common(
      const std::string& name, const bool log_stdout, const bool log_rot_file) {
    oai::logger::logger_registry::register_logger(
        name, ASYNC_CMD, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, LOGGER_COMMON, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, LOGGER_COMMON_NAS, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, LOGGER_COMMON_NGAP, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, LOGGER_COMMON_PFCP, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, SYSTEM, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, LOGGER_COMMON_UTILS, log_stdout, log_rot_file);
  }
  static bool should_log(spdlog::level::level_enum level) {
    return oai::logger::logger_registry::should_log(level);
  }

  static const oai::logger::printf_logger& async_cmd() {
    return oai::logger::logger_registry::get_logger(ASYNC_CMD);
  }
  static const oai::logger::printf_logger& common() {
    return oai::logger::logger_registry::get_logger(LOGGER_COMMON);
  }
  static const oai::logger::printf_logger& nas() {
    return oai::logger::logger_registry::get_logger(LOGGER_COMMON_NAS);
  }
  static const oai::logger::printf_logger& ngap() {
    return oai::logger::logger_registry::get_logger(LOGGER_COMMON_NGAP);
  }
  static const oai::logger::printf_logger& pfcp() {
    return oai::logger::logger_registry::get_logger(LOGGER_COMMON_PFCP);
  }
  static const oai::logger::printf_logger& system() {
    return oai::logger::logger_registry::get_logger(SYSTEM);
  }
  static const oai::logger::printf_logger& utils() {
    return oai::logger::logger_registry::get_logger(LOGGER_COMMON_UTILS);
  }
};

}  // namespace oai::logger
