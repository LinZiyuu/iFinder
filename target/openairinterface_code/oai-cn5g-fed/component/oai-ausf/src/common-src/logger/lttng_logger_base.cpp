/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "lttng_logger_base.hpp"

using namespace oai::logger;

lttng_logger::lttng_logger(
    const std::string& nf_name, const std::string& category, bool log_stdout,
    bool log_rot_file)
    : m_provider(nf_name), m_event(category) {}

void lttng_logger::set_level(const spdlog::level::level_enum& level) {
  m_level = level;
}

bool lttng_logger::should_log(const spdlog::level::level_enum& level) const {
  return (static_cast<int>(m_level) <= static_cast<int>(level));
}

void lttng_logger::lttng_trace_log(
    const spdlog::level::level_enum& lvl, const char* cstr_msg) const {
#ifdef LOGGER_CAN_USE_LTTNG
  // NF_TRACE_EVENT(m_provider.c_str(), m_event.c_str(), cstr_msg);
  switch (lvl) {
    case spdlog::level::level_enum::trace:
      tracelog(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG, cstr_msg);
      break;
    case spdlog::level::level_enum::debug:
      tracelog(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG, cstr_msg);
      break;
    case spdlog::level::level_enum::info:
      tracelog(LTTNG_UST_TRACEPOINT_LOGLEVEL_INFO, cstr_msg);
      break;
    case spdlog::level::level_enum::warn:
      tracelog(LTTNG_UST_TRACEPOINT_LOGLEVEL_WARNING, cstr_msg);
      break;
    case spdlog::level::level_enum::err:
      tracelog(LTTNG_UST_TRACEPOINT_LOGLEVEL_ERR, cstr_msg);
      break;
    case spdlog::level::level_enum::critical:
      tracelog(LTTNG_UST_TRACEPOINT_LOGLEVEL_CRIT, cstr_msg);
      break;
  }
#endif
}
