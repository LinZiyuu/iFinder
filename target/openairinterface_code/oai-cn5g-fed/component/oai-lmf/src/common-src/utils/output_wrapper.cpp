/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "output_wrapper.hpp"

#include "logger.hpp"

//------------------------------------------------------------------------------
void oai::utils::output_wrapper::print_buffer(
    const std::string app, const std::string sink, const uint8_t* buf,
    int len) {
  std::string str = "[" + app + "]" + sink;
  oai::logger::logger_registry::get_logger(LOGGER_COMMON).debug(str.c_str());
  if (Logger::should_log(spdlog::level::debug)) {
    for (int i = 0; i < len; i++) printf("%02x ", buf[i]);
    printf("\n");
  }
}
