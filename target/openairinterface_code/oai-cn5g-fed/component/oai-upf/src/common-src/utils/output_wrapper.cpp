/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "output_wrapper.hpp"

#include "logger_base.hpp"

//------------------------------------------------------------------------------
void oai::utils::output_wrapper::print_buffer(
    const std::string app, const std::string sink, const uint8_t* buf,
    int len) {
  std::string str = app.empty() ? sink : "[" + app + "]" + sink;
  oai::logger::logger_common::common().debug(str.c_str());
  if (oai::logger::logger_common::should_log(spdlog::level::debug)) {
    for (int i = 0; i < len; i++) printf("%02x ", buf[i]);
    printf("\n");
  }
}
