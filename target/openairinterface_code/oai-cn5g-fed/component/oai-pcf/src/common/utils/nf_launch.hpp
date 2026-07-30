/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <cstdint>
#include <string>

namespace oai::utils {

class nf_launch {
 public:
  /**
   * Checks if a process of this NF is already running
   * @return True when a process is already running
   */
  static bool already_running();

 private:
  /**
   * Executes the given command and returns the output
   * WARNING: This function does not sanitize user input, do not call it on
   * any un-sanitized user input due to security reasons
   * @param command Command to execute
   * @return Output
   */
  static std::string command_output(const std::string& command);
};

}  // namespace oai::utils
