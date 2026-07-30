/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nf_launch.hpp"

#include <boost/filesystem.hpp>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <stdexcept>

using namespace oai::utils;
namespace fs = boost::filesystem;

//------------------------------------------------------------------------------
bool nf_launch::already_running() {
  // Strip the exec name from the path

  auto process_name = fs::canonical("/proc/self/exe").filename().string();

  std::string cmd    = "pgrep -c " + process_name;
  std::string output = command_output(cmd);

  int running_processes;

  try {
    running_processes = std::stoi(output);
  } catch (std::invalid_argument& ex) {
    std::cout << "ERROR: Could not read how many processes are running"
              << std::endl;
    return true;
  }

  if (running_processes > 1) {
    std::cout << "ERROR: There are " << running_processes << " instances of "
              << process_name << " running" << std::endl;
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
std::string nf_launch::command_output(const std::string& command) {
  static uint64_t index = 0;
  auto filename         = std::ostringstream{};
  filename << getpid() << "_" << index++;
  auto const tmp_path = fs::temp_directory_path() / filename.str();
  if (fs::exists(tmp_path) && !fs::remove(tmp_path)) {
    return "failed to open temporary file " + tmp_path.string();
  }

  int ret =
      std::system((command + " > " + tmp_path.string() + " 2>&1 ").c_str());
  if (ret != 0) {
    return "Command return non-zero exit code";
  }

  auto content = std::ostringstream{};
  {
    auto const istream = std::ifstream{tmp_path.string()};
    content << istream.rdbuf();
  }

  fs::remove(tmp_path);
  return content.str();
}
