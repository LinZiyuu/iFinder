/*
 * Copyright (c) 2017 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <getopt.h>

#include "options.hpp"

using namespace oai::utils;

int options::m_options;
std::string options::m_libconfigcfg;
bool options::m_log_rot_file_log;
bool options::m_log_stdout;

void options::help() {
  std::cout << std::endl
            << "Usage:  pcf [OPTIONS]..." << std::endl
            << "  -h, --help                   Print help and exit" << std::endl
            << "  -c, --libconfigcfg filename  Read the application "
               "configuration from this file."
            << std::endl
            << "  -o, --stdoutlog              Send the application logs to "
               "STDOUT fd."
            << std::endl
            << "  -r, --rotatelog              Send the application logs to "
               "local file (in  current working directory)."
            << std::endl;
}

bool options::parse(int argc, char** argv) {
  bool ret;

  ret = parseInputOptions(argc, argv);
  ret &= validateOptions();
  return ret;
}

bool options::validateOptions() {
  return ((m_options & libconfigcfg));
}

bool options::parseInputOptions(int argc, char** argv) {
  int c;
  int option_index = 0;
  bool result      = true;

  struct option long_options[] = {
      {"help", no_argument, nullptr, 'h'},
      {"libconfigcfg", required_argument, nullptr, 'f'},
      {"stdoutlog", no_argument, nullptr, 'o'},
      {"rotatelog", no_argument, nullptr, 'r'},
      {nullptr, 0, nullptr, 0}};

  // Loop on arguments
  while (true) {
    c = getopt_long(argc, argv, "horc:", long_options, &option_index);
    if (c == -1) break;  // Exit from the loop.

    switch (c) {
      case 'h': {
        help();
        exit(0);
      }
      case 'c': {
        m_libconfigcfg = optarg;
        m_options |= libconfigcfg;
        break;
      }
      case 'o': {
        m_log_stdout = true;
        m_options |= log_stdout;
        break;
      }
      case 'r': {
        m_log_rot_file_log = true;
        m_options |= log_rot_file_log;
        break;
      }

      case '?': {
        switch (optopt) {
          case 'c': {
            std::cout << "Option -l (libconfig config) requires an argument"
                      << std::endl;
            break;
          }
          case 'o': {
            std::cout << "Option -o does not require an argument, can be also "
                         "set with option -r."
                      << std::endl;
            break;
          }
          case 'r': {
            std::cout << "Option -r does not require an argument, can be also "
                         "set with option -o."
                      << std::endl;
            break;
          }
          default: {
            std::cout << "Unrecognized option [" << c << "]" << std::endl;
            break;
          }
        }
        result = false;
        break;
      }
      default: {
        std::cout << "Unrecognized option [" << c << "]" << std::endl;
        result = false;
      }
    }
  }
  return result;
}
