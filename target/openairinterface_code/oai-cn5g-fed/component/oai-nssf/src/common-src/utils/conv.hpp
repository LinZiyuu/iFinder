/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// TODO we should move conversions.hpp and conversion.h in this file and rename
// it conversions.hpp

#pragma once
#include "nlohmann/json.hpp"
#include "yaml-cpp/yaml.h"

namespace oai::utils::conversions {

/**
 * Replaces primitive JSON string values with integers or bools if possible
 * @param j
 */

static void fix_primitive_json_values(
    nlohmann::json& j, bool parse_hex_values = false) {
  for (const auto& elem : j.items()) {
    if (elem.value().is_primitive()) {
      // we have to hardcode SD value here, because of the stupid 3GPP format
      // without leading 0x -> There is no way how we can detect this
      // automatically so then, stoi just takes base 10 and we have wrong values
      if (elem.key() == "sd") continue;

      try {
        std::string e = elem.value();
        if (e == "true") j[elem.key()] = true;
        if (e == "false") j[elem.key()] = false;
        // rfind returns 0 if string starts with 0x
        // we have to handle this here, because otherwise "0x123" is evaluated
        // as 0 int with base 10
        if (e.rfind("0x", 0) == 0) {
          if (parse_hex_values) {
            int val       = std::stoi(e, nullptr, 16);
            j[elem.key()] = val;
          } else {
            // we do not parse the int and keep a string value
            continue;
          }
        } else {
          size_t chars_processed = 0;
          int val                = std::stoi(e, &chars_processed);
          if (chars_processed != e.length()) throw std::invalid_argument("");
          j[elem.key()] = val;  // replace with int
        }
      } catch (std::invalid_argument& ex) {
      } catch (std::exception& e) {
      }
    } else {
      fix_primitive_json_values(elem.value(), parse_hex_values);
    }
  }
}

static nlohmann::json yaml_to_json(
    const YAML::Node& node, bool parse_hex_values = false) {
  YAML::Emitter emitter;
  emitter << YAML::DoubleQuoted << YAML::Flow << YAML::BeginSeq << node;
  std::string json_string(emitter.c_str() + 1);
  nlohmann::json j = nlohmann::json::parse(json_string);
  // this is a bit hacky but the problem is that YAML emits ints as strings
  fix_primitive_json_values(j, parse_hex_values);
  return j;
}
}  // namespace oai::utils::conversions
