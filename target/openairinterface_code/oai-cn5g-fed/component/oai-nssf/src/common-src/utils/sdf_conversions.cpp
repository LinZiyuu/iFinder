/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "conversions.hpp"
#include "sdf_conversions.hpp"
#include "Helpers.h"
#include "logger_base.hpp"

#include <regex>
#include <fmt/format.h>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/classification.hpp>

using namespace oai::utils;

sdf_conversions::sdf_filter sdf_conversions::sdf_filter::from_string(
    const std::string& filter_string) {
  sdf_filter filter;
  // according to 29.212, we may also need to encode the destination IP
  // accordingly (instead of assigned)

  // example for parsing: permit out ip from 1.2.3.4/24 80,433-500 to assigned

  std::string regex = "permit out (\\S*) from (\\S*) ?(.*)? to assigned";
  //                               proto        src   ports

  std::regex re(regex);
  std::smatch matches;
  if (!std::regex_match(filter_string, matches, re)) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error(
            "SDF Filter %s cannot be parsed, does not follow the "
            "specification, use default filter",
            filter_string);
    return filter;
  }
  std::string proto = matches[1];
  if (!proto.empty() && proto != "ip") {
    filter.protocol_identifier     = std::stoi(proto);
    filter.use_protocol_identifier = true;
    filter.default_filter          = false;
    filter.filter_components++;
  }

  std::string src_ip = matches[2];
  if (!src_ip.empty() && src_ip != "any") {
    filter.src_ip_range   = ip_range::from_string(src_ip);
    filter.default_filter = false;
    filter.filter_components++;
  }

  std::string src_ports = matches[3];
  if (!src_ports.empty()) {
    std::vector<std::string> splits;
    boost::split(
        splits, src_ports, boost::is_any_of(","), boost::token_compress_on);
    for (auto& split : splits) {
      boost::trim(split);
      port_range range = port_range::from_string(split);
      if (range.use_port_range) {
        filter.src_port_ranges.push_back(range);
        filter.filter_components++;
      }
    }
  }
  return filter;
}

sdf_conversions::port_range sdf_conversions::port_range::from_string(
    const std::string& port_string) {
  port_range range;

  std::vector<std::string> splits;
  boost::split(
      splits, port_string, boost::is_any_of("-"), boost::token_compress_on);
  boost::trim(splits[0]);
  range.start = std::stoi(splits[0]);
  if (splits.size() > 1) {
    boost::trim(splits[1]);
    range.end      = std::stoi(splits[1]);
    range.is_range = true;
  }
  range.use_port_range = true;

  return range;
}

sdf_conversions::ip_range sdf_conversions::ip_range::from_string(
    const std::string& ip_string) {
  ip_range range;
  std::vector<std::string> splits;
  boost::split(
      splits, ip_string, boost::is_any_of("/"), boost::token_compress_on);

  if (splits[0] == "any") {
    range.use_ip_range = false;
    return range;
  }
  range.use_ip_range = true;
  in_addr ip_addr    = conv::fromString(splits[0]);
  if (splits.size() == 1) {
    // there is no SNM, so we take 255.255.255.255
    range.snm.s_addr = 0xffffffff;
    range.ip_addr    = ip_addr;
  } else {
    uint8_t snm       = std::stoi(splits[1]);
    uint8_t left_bits = 32 - snm;
    range.snm.s_addr  = ntohl(0xffffffff << left_bits);
  }
  return range;
}

bool sdf_conversions::parse_bitrate_string(
    const std::string& bitrate, uint16_t& value, bitrate_unit_e& unit) {
  std::string bandwidth_regex =
      oai::model::common::helpers::BANDWIDTH_VALIDATION_REGEX;

  std::regex re(bandwidth_regex);
  std::smatch matches;
  if (!std::regex_match(bitrate, matches, re)) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error(
            "Bitrate %s cannot be parsed, does not follow the specification",
            bitrate);
    return false;
  }

  std::string string_bw_value = matches[1];
  // matches[2] is the fractional part but that is included in matches[1]
  // already
  std::string string_unit = matches[3];

  try {
    double bw_value = std::stod(string_bw_value);

    if (string_unit == "bps") {
      unit     = bitrate_unit_e::KBPS;
      bw_value = bw_value / 1000;
    } else if (string_unit == "Kbps") {
      unit = bitrate_unit_e::KBPS;
    } else if (string_unit == "Mbps") {
      unit = bitrate_unit_e::MBPS;
    } else if (string_unit == "Gbps") {
      unit = bitrate_unit_e::GBPS;
    } else if (string_unit == "Tbps") {
      unit = bitrate_unit_e::TBPS;
    }

    // a bit hacky, but like this we can use arithmetic to calculate the unit
    int bitrate_int = static_cast<std::underlying_type_t<bitrate_unit_e>>(unit);

    // Here we convert up so that there is enough space in the int buffer
    while (bw_value > UINT16_MAX) {
      if (bitrate_int == 6) {
        oai::logger::logger_registry::get_logger(LOGGER_COMMON)
            .warn("Bitrate cannot be higher than %d x 256 PBPS", bw_value);
      }
      if (bitrate_int == 5) {
        bw_value = bw_value / 256;
      } else {
        bw_value = bw_value / 1000;
      }
      bitrate_int++;
    }

    // Here we have to handle the fractional part, as 3GPP also allows that
    // we check if bw_value has fractional parts
    while (long(bw_value) != bw_value) {
      if (bitrate_int == 1 || (long(bw_value / 1000) > (UINT16_MAX / 1000))) {
        // we possibly cant make it smaller, so we just cut it off
        break;
      }
      bw_value = bw_value * 1000;
      bitrate_int--;
    }
    // we round up because it is described in 3GPP 29.244
    value = long(bw_value + 0.5);
    unit  = static_cast<bitrate_unit_e>(bitrate_int);
    return true;
  } catch (std::invalid_argument&) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error(
            "Bitrate value part %s is not a number, cannot parse.",
            string_bw_value);
    return false;
  }
}

bool oai::utils::sdf_conversions::parse_bitrate_string_to_unit(
    const std::string& bitrate, const bitrate_unit_e& unit, uint32_t& value) {
  // we make it super easy here and just calculate, we could also integrate it
  // into the other parse function to safe some arithmetics, but I think it is
  // negligible
  bitrate_unit_e calculated_unit;
  uint16_t calculated_value;
  if (!parse_bitrate_string(bitrate, calculated_value, calculated_unit)) {
    return false;
  }

  int bitrate_int_goal =
      static_cast<std::underlying_type_t<bitrate_unit_e>>(unit);
  int bitrate_int_calculated =
      static_cast<std::underlying_type_t<bitrate_unit_e>>(calculated_unit);

  int diff = bitrate_int_calculated - bitrate_int_goal;

  value = calculated_value;

  if (diff > 0) {
    value = value * (diff * 1000);
  } else if (diff < 0) {
    value = value * (diff / 1000);
  }

  return value;
}
