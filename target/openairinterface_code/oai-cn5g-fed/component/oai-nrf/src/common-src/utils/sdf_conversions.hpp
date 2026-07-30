/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SDF_CONVERSIONS_HPP_SEEN
#define FILE_SDF_CONVERSIONS_HPP_SEEN

#include <netinet/in.h>

#include <string>
#include <vector>

#include "3gpp_commons.h"

namespace oai::utils::sdf_conversions {

struct port_range {
  bool use_port_range = false;
  bool is_range =
      false;  // if range is false, only start should be used and set
  uint16_t start = 0;
  uint16_t end   = UINT16_MAX;

  static port_range from_string(const std::string& port_string);
};

struct ip_range {
  bool use_ip_range = false;
  in_addr ip_addr{};
  in_addr snm{};

  static ip_range from_string(const std::string& ip_string);
};

struct sdf_filter {
  bool default_filter          = true;
  bool use_protocol_identifier = false;
  uint8_t protocol_identifier  = 0;
  // as I understood the spec, there is only one IP range (not like for ports)
  ip_range src_ip_range;
  std::vector<port_range> src_port_ranges;
  ip_range dst_ip_range;
  std::vector<port_range> dst_port_ranges;
  int filter_components = 0;
  // TODO there are some more things in RFC 6733 but this should cover most
  // cases

  static sdf_filter from_string(const std::string& filter_string);
};

// DO NOT CHANGE the int values of the enum, they are used
// Note: 3GPP also allows bit/s, but it is neither used in NAS nor in PFCP so we
// ignore it
enum class bitrate_unit_e {
  KBPS     = 1,
  MBPS     = 2,
  GBPS     = 3,
  TBPS     = 4,
  PBPS     = 5,
  _256PBPS = 6  // to support maximum NAS value
};

/**
 * Parses 3GPP 29.571 BitRate string into value and unit
 * @param bitrate input: bitrate string
 * @param value output: bitrate value
 * @param unit output: bitrate unit
 * @return true if parsing is successful
 */
bool parse_bitrate_string(
    const std::string& bitrate, uint16_t& value, bitrate_unit_e& unit);

bool parse_bitrate_string(const std::string& bitrate, BitRate& bit_rate);
/**
 * Parses 3GPP 29.571 BitRate string to a desired unit (e.g. KBPS)
 * @param bitrate input: bitrate string
 * @param unit input: unit to convert to
 * @param value output: bitrate value
 * @return true if parsing is successful
 */
bool parse_bitrate_string_to_unit(
    const std::string& bitrate, const bitrate_unit_e& unit, uint32_t& value);

}  // namespace oai::utils::sdf_conversions
#endif /* FILE_CONVERSIONS_HPP_SEEN */
