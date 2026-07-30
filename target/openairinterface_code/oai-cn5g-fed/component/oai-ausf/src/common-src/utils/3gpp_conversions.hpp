/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_3GPP_CONVERSIONS_HPP_SEEN
#define FILE_3GPP_CONVERSIONS_HPP_SEEN

#include "3gpp_29.274.h"
#include "3gpp_29.244.h"
#include "3gpp_29.281.h"
#include "3gpp_24.501.hpp"
#include "endpoint.hpp"

namespace oai::utils {

class xgpp_conv {
 public:
  static void pdu_session_type_to_pdn_type(
      const pdu_session_type_t& pdu_session_type, pdn_type_t& pdn_type);
  static void pdu_session_type_to_pdn_type(
      const pdu_session_type_t& pdu_session_type, pfcp::pdn_type_t& pdn_type);
  static void ethType_to_pcfp_ethertype(
      const std::string& ethType, pfcp::ethertype_t& ethertype);
  static void pdn_type_to_pdu_session_type(
      const pdn_type_t& pdn_type, pdu_session_type_t& pdu_session_type);
  static void paa_to_pfcp_ue_ip_address(
      const paa_t& paa, pfcp::ue_ip_address_t& ue_ip_address);
  static void pdu_session_ip_to_pfcp_ue_ip_address(
      const pdu_session_type_t& pdu_session_type,
      const struct in_addr& ipv4_address, const struct in6_addr ipv6_address,
      pfcp::ue_ip_address_t& ue_ip_address);
  static void pdn_ip_to_pfcp_ue_ip_address(
      const pdn_type_t& pdn_type, const struct in_addr& ipv4_address,
      const struct in6_addr ipv6_address, pfcp::ue_ip_address_t& ue_ip_address);
  static void pfcp_to_core_fteid(const pfcp::fteid_t& pfteid, fteid_t& fteid);
  static void pfcp_from_core_fteid(pfcp::fteid_t& pfteid, const fteid_t& fteid);
  static void pfcp_cause_to_core_cause(const pfcp::cause_t& pc, cause_t& c);
  static bool endpoint_to_gtp_u_peer_address(
      const endpoint& ep, gtp_u_peer_address_t& gpa);
  static u_int8_t pdu_session_type_to_ngap_pdu_session_type(
      u_int8_t pdu_session_type_24_501);
};  // class xgpp_conv
}  // namespace oai::utils

#endif /* FILE_3GPP_CONVERSIONS_HPP_SEEN */
