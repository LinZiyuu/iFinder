/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

// TODO this is here because we need it for the common DNS configuration
// but we should refactor the whole 24.051 (and other common definitions) into
// the common-src

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

static const std::vector<std::string> notification_control_e2str = {
    "ERROR", "REQUESTED", "NOT_REQUESTED"};

// PDU Session Type value
enum pdu_session_type_e {
  PDU_SESSION_TYPE_E_UNKNOWN      = 0,
  PDU_SESSION_TYPE_E_IPV4         = 1,
  PDU_SESSION_TYPE_E_IPV6         = 2,
  PDU_SESSION_TYPE_E_IPV4V6       = 3,
  PDU_SESSION_TYPE_E_UNSTRUCTURED = 4,
  PDU_SESSION_TYPE_E_ETHERNET     = 5,
  PDU_SESSION_TYPE_E_RESERVED     = 7,
};

static const std::vector<std::string> pdu_session_type_e2str = {
    "Error",        "IPV4",     "IPV6",   "IPV4V6",
    "UNSTRUCTURED", "ETHERNET", "IPV4V6", "RESERVED"};

typedef struct pdu_session_type_s {
  uint8_t pdu_session_type;
  pdu_session_type_s() : pdu_session_type(PDU_SESSION_TYPE_E_IPV4) {}
  pdu_session_type_s(const uint8_t& p) : pdu_session_type(p) {}
  pdu_session_type_s(const struct pdu_session_type_s& p) = default;
  pdu_session_type_s(const std::string& s) {
    if (s == "IPV4") {
      pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4;
    } else if (s == "IPV6") {
      pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV6;
    } else if (s == "IPV4V6") {
      pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4V6;
    } else {
      pdu_session_type =
          pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4;  // Default value
    }
  }
  bool operator==(const struct pdu_session_type_s& p) const {
    return (p.pdu_session_type == pdu_session_type);
  }
  //------------------------------------------------------------------------------
  bool operator==(const pdu_session_type_e& p) const {
    return (p == pdu_session_type);
  }
  //------------------------------------------------------------------------------
  const std::string& to_string() const {
    return pdu_session_type_e2str.at(pdu_session_type);
  }
  //------------------------------------------------------------------------------
  nlohmann::json to_json() const {
    nlohmann::json json_data = {};
    json_data                = to_string();
    return json_data;
  }
  //------------------------------------------------------------------------------
  void from_json(nlohmann::json& json_data) {
    std::string pdu_session_type_str = json_data.get<std::string>();
    if (pdu_session_type_str == "IPV4") {
      pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4;
    } else if (pdu_session_type_str == "IPV6") {
      pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV6;
    } else if (pdu_session_type_str == "IPV4V6") {
      pdu_session_type = pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4V6;
    } else {
      pdu_session_type =
          pdu_session_type_e::PDU_SESSION_TYPE_E_IPV4;  // Default value
    }
  }

} pdu_session_type_t;
