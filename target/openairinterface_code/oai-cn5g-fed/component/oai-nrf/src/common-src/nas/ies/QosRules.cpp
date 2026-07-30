/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosRules.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
QosRules::QosRules() : Type6NasIe(), qos_rules_() {
  SetLengthIndicator(kQosRulesContentMinimumLength);
}

//------------------------------------------------------------------------------
QosRules::QosRules(uint8_t iei) : Type6NasIe(iei) {
  SetLengthIndicator(kQosRulesContentMinimumLength);
}

//------------------------------------------------------------------------------
QosRules::QosRules(const std::vector<QosRule>& qos_rules) : Type6NasIe() {
  uint32_t length = 0;  // not include 3 first octets: 1 for IE , 2 for length,
  for (auto qos : qos_rules) {
    length += qos.GetIeLength();
  }
  SetLengthIndicator(
      (length > kQosRulesContentMinimumLength) ? length :
                                                 kQosRulesContentMinimumLength);

  qos_rules_.assign(qos_rules.begin(), qos_rules.end());
}

//------------------------------------------------------------------------------
QosRules::QosRules(uint8_t iei, const std::vector<QosRule>& qos_rules)
    : Type6NasIe(iei) {
  uint32_t length = 0;  // not include 3 first octets: 1 for IE , 2 for length,
  for (auto qos : qos_rules) {
    length += qos.GetIeLength();
  }
  SetLengthIndicator(
      (length > kQosRulesContentMinimumLength) ? length :
                                                 kQosRulesContentMinimumLength);
  qos_rules_.assign(qos_rules.begin(), qos_rules.end());
}

//------------------------------------------------------------------------------
QosRules::~QosRules() {}

//------------------------------------------------------------------------------
void QosRules::Set(const std::vector<QosRule>& qos_rules) {
  if (qos_rules.size() == 0) return;

  uint32_t length = 0;  // not include 3 first octets: 1 for IE , 2 for length,
  for (auto qos : qos_rules) {
    length += qos.GetIeLength();
  }

  SetLengthIndicator(length);

  qos_rules_.assign(qos_rules.begin(), qos_rules.end());
}

//------------------------------------------------------------------------------
void QosRules::Get(std::vector<QosRule>& qos_rules) const {
  qos_rules.assign(qos_rules_.begin(), qos_rules_.end());
  return;
}

//------------------------------------------------------------------------------
void QosRules::AddQosRule(const QosRule& rule) {
  qos_rules_.push_back(rule);
  uint32_t length = GetLengthIndicator();
  length += rule.GetIeLength();
  SetLengthIndicator(length);
}

//------------------------------------------------------------------------------
int QosRules::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int len_pos = 0;
  int encoded_header_size =
      Type6NasIe::Encode(buf + encoded_size, len, len_pos);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;
  for (const auto& q : qos_rules_) {
    int encoded_qos_rule_size =
        q.Encode(buf + encoded_size, len - encoded_size);
    if (encoded_qos_rule_size == KEncodeDecodeError) return KEncodeDecodeError;
    encoded_size += encoded_qos_rule_size;
  }

  // Encode length
  int encoded_len_ie = 0;
  ENCODE_U16(buf + len_pos, encoded_size - GetHeaderLength(), encoded_len_ie);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int QosRules::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());
  int decoded_size = 0;

  // IEI and Length
  uint16_t ie_len         = 0;
  int decoded_header_size = Type6NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;
  qos_rules_.clear();

  uint16_t length           = GetLengthIndicator();
  uint16_t decoded_qos_rule = length;
  while (length > 0) {
    QosRule qos_rule = {};
    int decoded_qos_rule_size =
        qos_rule.Decode(buf + decoded_size, len - decoded_size);
    if (decoded_qos_rule_size == KEncodeDecodeError) break;
    decoded_size += decoded_qos_rule_size;
    length -= decoded_qos_rule_size;
    qos_rules_.push_back(qos_rule);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s (len %d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
