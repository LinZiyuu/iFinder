/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowDescriptions.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
QosFlowDescriptions::QosFlowDescriptions()
    : Type6NasIe(), qos_flow_descriptions_() {
  SetLengthIndicator(kQosFlowDescriptionsContentMinimumLength);
}

//------------------------------------------------------------------------------
QosFlowDescriptions::QosFlowDescriptions(uint8_t iei) : Type6NasIe(iei) {
  SetLengthIndicator(kQosFlowDescriptionsContentMinimumLength);
}

//------------------------------------------------------------------------------
QosFlowDescriptions::QosFlowDescriptions(
    const std::vector<QosFlowDescription>& qos_flow_descriptions)
    : Type6NasIe() {
  uint32_t length = 0;  // not include 3 first octets: 1 for IE , 2 for length,
  for (auto qos : qos_flow_descriptions) {
    length += qos.GetLength();
  }
  SetLengthIndicator(
      (length > kQosFlowDescriptionsContentMinimumLength) ?
          length :
          kQosFlowDescriptionsContentMinimumLength);

  qos_flow_descriptions_.assign(
      qos_flow_descriptions.begin(), qos_flow_descriptions.end());
}

//------------------------------------------------------------------------------
QosFlowDescriptions::QosFlowDescriptions(
    uint8_t iei, const std::vector<QosFlowDescription>& qos_flow_descriptions)
    : Type6NasIe(iei) {
  uint32_t length = 0;  // not include 3 first octets: 1 for IE , 2 for length,
  for (auto qos : qos_flow_descriptions) {
    length += qos.GetLength();
  }
  SetLengthIndicator(
      (length > kQosFlowDescriptionsContentMinimumLength) ?
          length :
          kQosFlowDescriptionsContentMinimumLength);

  qos_flow_descriptions_.assign(
      qos_flow_descriptions.begin(), qos_flow_descriptions.end());
}

//------------------------------------------------------------------------------
QosFlowDescriptions::~QosFlowDescriptions() {}

//------------------------------------------------------------------------------
void QosFlowDescriptions::Set(
    const std::vector<QosFlowDescription>& qos_flow_descriptions) {
  if (qos_flow_descriptions.size() == 0) return;

  uint32_t length = 0;  // not include 3 first octets: 1 for IE , 2 for length,
  for (auto qos : qos_flow_descriptions) {
    length += qos.GetLength();
  }

  SetLengthIndicator(length);

  qos_flow_descriptions_.assign(
      qos_flow_descriptions.begin(), qos_flow_descriptions.end());
}

//------------------------------------------------------------------------------
void QosFlowDescriptions::Get(
    std::vector<QosFlowDescription>& qos_flow_descriptions) const {
  qos_flow_descriptions.assign(
      qos_flow_descriptions_.begin(), qos_flow_descriptions_.end());
  return;
}

//------------------------------------------------------------------------------
void QosFlowDescriptions::AddQosFlowDescription(
    const QosFlowDescription& rule) {
  qos_flow_descriptions_.push_back(rule);
  uint32_t length = GetLengthIndicator();
  length += rule.GetLength();
  SetLengthIndicator(length);
}

//------------------------------------------------------------------------------
int QosFlowDescriptions::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int len_pos = 0;
  int encoded_header_size =
      Type6NasIe::Encode(buf + encoded_size, len, len_pos);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;
  for (const auto& q : qos_flow_descriptions_) {
    int encoded_qos_flow_size =
        q.Encode(buf + encoded_size, len - encoded_size);
    if (encoded_qos_flow_size == KEncodeDecodeError) return KEncodeDecodeError;
    encoded_size += encoded_qos_flow_size;
  }

  // Encode length
  int encoded_len_ie = 0;
  ENCODE_U16(buf + len_pos, encoded_size - GetHeaderLength(), encoded_len_ie);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int QosFlowDescriptions::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());
  int decoded_size = 0;

  // IEI and Length
  uint16_t ie_len         = 0;
  int decoded_header_size = Type6NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;
  qos_flow_descriptions_.clear();

  uint16_t length           = GetLengthIndicator();
  uint16_t decoded_qos_rule = length;
  while (length > 0) {
    QosFlowDescription qos_flow = {};
    int decoded_qos_flow_size =
        qos_flow.Decode(buf + decoded_size, len - decoded_size);
    if (decoded_qos_flow_size == KEncodeDecodeError) break;
    decoded_size += decoded_qos_flow_size;
    length -= decoded_qos_flow_size;
    qos_flow_descriptions_.push_back(qos_flow);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s (len %d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
