/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionReactivationResultErrorCause.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionReactivationResultErrorCause::PduSessionReactivationResultErrorCause()
    : Type6NasIe(kIeiPduSessionReactivationResultErrorCause),
      pdu_session_id_cause_value_pair_() {
  std::pair<uint8_t, uint8_t> value = std::make_pair<uint8_t, uint8_t>(0, 0);
  pdu_session_id_cause_value_pair_.push_back(value);
  SetLengthIndicator(
      kPduSessionReactivationResultErrorCauseContentMinimumLength);
}

//------------------------------------------------------------------------------
PduSessionReactivationResultErrorCause::PduSessionReactivationResultErrorCause(
    uint8_t session_id, uint8_t cause)
    : Type6NasIe(kIeiPduSessionReactivationResultErrorCause) {
  std::pair<uint8_t, uint8_t> value = std::make_pair(session_id, cause);
  pdu_session_id_cause_value_pair_.push_back(value);
  SetLengthIndicator(
      kPduSessionReactivationResultErrorCauseContentMinimumLength);
}

//------------------------------------------------------------------------------
// PduSessionReactivationResultErrorCause::
//    ~PduSessionReactivationResultErrorCause() {}

//------------------------------------------------------------------------------
void PduSessionReactivationResultErrorCause::SetValue(
    uint8_t session_id, uint8_t cause) {
  std::pair<uint8_t, uint8_t> value = std::make_pair(session_id, cause);
  pdu_session_id_cause_value_pair_.clear();
  pdu_session_id_cause_value_pair_.push_back(value);
}

//------------------------------------------------------------------------------
void PduSessionReactivationResultErrorCause::SetValue(
    const std::vector<std::pair<uint8_t, uint8_t>>& value) {
  if (value.size() > 0) pdu_session_id_cause_value_pair_ = value;
  SetLengthIndicator(value.size() * 2);
}

//------------------------------------------------------------------------------
std::pair<uint8_t, uint8_t> PduSessionReactivationResultErrorCause::GetValue()
    const {
  if (pdu_session_id_cause_value_pair_.size() > 0) {
    return pdu_session_id_cause_value_pair_[0];
  }
  return std::pair<uint8_t, uint8_t>(0, 0);
}

//------------------------------------------------------------------------------
int PduSessionReactivationResultErrorCause::Encode(
    uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length (later)
  int len_pos = 0;
  int encoded_header_size =
      Type6NasIe::Encode(buf + encoded_size, len, len_pos);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // PDU Session ID/Cause Value
  for (const auto& i : pdu_session_id_cause_value_pair_) {
    ENCODE_U8(buf + encoded_size, i.first, encoded_size);
    ENCODE_U8(buf + encoded_size, i.second, encoded_size);
  }

  // Encode length
  int encoded_len_ie = 0;
  ENCODE_U16(buf + len_pos, encoded_size - GetHeaderLength(), encoded_len_ie);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionReactivationResultErrorCause::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());
  int decoded_size = 0;

  // IEI and Length
  uint16_t ie_len         = 0;
  int decoded_header_size = Type6NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;
  ie_len = GetLengthIndicator();

  // Decode PDU Session ID/Cause Value
  pdu_session_id_cause_value_pair_.clear();
  while (decoded_size < ie_len - 2) {
    uint8_t pdu_session_id = {};
    uint8_t cause_value    = {};
    DECODE_U8(buf + decoded_size, pdu_session_id, decoded_size);
    DECODE_U8(buf + decoded_size, cause_value, decoded_size);
    std::pair<uint8_t, uint8_t> value =
        std::make_pair(pdu_session_id, cause_value);
    pdu_session_id_cause_value_pair_.push_back(value);
  }

  for (const auto& i : pdu_session_id_cause_value_pair_) {
    oai::logger::logger_common::nas().debug(
        "PDU Session ID 0x%x, Cause Value", i.first, i.second);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s (len %d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
