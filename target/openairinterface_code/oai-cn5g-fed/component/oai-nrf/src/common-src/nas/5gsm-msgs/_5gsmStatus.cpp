/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gsmStatus.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsmStatus::_5gsmStatus()
    : Nas5gsmMessage(k5gsSessionManagementMessages, k5gsmStatus) {}

//------------------------------------------------------------------------------
_5gsmStatus::~_5gsmStatus() {}

//------------------------------------------------------------------------------
uint32_t _5gsmStatus::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();
  msg_len += ie_5gsm_cause_.GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void _5gsmStatus::Set5gsmCause(const _5gsmCause& _5gsm_cause) {
  ie_5gsm_cause_ = _5gsm_cause;
}

//------------------------------------------------------------------------------
void _5gsmStatus::Get5gsmCause(_5gsmCause& _5gsm_cause) const {
  _5gsm_cause = ie_5gsm_cause_;
}

//------------------------------------------------------------------------------
int _5gsmStatus::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding _5gsmStatus message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = Nas5gsmMessage::Encode(buf, len)) ==
      KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GSM cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gsm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded _5gsmStatus message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int _5gsmStatus::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding _5gsmStatus message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = Nas5gsmMessage::Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // 5GSM cause
  if ((decoded_ie_size =
           NasHelper::Decode(ie_5gsm_cause_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Decoded _5gsmStatus message len (%d)", decoded_size);
  return decoded_size;
}
