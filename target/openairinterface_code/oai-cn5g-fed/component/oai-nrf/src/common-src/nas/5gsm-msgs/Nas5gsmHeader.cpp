/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Nas5gsmHeader.hpp"

#include "3gpp_24.501.hpp"
#include "NasHelper.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Nas5gsmHeader::Nas5gsmHeader(
    uint8_t epd, uint8_t pdu_session_id, uint16_t procedure_transaction_id,
    uint8_t msg_type)
    : ie_epd_(epd),
      ie_pdu_session_id_(pdu_session_id),
      ie_procedure_transaction_id_(procedure_transaction_id),
      ie_msg_type_(msg_type) {}

//------------------------------------------------------------------------------
Nas5gsmHeader::Nas5gsmHeader(uint8_t epd, uint8_t msg_type)
    : ie_epd_(epd), ie_msg_type_(msg_type) {}

//------------------------------------------------------------------------------
void Nas5gsmHeader::SetHeader(
    uint8_t epd, uint8_t pdu_session_id, uint16_t procedure_transaction_id,
    uint8_t msg_type) {
  ie_epd_.Set(epd);
  ie_pdu_session_id_.Set(pdu_session_id);
  ie_procedure_transaction_id_.Set(procedure_transaction_id);
  ie_msg_type_.Set(msg_type);
}

//------------------------------------------------------------------------------
void Nas5gsmHeader::SetEpd(uint8_t epd) {
  ie_epd_.Set(epd);
}

//------------------------------------------------------------------------------
uint8_t Nas5gsmHeader::GetEpd() const {
  return ie_epd_.Get();
}

//------------------------------------------------------------------------------
void Nas5gsmHeader::SetPduSessionIdentity(uint8_t pdu_session_id) {
  ie_pdu_session_id_.Set(pdu_session_id);
}

//------------------------------------------------------------------------------
uint8_t Nas5gsmHeader::GetPduSessionIdentity() const {
  return ie_pdu_session_id_.Get();
}

//------------------------------------------------------------------------------
void Nas5gsmHeader::SetProcedureTransactionIdentity(
    uint8_t procedure_transaction_id) {
  ie_procedure_transaction_id_.Set(procedure_transaction_id);
}
//------------------------------------------------------------------------------
uint8_t Nas5gsmHeader::GetProcedureTransactionIdentity() const {
  return ie_procedure_transaction_id_.Get();
}

//------------------------------------------------------------------------------
void Nas5gsmHeader::SetMessageType(uint8_t type) {
  ie_msg_type_.Set(type);
}

//------------------------------------------------------------------------------
uint8_t Nas5gsmHeader::GetMessageType() const {
  return ie_msg_type_.Get();
}

//------------------------------------------------------------------------------
uint32_t Nas5gsmHeader::GetLength() const {
  return kNas5gsmHeaderLength;
}

//------------------------------------------------------------------------------
bool Nas5gsmHeader::Validate(uint32_t len) const {
  uint32_t actual_length = GetLength();
  if (len < actual_length) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this message "
        "(0x%x "
        "octet)",
        actual_length);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
int Nas5gsmHeader::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding Nas5gsmHeader");

  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  if ((encoded_ie_size = NasHelper::Encode(ie_epd_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((encoded_ie_size = NasHelper::Encode(
           ie_pdu_session_id_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((encoded_ie_size = NasHelper::Encode(
           ie_procedure_transaction_id_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((encoded_ie_size = NasHelper::Encode(
           ie_msg_type_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded Nas5gsmHeader (len %d octets)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int Nas5gsmHeader::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding Nas5gsmHeader");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  if (len < kNas5gsmHeaderLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than %d octets", kNas5gsmHeaderLength);
    return KEncodeDecodeError;
  }

  if ((decoded_ie_size = NasHelper::Decode(
           ie_epd_, buf, len, decoded_size, true)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((decoded_ie_size = NasHelper::Decode(
           ie_pdu_session_id_, buf, len, decoded_size, true)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((decoded_ie_size = NasHelper::Decode(
           ie_procedure_transaction_id_, buf, len, decoded_size, true)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((decoded_ie_size = NasHelper::Decode(
           ie_msg_type_, buf, len, decoded_size, true)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Decoded Nas5gsmHeader len (%d octets)", decoded_size);
  return decoded_size;
}
