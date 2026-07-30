/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Nas5gsmMessage.hpp"

#include "NasHelper.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Nas5gsmMessage::Nas5gsmMessage(
    uint8_t epd, uint8_t pdu_session_id, uint16_t procedure_transaction_id,
    uint8_t msg_type)
    : ie_header_(epd, pdu_session_id, procedure_transaction_id, msg_type) {}

//------------------------------------------------------------------------------
Nas5gsmMessage::Nas5gsmMessage(uint8_t epd, uint8_t msg_type)
    : ie_header_(epd, msg_type) {}

//------------------------------------------------------------------------------
void Nas5gsmMessage::SetHeader(
    uint8_t epd, uint8_t pdu_session_id, uint16_t procedure_transaction_id,
    uint8_t msg_type) {
  ie_header_.SetHeader(epd, pdu_session_id, procedure_transaction_id, msg_type);
}

//------------------------------------------------------------------------------
void Nas5gsmMessage::SetHeader(
    uint8_t pdu_session_id, uint16_t procedure_transaction_id) {
  ie_header_.SetPduSessionIdentity(pdu_session_id);
  ie_header_.SetProcedureTransactionIdentity(procedure_transaction_id);
}

//------------------------------------------------------------------------------
Nas5gsmHeader Nas5gsmMessage::GetHeader() const {
  return ie_header_;
}

//------------------------------------------------------------------------------
void Nas5gsmMessage::GetHeader(Nas5gsmHeader& nas_header) const {
  nas_header = ie_header_;
}

//------------------------------------------------------------------------------
uint32_t Nas5gsmMessage::GetLength() const {
  return ie_header_.GetLength();
}

//------------------------------------------------------------------------------
int Nas5gsmMessage::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding Nas5gsmMessage");

  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  oai::logger::logger_common::nas().debug(
      "Encoded Nas5gsmMessage (len %d octets)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int Nas5gsmMessage::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding Nas5gsmMessage");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  oai::logger::logger_common::nas().debug(
      "Decoded Nas5gsmMessage len (%d octets)", decoded_size);
  return decoded_size;
}
