/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NAS_5GSM_HEADER_H_
#define _NAS_5GSM_HEADER_H_

#include "3gpp_24.501.hpp"
#include "ExtendedProtocolDiscriminator.hpp"
#include "NasMessageType.hpp"
#include "PduSessionIdentity.hpp"
#include "ProcedureTransactionIdentity.hpp"

constexpr uint8_t kNas5gsmHeaderLength = 4;

namespace oai::nas {

class Nas5gsmHeader {
 public:
  Nas5gsmHeader(){};
  virtual ~Nas5gsmHeader() = default;

  Nas5gsmHeader(
      uint8_t epd, uint8_t pdu_session_id, uint16_t procedure_transaction_id,
      uint8_t msg_type);
  Nas5gsmHeader(uint8_t epd, uint8_t msg_type);

  Nas5gsmHeader& operator=(const struct Nas5gsmHeader& nas_header) {
    ie_epd_                      = nas_header.ie_epd_;
    ie_pdu_session_id_           = nas_header.ie_pdu_session_id_;
    ie_procedure_transaction_id_ = nas_header.ie_procedure_transaction_id_;
    ie_msg_type_                 = nas_header.ie_msg_type_;
    return *this;
  }

  void SetHeader(
      uint8_t epd, uint8_t pdu_session_id, uint16_t procedure_transaction_id,
      uint8_t msg_type);

  uint32_t GetLength() const;
  bool Validate(uint32_t len) const;

  int Encode(uint8_t* buf, int len);
  int Decode(uint8_t* buf, int len);

  void SetEpd(uint8_t epd);
  uint8_t GetEpd() const;

  void SetPduSessionIdentity(uint8_t pdu_session_id);
  uint8_t GetPduSessionIdentity() const;

  void SetProcedureTransactionIdentity(uint8_t procedure_transaction_id);
  uint8_t GetProcedureTransactionIdentity() const;

  void SetMessageType(uint8_t type);
  uint8_t GetMessageType() const;

 private:
  ExtendedProtocolDiscriminator ie_epd_;                      // Mandatory
  PduSessionIdentity ie_pdu_session_id_;                      // Mandatory
  ProcedureTransactionIdentity ie_procedure_transaction_id_;  // Mandatory
  NasMessageType ie_msg_type_;                                // Mandatory
};

}  // namespace oai::nas

#endif
