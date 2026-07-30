/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NAS_5GSM_MESSAGE_H_
#define _NAS_5GSM_MESSAGE_H_

#include "Nas5gsmHeader.hpp"
#include "NasMessage.hpp"

namespace oai::nas {

class Nas5gsmMessage : public NasMessage {
 public:
  Nas5gsmMessage(){};
  virtual ~Nas5gsmMessage(){};

  Nas5gsmMessage(
      uint8_t epd, uint8_t pdu_session_id, uint16_t procedure_transaction_id,
      uint8_t msg_type);
  Nas5gsmMessage(uint8_t epd, uint8_t msg_type);

  Nas5gsmMessage& operator=(const struct Nas5gsmMessage& nas_msg) {
    ie_header_ = nas_msg.ie_header_;
    return *this;
  }

  void SetHeader(
      uint8_t epd, uint8_t pdu_session_id, uint16_t procedure_transaction_id,
      uint8_t msg_type);
  void SetHeader(uint8_t pdu_session_id, uint16_t procedure_transaction_id);

  Nas5gsmHeader GetHeader() const;
  void GetHeader(Nas5gsmHeader& nas_header) const;

  uint32_t GetLength() const override;

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

 protected:
  Nas5gsmHeader ie_header_;  // Mandatory
};

}  // namespace oai::nas

#endif
