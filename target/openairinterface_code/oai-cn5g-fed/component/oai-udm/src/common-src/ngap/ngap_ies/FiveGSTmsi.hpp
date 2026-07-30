/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _FIVE_GS_TMSI_H_
#define _FIVE_GS_TMSI_H_

#include <string>

#include "AmfPointer.hpp"
#include "AmfSetId.hpp"

extern "C" {
#include "Ngap_FiveG-S-TMSI.h"
}

namespace oai::ngap {

class FiveGSTmsi {
 public:
  FiveGSTmsi();
  ~FiveGSTmsi();

 public:
  void getTmsi(std::string& value) const;

  void get(std::string& setId, std::string& pointer, std::string& tmsi) const;
  bool set(
      const std::string& setId, const std::string& pointer,
      const std::string& tmsi);

  bool encode(Ngap_FiveG_S_TMSI_t& pdu) const;
  bool decode(const Ngap_FiveG_S_TMSI_t& pdu);

 private:
  std::string m_5gSTmsi;
  std::string m_TmsiValue;

  AmfSetId m_AmfSetId;
  AmfPointer m_AmfPointer;
};

}  // namespace oai::ngap

#endif
