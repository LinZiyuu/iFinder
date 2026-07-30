/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PLMN_ID_H
#define _PLMN_ID_H

extern "C" {
#include "Ngap_PLMNIdentity.h"
}

#include <string>

namespace oai::ngap {

class PlmnId {
 public:
  PlmnId();
  virtual ~PlmnId();

  void set(const std::string& mcc, const std::string& mnc);
  void get(std::string& mcc, std::string& mnc) const;

  void getMcc(std::string& mcc) const;
  std::string getMcc() const;

  void getMnc(std::string& mnc) const;
  std::string getMnc() const;

  bool encode(Ngap_PLMNIdentity_t&) const;
  bool decode(const Ngap_PLMNIdentity_t&);

 private:
  uint8_t m_MccDigit2;
  uint8_t m_MccDigit1;
  uint8_t m_MncDigit3;  // in case of 2 digit MNC, it should be 0xf
  uint8_t m_MccDigit3;
  uint8_t m_MncDigit2;
  uint8_t m_MncDigit1;
};

}  // namespace oai::ngap

#endif
