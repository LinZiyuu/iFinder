/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TAI_H_
#define _TAI_H_

#include "NgapIesStruct.hpp"
#include "PlmnId.hpp"
#include "Tac.hpp"

extern "C" {
#include "Ngap_TAI.h"
}

namespace oai::ngap {

class Tai {
 public:
  Tai();
  virtual ~Tai();

  void set(const PlmnId&, const TAC&);
  void get(PlmnId&, TAC&);

  void set(const std::string& mcc, const std::string& mnc, const uint32_t& tac);
  void get(std::string& mcc, std::string& mnc, uint32_t& tac);

  void set(const Tai_t& tai);
  void get(Tai_t& tai);

  bool encode(Ngap_TAI_t&) const;
  bool decode(const Ngap_TAI_t&);

 private:
  PlmnId m_PlmnId;  // Mandatory
  TAC m_Tac;        // Mandatory
};
}  // namespace oai::ngap

#endif
