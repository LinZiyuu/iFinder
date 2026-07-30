/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef _AMF_SET_ID_H_
#define _AMF_SET_ID_H_

#include <string>
constexpr uint16_t kAmfSetIdMaxValue = 1023;

extern "C" {
#include "Ngap_AMFSetID.h"
}

namespace oai::ngap {

class AmfSetId {
 public:
  AmfSetId();
  virtual ~AmfSetId();

  bool set(const std::string&);
  bool set(const uint16_t&);

  void get(std::string&) const;
  void get(uint16_t&) const;

  bool encode(Ngap_AMFSetID_t&) const;
  bool decode(const Ngap_AMFSetID_t&);

 private:
  uint16_t m_Id;
};

}  // namespace oai::ngap

#endif
