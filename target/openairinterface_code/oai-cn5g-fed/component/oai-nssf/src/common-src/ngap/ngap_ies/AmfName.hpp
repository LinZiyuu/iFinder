/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AMF_NAME_H_
#define _AMF_NAME_H_

#include <string>

extern "C" {
#include "Ngap_AMFName.h"
}

constexpr uint8_t AMF_NAME_SIZE_MAX = 150;

namespace oai::ngap {

class AmfName {
 public:
  AmfName();
  virtual ~AmfName();

  bool set(const std::string& amf_name);
  void get(std::string& amf_name) const;

  bool encode(Ngap_AMFName_t&) const;
  bool decode(const Ngap_AMFName_t&);

 private:
  std::string m_AmfName;
};
}  // namespace oai::ngap

#endif
