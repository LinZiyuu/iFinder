/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AMF_REGIONID_H_
#define _AMF_REGIONID_H_

#include <string>

extern "C" {
#include "Ngap_AMFRegionID.h"
}

namespace oai::ngap {

class AmfRegionId {
 public:
  AmfRegionId();
  virtual ~AmfRegionId();

  void set(const std::string&);
  void get(std::string&) const;

  void set(const uint8_t&);
  void get(uint8_t&) const;

  bool encode(Ngap_AMFRegionID_t&) const;
  bool decode(const Ngap_AMFRegionID_t&);

 private:
  uint8_t m_RegionId;
};

}  // namespace oai::ngap

#endif
