/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _MAXIMUM_DATA_BURST_VOLUME_H_
#define _MAXIMUM_DATA_BURST_VOLUME_H_

extern "C" {
#include "Ngap_MaximumDataBurstVolume.h"
}

namespace oai::ngap {

class MaximumDataBurstVolume {
 public:
  MaximumDataBurstVolume();
  virtual ~MaximumDataBurstVolume();

  void set(const long& value);
  void get(long& value) const;

  bool encode(Ngap_MaximumDataBurstVolume_t&) const;
  bool decode(const Ngap_MaximumDataBurstVolume_t&);

 private:
  long m_MaximumDataBurstVolume;
};

}  // namespace oai::ngap

#endif
