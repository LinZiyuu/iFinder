/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NETWORK_INSTANCE_H_
#define _NETWORK_INSTANCE_H_

extern "C" {
#include "Ngap_NetworkInstance.h"
}

namespace oai::ngap {

class NetworkInstance {
 public:
  NetworkInstance();
  NetworkInstance(const long& networkInstance);
  virtual ~NetworkInstance();

  void set(const long& networkInstance);
  bool get(long& networkInstance) const;

  bool encode(Ngap_NetworkInstance_t&) const;
  bool decode(const Ngap_NetworkInstance_t&);

 private:
  long m_NetworkInstance;
};

}  // namespace oai::ngap

#endif
