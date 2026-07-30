/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TAI_LIST_FOR_PAGING_H_
#define _TAI_LIST_FOR_PAGING_H_

#include "Tai.hpp"

extern "C" {
#include "Ngap_TAIListForPaging.h"
}

namespace oai::ngap {

class TaiListForPaging {
 public:
  TaiListForPaging();
  virtual ~TaiListForPaging();

  void set(const std::vector<Tai>& list);
  void get(std::vector<Tai>& list) const;

  bool encode(Ngap_TAIListForPaging_t& pdu) const;
  bool decode(const Ngap_TAIListForPaging_t& pdu);

 private:
  std::vector<Tai> m_TaiList;
};

}  // namespace oai::ngap

#endif
