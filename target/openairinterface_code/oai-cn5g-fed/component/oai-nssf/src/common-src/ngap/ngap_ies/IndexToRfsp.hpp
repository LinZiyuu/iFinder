/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _INDEX_TO_RFSP_H_
#define _INDEX_TO_RFSP_H_

extern "C" {
#include "Ngap_IndexToRFSP.h"
}

namespace oai::ngap {

class IndexToRfsp {
 public:
  IndexToRfsp();
  IndexToRfsp(const uint32_t&);
  virtual ~IndexToRfsp();

  void set(const uint32_t&);
  uint32_t get() const;

  bool encode(Ngap_IndexToRFSP_t&) const;
  bool decode(const Ngap_IndexToRFSP_t&);

 private:
  uint32_t m_Index;
};

}  // namespace oai::ngap

#endif
