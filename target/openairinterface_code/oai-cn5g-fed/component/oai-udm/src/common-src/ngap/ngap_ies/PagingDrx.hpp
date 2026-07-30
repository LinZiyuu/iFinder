/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PAGING_DRX_H
#define _PAGING_DRX_H

namespace oai::ngap {

class PagingDRX {
 public:
 private:
  enum { 32, 64, 128, 256 } pagingDrx;
};

}  // namespace oai::ngap

#endif
