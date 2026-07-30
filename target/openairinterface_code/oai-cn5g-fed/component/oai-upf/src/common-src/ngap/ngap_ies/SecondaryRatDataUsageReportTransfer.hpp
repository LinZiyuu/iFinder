/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SECONDARY_RAT_DATA_USAGE_REPORT_TRANSFER_H_
#define _SECONDARY_RAT_DATA_USAGE_REPORT_TRANSFER_H_

#include "Cause.hpp"
#include "NgapIesStruct.hpp"

extern "C" {
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_SecondaryRATDataUsageReportTransfer.h"
}

namespace oai::ngap {

class SecondaryRatDataUsageReportTransfer {
 public:
  SecondaryRatDataUsageReportTransfer();
  virtual ~SecondaryRatDataUsageReportTransfer();

  // TODO: Secondary RAT Usage Information (Optional)

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_SecondaryRATDataUsageReportTransfer_t*
      m_SecondaryRatDataUsageReportTransferIe;

  // TODO: Secondary RAT Usage Information (Optional)
};

}  // namespace oai::ngap
#endif
