/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_RETENTION_INFORMATION_H_
#define _UE_RETENTION_INFORMATION_H_

extern "C" {
#include "Ngap_UERetentionInformation.h"
}

namespace oai::ngap {

class UeRetentionInformation {
 public:
  UeRetentionInformation();
  virtual ~UeRetentionInformation();

  void set(const long value);
  void get(long& value) const;

  void set(const e_Ngap_UERetentionInformation& value);
  void get(e_Ngap_UERetentionInformation& value) const;
  e_Ngap_UERetentionInformation get() const;

  bool encode(Ngap_UERetentionInformation_t& value) const;
  bool decode(Ngap_UERetentionInformation_t value);

 private:
  long m_UeRetentionInformation;
};

}  // namespace oai::ngap

#endif
