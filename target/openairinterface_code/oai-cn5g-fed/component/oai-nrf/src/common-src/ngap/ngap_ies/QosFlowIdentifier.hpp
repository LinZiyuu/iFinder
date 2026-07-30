/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_IDENTIFIER_H_
#define _QOS_FLOW_IDENTIFIER_H_

extern "C" {
#include "Ngap_QosFlowIdentifier.h"
}

namespace oai::ngap {

class QosFlowIdentifier {
 public:
  QosFlowIdentifier();
  virtual ~QosFlowIdentifier();

  void set(const long& value);
  void get(long& value) const;
  long get() const;

  bool encode(Ngap_QosFlowIdentifier_t&) const;
  bool decode(const Ngap_QosFlowIdentifier_t&);

 private:
  long m_QosFlowIdentifier;
};

}  // namespace oai::ngap

#endif
