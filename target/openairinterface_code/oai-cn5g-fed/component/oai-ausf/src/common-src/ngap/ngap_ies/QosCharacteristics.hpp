/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_CHARACTERISTICS_H_
#define _QOS_CHARACTERISTICS_H_

#include <optional>

#include "Dynamic5qiDescriptor.hpp"
#include "NonDynamic5qiDescriptor.hpp"

extern "C" {
#include "Ngap_QosCharacteristics.h"
}

namespace oai::ngap {

class QosCharacteristics {
 public:
  QosCharacteristics();
  virtual ~QosCharacteristics();

  int QosCharacteristicsPresent();

  void set(const NonDynamic5qiDescriptor& nonDynamic5qiDescriptor);
  void get(
      std::optional<NonDynamic5qiDescriptor>& nonDynamic5qiDescriptor) const;

  void set(const Dynamic5qiDescriptor& dynamic5qiDescriptor);
  void get(std::optional<Dynamic5qiDescriptor>& dynamic5qiDescriptor) const;

  bool encode(Ngap_QosCharacteristics_t&) const;
  bool decode(const Ngap_QosCharacteristics_t&);

 private:
  std::optional<NonDynamic5qiDescriptor> m_NonDynamic5qiDescriptor;
  std::optional<Dynamic5qiDescriptor> m_Dynamic5qiDescriptor;
};
}  // namespace oai::ngap

#endif
