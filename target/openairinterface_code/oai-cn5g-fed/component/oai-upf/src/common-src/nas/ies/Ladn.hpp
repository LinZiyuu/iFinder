/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _LADN_H_
#define _LADN_H_

#include "Type6NasIe.hpp"
#include "_5gsTrackingAreaIdList.hpp"
#include "Dnn.hpp"

namespace oai::nas {
using namespace oai::nas;

class Ladn {
 public:
  Ladn();
  virtual ~Ladn();

  int Encode(uint8_t* buf, int len) const;
  int Decode(uint8_t* buf, int len);

  uint32_t GetLength() const;

  void Set(const oai::nas::Dnn& value);
  void Set(const _5gsTrackingAreaIdList& value);

 private:
  Dnn dnn_;
  _5gsTrackingAreaIdList ta_list_;
};

}  // namespace oai::nas

#endif
