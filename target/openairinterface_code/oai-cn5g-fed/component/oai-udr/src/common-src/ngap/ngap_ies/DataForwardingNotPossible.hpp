/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DATA_FORWARDING_NOT_POSSIBLE_H_
#define _DATA_FORWARDING_NOT_POSSIBLE_H_

extern "C" {
#include "Ngap_DataForwardingNotPossible.h"
}

namespace oai::ngap {

class DataForwardingNotPossible {
 public:
  DataForwardingNotPossible();
  virtual ~DataForwardingNotPossible();

  void set(const long& value);
  void get(long& value) const;

  bool encode(Ngap_DataForwardingNotPossible_t& value) const;
  bool decode(const Ngap_DataForwardingNotPossible_t& value);

 private:
  long m_DataForwardingNotPossible;
};

}  // namespace oai::ngap

#endif
