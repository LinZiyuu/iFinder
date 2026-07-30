/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RAN_NODE_NAME_H_
#define _RAN_NODE_NAME_H_

extern "C" {
#include "Ngap_RANNodeName.h"
}

#include <string>

constexpr uint8_t RAN_NODE_NAME_SIZE_MAX = 150;
namespace oai::ngap {

class RanNodeName {
 public:
  RanNodeName();
  virtual ~RanNodeName();

  bool set(const std::string& value);
  void get(std::string& value) const;

  bool encode(Ngap_RANNodeName_t&) const;
  bool decode(const Ngap_RANNodeName_t&);

 private:
  std::string m_RanNodeName;
};

}  // namespace oai::ngap

#endif
