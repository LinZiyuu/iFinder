/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GNB_ID_H_
#define _GNB_ID_H_

#include <optional>

#include "NgapIesStruct.hpp"

extern "C" {
#include "Ngap_GNB-ID.h"
}

namespace oai::ngap {

constexpr uint8_t NGAP_GNB_ID_SIZE_MAX = 32;
constexpr uint8_t NGAP_GNB_ID_SIZE_MIN = 22;

class GnbId {
 public:
  GnbId();
  virtual ~GnbId();

  void set(const gNBId_t& gnbId);
  bool get(gNBId_t& gnbId) const;

  bool set(const uint32_t& id, const uint8_t& bitLength);
  // long get() const;
  bool get(uint32_t& id) const;

  bool encode(Ngap_GNB_ID_t&) const;
  bool decode(const Ngap_GNB_ID_t&);

 private:
  std::optional<gNBId_t> m_GnbId;  // 22bits to 32bits
  Ngap_GNB_ID_PR m_Present;
};

}  // namespace oai::ngap

#endif
