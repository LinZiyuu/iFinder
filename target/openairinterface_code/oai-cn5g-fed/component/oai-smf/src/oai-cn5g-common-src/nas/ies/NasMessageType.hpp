/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NAS_MESSAGE_TYPE_H_
#define _NAS_MESSAGE_TYPE_H_

#include "NasIe.hpp"

constexpr uint8_t kNasMessageTypeIeSize = 1;
constexpr auto kNasMessageTypeIeName    = "NAS Message Type";

namespace oai::nas {

class NasMessageType : public NasIe {
 public:
  NasMessageType() : NasIe(){};  // TODO: = delete;
  NasMessageType(uint8_t message_type);
  virtual ~NasMessageType(){};

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kNasMessageTypeIeName; }

  bool Validate(int len) const override;
  uint32_t GetIeLength() const override;

  void Set(uint8_t message_type);
  void Get(uint8_t& message_type) const;
  uint8_t Get() const;

 private:
  uint8_t message_type_;
};

}  // namespace oai::nas

#endif
