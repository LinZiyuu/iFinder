/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef EXTENDED_PROTOCOL_DISCRIMINATOR_H_
#define EXTENDED_PROTOCOL_DISCRIMINATOR_H_

#include "NasIe.hpp"

constexpr uint8_t kExtendedProtocolDiscriminatorLength = 1;
constexpr auto kExtendedProtocolDiscriminatorIeName =
    "Extended Protocol Discriminator";

namespace oai::nas {

class ExtendedProtocolDiscriminator : public NasIe {
 public:
  ExtendedProtocolDiscriminator(){};  // TODO: = delete;
  ExtendedProtocolDiscriminator(uint8_t epd);
  virtual ~ExtendedProtocolDiscriminator();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() {
    return kExtendedProtocolDiscriminatorIeName;
  }

  uint32_t GetIeLength() const override;
  bool Validate(int len) const override;

  void Set(uint8_t epd);
  void Get(uint8_t& epd) const;
  uint8_t Get() const;

 private:
  uint8_t epd_;
};

}  // namespace oai::nas

#endif
