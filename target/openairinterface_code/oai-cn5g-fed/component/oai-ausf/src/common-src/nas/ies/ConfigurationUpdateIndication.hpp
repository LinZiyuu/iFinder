/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _CONFIGURATION_UPDATE_INDICATION_H_
#define _CONFIGURATION_UPDATE_INDICATION_H_

#include "Type1NasIe.hpp"

constexpr auto kConfigurationUpdateIndicationIeName =
    "Configuration Update Indication";

namespace oai::nas {

class ConfigurationUpdateIndication : public Type1NasIe {
 public:
  ConfigurationUpdateIndication();
  ConfigurationUpdateIndication(bool red, bool ack);
  virtual ~ConfigurationUpdateIndication();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() {
    return kConfigurationUpdateIndicationIeName;
  }

  void SetRed(bool value);
  void GetRed(bool& value) const;

  void SetAck(bool value);
  void GetAck(bool& value) const;

 private:
  bool red_;
  bool ack_;

  void SetValue() override;
  void GetValue() override;
};

}  // namespace oai::nas

#endif
