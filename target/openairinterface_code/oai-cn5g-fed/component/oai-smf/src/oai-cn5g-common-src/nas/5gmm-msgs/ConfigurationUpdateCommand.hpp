/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef CONFIGURATION_UPDATE_COMMAND_H_
#define CONFIGURATION_UPDATE_COMMAND_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class ConfigurationUpdateCommand : public Nas5gmmMessage {
 public:
  ConfigurationUpdateCommand();
  ~ConfigurationUpdateCommand();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);
  void GetSecurityHeaderType(uint8_t security_header_type);
  bool VerifyHeader();

  void SetConfigurationUpdateIndication(
      const ConfigurationUpdateIndication& configuration_update_indication);
  void GetConfigurationUpdateIndication(
      std::optional<ConfigurationUpdateIndication>&
          configuration_update_indication);

  void Set5gGuti(
      const std::string& mcc, const std::string& mnc, uint8_t amf_region_id,
      uint16_t amf_set_id, uint8_t amf_pointer, uint32_t tmsi);
  // TODO: Get

  void SetFullNameForNetwork(const NetworkName& name);
  void SetFullNameForNetwork(const std::string& text_string);
  void GetFullNameForNetwork(std::optional<NetworkName>& name) const;

  void SetShortNameForNetwork(const NetworkName& name);
  void SetShortNameForNetwork(const std::string& text_string);
  void GetShortNameForNetwork(NetworkName& name) const;

 private:
  NasMmPlainHeader ie_header_;  // Mandatory
  // Configuration update indication
  std::optional<ConfigurationUpdateIndication>
      ie_configuration_update_indication_;        // Optional
  std::optional<_5gsMobileIdentity> ie_5g_guti_;  // Optional
  // TODO: TAI list (Optional)
  // TODO: Allowed NSSAI (Optional)
  // TODO: Service area list (Optional)
  // Full name for network (Optional)
  std::optional<NetworkName> ie_full_name_for_network_;  // Optional
  // Short name for network
  std::optional<NetworkName> ie_short_name_for_network_;  // Optional
  // TODO: Local time zone (Optional)
  // TODO: Universal time and local time zone (Optional)
  // TODO: Network daylight saving time (Optional)
  // TODO: LADN information (Optional)
  // TODO: MICO indication (Optional)
  // TODO: Network slicing indication (Optional)
  // TODO: Configured NSSAI (Optional)
  // TODO: Rejected NSSAI (Optional)
  // TODO: Operator-defined access category definitions (Optional)
  // TODO: SMS indication (Optional)
  // TODO: T3447 value (Optional)
  // TODO: CAG information list (Rel 16.4.1) (Optional)
  // TODO: UE radio capability ID (Rel 16.4.1) (Optional)
  // TODO: UE radio capability ID deletion indication (Rel 16.4.1) (Optional)
  // TODO: 5GS registration result (Rel 16.4.1) (Optional)
  // TODO: Truncated 5G-S-TMSI configuration (Rel 16.4.1) (Optional)
  // TODO: Additional configuration indication (Rel 16.14.0) (Optional)
};

}  // namespace oai::nas

#endif
