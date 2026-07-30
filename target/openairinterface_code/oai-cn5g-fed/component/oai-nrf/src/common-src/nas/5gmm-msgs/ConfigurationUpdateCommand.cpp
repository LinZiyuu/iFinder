/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ConfigurationUpdateCommand.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ConfigurationUpdateCommand::ConfigurationUpdateCommand()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kConfigurationUpdateCommand) {
  ie_configuration_update_indication_ = std::nullopt;
  ie_5g_guti_                         = std::nullopt;
  ie_full_name_for_network_           = std::nullopt;
  ie_short_name_for_network_          = std::nullopt;
}

//------------------------------------------------------------------------------
ConfigurationUpdateCommand::~ConfigurationUpdateCommand() {}

//------------------------------------------------------------------------------
uint32_t ConfigurationUpdateCommand::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  if (ie_configuration_update_indication_.has_value())
    msg_len += ie_configuration_update_indication_.value().GetIeLength();
  if (ie_5g_guti_.has_value()) msg_len += ie_5g_guti_.value().GetIeLength();
  if (ie_full_name_for_network_.has_value())
    msg_len += ie_full_name_for_network_.value().GetIeLength();
  if (ie_short_name_for_network_.has_value())
    msg_len += ie_short_name_for_network_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::SetConfigurationUpdateIndication(
    const ConfigurationUpdateIndication& configuration_update_indication) {
  ie_configuration_update_indication_ =
      std::make_optional<ConfigurationUpdateIndication>(
          configuration_update_indication);
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::GetConfigurationUpdateIndication(
    std::optional<ConfigurationUpdateIndication>&
        configuration_update_indication) {
  configuration_update_indication = ie_configuration_update_indication_;
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::Set5gGuti(
    const std::string& mcc, const std::string& mnc, uint8_t amf_region_id,
    uint16_t amf_set_id, uint8_t amf_pointer, uint32_t tmsi) {
  _5gsMobileIdentity ie_5g_guti_tmp = {};
  ie_5g_guti_tmp.SetIei(kIei5gGuti);
  ie_5g_guti_tmp.Set5gGuti(
      mcc, mnc, amf_region_id, amf_set_id, amf_pointer, tmsi);
  ie_5g_guti_ = std::optional<_5gsMobileIdentity>(ie_5g_guti_tmp);
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::SetFullNameForNetwork(
    const NetworkName& name) {
  ie_full_name_for_network_ = std::optional<NetworkName>(name);
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::SetFullNameForNetwork(
    const std::string& text_string) {
  NetworkName full_name_for_network_tmp;
  full_name_for_network_tmp.SetIei(kIeiFullNameForNetwork);
  full_name_for_network_tmp.SetCodingScheme(0);
  full_name_for_network_tmp.SetAddCI(0);
  full_name_for_network_tmp.SetNumberOfSpareBits(
      0x07);  // TODO: remove hardcoded value
  full_name_for_network_tmp.SetTextString(text_string);
  ie_full_name_for_network_ =
      std::optional<NetworkName>(full_name_for_network_tmp);
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::GetFullNameForNetwork(
    std::optional<NetworkName>& name) const {
  name = ie_full_name_for_network_;
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::SetShortNameForNetwork(
    const std::string& text_string) {
  NetworkName short_name_for_network_tmp;
  short_name_for_network_tmp.SetIei(kIeiShortNameForNetwork);  // TODO
  short_name_for_network_tmp.SetCodingScheme(0);
  short_name_for_network_tmp.SetAddCI(0);
  short_name_for_network_tmp.SetNumberOfSpareBits(
      0x07);  // TODO: remove hardcoded value
  short_name_for_network_tmp.SetTextString(text_string);
  ie_short_name_for_network_ =
      std::optional<NetworkName>(short_name_for_network_tmp);
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::SetShortNameForNetwork(
    const NetworkName& name) {
  ie_short_name_for_network_ = std::optional<NetworkName>(name);
}

//------------------------------------------------------------------------------
void ConfigurationUpdateCommand::GetShortNameForNetwork(
    NetworkName& name) const {}

//------------------------------------------------------------------------------
int ConfigurationUpdateCommand::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding ConfigurationUpdateCommand message");

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  if ((encoded_ie_size = NasHelper::Encode(
           ie_configuration_update_indication_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((encoded_ie_size = NasHelper::Encode(
           ie_5g_guti_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((encoded_ie_size = NasHelper::Encode(
           ie_full_name_for_network_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if ((encoded_ie_size = NasHelper::Encode(
           ie_short_name_for_network_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded ConfigurationUpdateCommand message (len %d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ConfigurationUpdateCommand::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding ConfigurationUpdateCommand message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  bool flag = false;
  while ((octet != 0x0)) {
    switch ((octet & 0xf0) >> 4) {
      case kIeiConfigurationUpdateIndication: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiConfigurationUpdateIndication);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_configuration_update_indication_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      default: {
        flag = true;
      }
    }

    switch (octet) {
      case kIeiFullNameForNetwork: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiFullNameForNetwork);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_full_name_for_network_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiShortNameForNetwork: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiShortNameForNetwork);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_short_name_for_network_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      default: {
        // TODO:
        if (flag) {
          oai::logger::logger_common::nas().warn(
              "Unknown IEI 0x%x, stop decoding...", octet);
          // Stop decoding
          octet = 0x00;
        }
      } break;
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded ConfigurationUpdateCommand message (len %d)", decoded_size);
  return decoded_size;
}
