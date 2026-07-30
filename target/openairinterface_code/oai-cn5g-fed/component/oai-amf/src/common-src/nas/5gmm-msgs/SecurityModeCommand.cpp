/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SecurityModeCommand.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
SecurityModeCommand::SecurityModeCommand()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kSecurityModeCommand) {
  ie_imeisv_request_                     = std::nullopt;
  ie_eps_nas_security_algorithms_        = std::nullopt;
  ie_additional_5g_security_information_ = std::nullopt;
  ie_eap_message_                        = std::nullopt;
  ie_abba_                               = std::nullopt;
  ie_s1_ue_security_capability_          = std::nullopt;
}

//------------------------------------------------------------------------------
SecurityModeCommand::~SecurityModeCommand() {}

//------------------------------------------------------------------------------
uint32_t SecurityModeCommand::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  msg_len += ie_selected_nas_security_algorithms_.GetIeLength();
  // msg_len += ie_ng_ksi_.GetIeLength();
  msg_len += 1;  // 1/2 octet for ngKSI and 1/2 octet for Spare half octet
  msg_len += ie_ue_security_capability_.GetIeLength();
  if (ie_imeisv_request_.has_value())
    msg_len += ie_imeisv_request_.value().GetIeLength();
  if (ie_eps_nas_security_algorithms_.has_value())
    msg_len += ie_eps_nas_security_algorithms_.value().GetIeLength();
  if (ie_additional_5g_security_information_.has_value())
    msg_len += ie_additional_5g_security_information_.value().GetIeLength();
  if (ie_eap_message_.has_value())
    msg_len += ie_eap_message_.value().GetIeLength();
  if (ie_abba_.has_value()) msg_len += ie_abba_.value().GetIeLength();
  if (ie_s1_ue_security_capability_.has_value())
    msg_len += ie_s1_ue_security_capability_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetNasSecurityAlgorithms(
    uint8_t ciphering, uint8_t integrity) {
  ie_selected_nas_security_algorithms_.Set(ciphering, integrity);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetNgKsi(uint8_t tsc, uint8_t key_set_id) {
  ie_ng_ksi_.SetTypeOfSecurityContext(tsc);
  ie_ng_ksi_.SetNasKeyIdentifier(key_set_id);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetUeSecurityCapability(uint8_t ea, uint8_t ia) {
  ie_ue_security_capability_.Set(ea, ia);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetUeSecurityCapability(
    uint8_t ea, uint8_t ia, uint8_t eea, uint8_t eia) {
  ie_ue_security_capability_.Set(ea, ia, eea, eia);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetUeSecurityCapability(
    const UeSecurityCapability& ue_security_capability) {
  uint8_t eea = 0;
  uint8_t eia = 0;
  if (ue_security_capability.GetEea(eea) &&
      ue_security_capability.GetEia(eia)) {
    ie_ue_security_capability_.Set(
        ue_security_capability.GetEa(), ue_security_capability.GetIa(), eea,
        eia);
  } else {
    ie_ue_security_capability_.Set(
        ue_security_capability.GetEa(), ue_security_capability.GetIa());
  }
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetImeisvRequest(uint8_t value) {
  ie_imeisv_request_ = std::make_optional<ImeisvRequest>(value);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetEpsNasSecurityAlgorithms(
    uint8_t ciphering, uint8_t integrity) {
  ie_eps_nas_security_algorithms_ =
      std::make_optional<EpsNasSecurityAlgorithms>(ciphering, integrity);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetAdditional5gSecurityInformation(
    bool rinmr, bool hdp) {
  ie_additional_5g_security_information_ =
      std::make_optional<Additional5gSecurityInformation>(rinmr, hdp);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetEapMessage(bstring eap) {
  ie_eap_message_ = std::make_optional<EapMessage>(kIeiEapMessage, eap);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetAbba(uint8_t length, uint8_t* value) {
  ie_abba_ = std::make_optional<Abba>(kIeiAbba, length, value);
}

//------------------------------------------------------------------------------
void SecurityModeCommand::SetS1UeSecurityCapability(uint8_t eea, uint8_t eia) {
  ie_s1_ue_security_capability_ = std::make_optional<S1UeSecurityCapability>(
      kIeiS1UeSecurityCapability, eea, eia);
}

//------------------------------------------------------------------------------
int SecurityModeCommand::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding SecurityModeCommand message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // NAS security algorithms
  if ((encoded_ie_size = NasHelper::Encode(
           ie_selected_nas_security_algorithms_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // NgKSI
  if ((encoded_ie_size = NasHelper::Encode(
           ie_ng_ksi_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (encoded_ie_size == 0)
    encoded_size++;  // 1/2 octet for ngKSI, 1/2 for Spare half octet

  // UE security capability
  if ((encoded_ie_size = NasHelper::Encode(
           ie_ue_security_capability_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // IMEISV Request
  if ((encoded_ie_size = NasHelper::Encode(
           ie_imeisv_request_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // EPS NAS Security Algorithms
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eps_nas_security_algorithms_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Additional 5G security information
  if ((encoded_ie_size = NasHelper::Encode(
           ie_additional_5g_security_information_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // EAP message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // ABBA
  if ((encoded_ie_size = NasHelper::Encode(ie_abba_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Replayed S1 UE Security Capability
  if ((encoded_ie_size = NasHelper::Encode(
           ie_s1_ue_security_capability_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded SecurityModeCommand message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int SecurityModeCommand::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding SecurityModeCommand message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // NAS security algorithms
  if ((decoded_ie_size = NasHelper::Decode(
           ie_selected_nas_security_algorithms_, buf, len, decoded_size,
           false)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // NAS key set identifier
  if ((decoded_ie_size = NasHelper::Decode(
           ie_ng_ksi_, buf, len, decoded_size, false, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (decoded_ie_size == 0)
    decoded_size++;  // 1/2 octet for ngKSI, 1/2 for Spare half octet

  // UE security capability
  if ((decoded_ie_size = NasHelper::Decode(
           ie_ue_security_capability_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug("Decoded_size (%d)", decoded_size);

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  bool flag = false;
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("IEI 0x%x", octet);
    switch ((octet & 0xf0) >> 4) {
      case kIeiImeisvRequest: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiImeisvRequest);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_imeisv_request_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
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
      case kIeiEpsNasSecurityAlgorithms: {
        oai::logger::logger_common::nas().debug(
            "decoding IEI 0x%x", kIeiEpsNasSecurityAlgorithms);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_eps_nas_security_algorithms_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiAdditional5gSecurityInformation: {
        oai::logger::logger_common::nas().debug(
            "decoding IEI 0x%x", kIeiAdditional5gSecurityInformation);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_additional_5g_security_information_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiEapMessage: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiEapMessage);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_eap_message_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiAbba: {
        oai::logger::logger_common::nas().debug("Decoding IEI 0x%x", kIeiAbba);
        if ((decoded_ie_size =
                 NasHelper::Decode(ie_abba_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiS1UeSecurityCapability: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiS1UeSecurityCapability);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_s1_ue_security_capability_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
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
      "Decoded SecurityModeCommand message len (%d)", decoded_size);
  return decoded_size;
}
