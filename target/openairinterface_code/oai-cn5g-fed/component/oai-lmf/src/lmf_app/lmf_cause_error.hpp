/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_LMF_CAUSE_ERROR_HPP_SEEN
#define FILE_LMF_CAUSE_ERROR_HPP_SEEN

#include "Cause.h"
#include "ProtocolIE-ID.h"
#include "lmf_sbi_helper.hpp"
#include "logger.hpp"

namespace oai::lmf::app {

class CauseError {
 public:
  asn_INTEGER_enum_map_t const *radio_network = nullptr, *protocol = nullptr,
                               *misc = nullptr;

  template<typename T, typename U>
  static CauseError parse(T const& failure, U const& present) {
    CauseError err;
    for (auto const& failureIe : failure.protocolIEs) {
      switch (failureIe->id) {
        case ProtocolIE_ID_id_Cause: {
          auto const& value = failureIe->value;
          if (value.present != present) {
            oai::lmf::api::lmf_sbi_helper::throwHttpError(
                "CauseError", "unexpected present");
          }
          auto const& cause = value.choice.Cause;
          err.parse_(cause);
        } break;

        case ProtocolIE_ID_id_CriticalityDiagnostics: {
        } break;

        default:;  // could be measurement-id in case of measurement-failure
      }
    }
    err.log();
    return err;
  }

  void parse_(Cause_t const& cause) {
    switch (cause.present) {
      case Cause_PR_radioNetwork: {
        auto const& radioNetwork = cause.choice.radioNetwork;
        this->radio_network      = INTEGER_map_value2enum(
            &asn_SPC_CauseRadioNetwork_specs_1, radioNetwork);
      } break;

      case Cause_PR_protocol: {
        auto const& protocol = cause.choice.protocol;
        this->protocol =
            INTEGER_map_value2enum(&asn_SPC_CauseProtocol_specs_1, protocol);
      } break;

      case Cause_PR_misc: {
        auto const& misc = cause.choice.misc;
        this->misc = INTEGER_map_value2enum(&asn_SPC_CauseMisc_specs_1, misc);
      } break;

      default:
        Logger::lmf_app().warn(
            "trpInformationFailure: unknwon cause IE id: %d", cause.present);
    }
  }

  std::string msg() const {
    return fmt::sprintf(
        "failure: radio_network: %s, protocol: %s, misc: %s",
        this->radio_network ? this->radio_network->enum_name : "not set",
        this->protocol ? this->protocol->enum_name : "not set",
        this->misc ? this->misc->enum_name : "not set");
  }

  void log() const { Logger::lmf_app().error(this->msg()); }
};

}  // namespace oai::lmf::app

#endif  // FILE_LMF_CAUSE_ERROR_HPP_SEEN
