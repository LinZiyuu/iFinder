/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __5GSM_CAUSE_H
#define __5GSM_CAUSE_H

#include "Type3NasIe.hpp"

enum class _5gsmCauseEnum {
  kOperatorDeterminedBarring               = 0b00001000,
  kInsufficientResources                   = 0b00011010,
  kMissingOrUnknownDnn                     = 0b00011011,
  kUnknownPduSessionType                   = 0b00011100,
  kUserAuthenticationOrAuthorizationFailed = 0b00011101,
  kRequestRejectedUnspecified              = 0b00011111,
  kServiceOptionNotSupported               = 0b00100000,
  kRequestedServiceOptionNotSubscribed     = 0b01000001,
  kPtiAlreadyInUse                         = 0b00100011,
  kRegularDeactivation                     = 0b00100100,
  kNetworkFailure                          = 0b00100110,
  kReactivationRequested                   = 0b00100111,
  kSemanticErrorInTheTftOperation          = 0b00101001,
  kSyntacticalErrorInTheTftOperation       = 0b00101010,
  kInvalidPduSessionIdentity               = 0b00101011,
  kSemanticErrorsInPacketFilter_s          = 0b00101100,
  kSyntacticalErrorInPacketFilter_s        = 0b00101101,
  kOutOfLadnServiceArea                    = 0b00101110,
  kPtiMismatch                             = 0b00101111,
  kPduSessionTypeIpv4OnlyAllowed           = 0b00110010
  // TODO:
};

constexpr uint8_t k5gsmCauseMinimumLength = 1;
constexpr uint8_t k5gsmCauseMaximumLength = 2;

constexpr auto k5gsmCauseIeName = "5GSM Cause";

namespace oai::nas {

class _5gsmCause : public Type3NasIe {
 public:
  _5gsmCause();
  _5gsmCause(uint8_t iei);
  _5gsmCause(uint8_t _iei, uint8_t value);
  virtual ~_5gsmCause() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return k5gsmCauseIeName; }
  uint32_t GetIeLength() const override;

  void Set(uint8_t _iei, uint8_t value);

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
  uint8_t value_;
};

}  // namespace oai::nas

#endif
