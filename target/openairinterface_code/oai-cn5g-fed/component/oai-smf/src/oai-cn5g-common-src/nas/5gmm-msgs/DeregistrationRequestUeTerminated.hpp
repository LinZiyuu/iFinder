/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DEREGISTRATION_REQUEST_UE_TERMINATED_H_
#define _DEREGISTRATION_REQUEST_UE_TERMINATED_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class DeregistrationRequestUeTerminated : public Nas5gmmMessage {
 public:
  DeregistrationRequestUeTerminated();
  ~DeregistrationRequestUeTerminated();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void SetDeregistrationType(uint8_t dereg_type);
  void GetDeregistrationType(uint8_t& dereg_type) const;

  void SetDeregistrationType(const _5gs_deregistration_type_t& type);
  void GetDeregistrationType(_5gs_deregistration_type_t& type) const;

  void Set5gmmCause(uint8_t value);
  std::optional<_5gmmCause> Get5gmmCause() const;

  void SetT3346Value(uint8_t value);
  std::optional<GprsTimer2> GetT3346Value() const;

  void SetRejectedNssai(const std::vector<RejectedSNssai>& nssai);
  std::optional<RejectedNssai> GetRejectedNssai() const;

  // TODO:CagInformationList

 private:
  NasMmPlainHeader ie_header_;                      // Mandatory
  _5gsDeregistrationType ie_deregistration_type_;   // Mandatory
  std::optional<_5gmmCause> ie_5gmm_cause_;         // Optional
  std::optional<GprsTimer2> ie_t3346_value_;        // Optional
  std::optional<RejectedNssai> ie_rejected_nssai_;  // Optional
  // TODO: CagInformationList ie_cag_information_list ; //Optional
};

}  // namespace oai::nas

#endif
