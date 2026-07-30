/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SECURITY_MODE_COMPLETE_H_
#define _SECURITY_MODE_COMPLETE_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class SecurityModeComplete : public Nas5gmmMessage {
 public:
  SecurityModeComplete();
  ~SecurityModeComplete();

  void SetHeader(uint8_t security_header_type);

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetImeisv(const IMEI_IMEISV_t& imeisv);
  bool GetImeisv(IMEI_IMEISV_t& imeisv) const;

  void SetNasMessageContainer(const bstring& value);
  bool GetNasMessageContainer(bstring& nas) const;

  void SetNonImeisv(const IMEI_IMEISV_t& imeisv);
  bool GetNonImeisv(IMEI_IMEISV_t& imeisv) const;

 private:
  NasMmPlainHeader ie_header_;                                   // Mandatory
  std::optional<_5gsMobileIdentity> ie_imeisv_;                  // Optional
  std::optional<NasMessageContainer> ie_nas_message_container_;  // Optional
  std::optional<_5gsMobileIdentity> ie_non_imeisvpei_;           // Optional
};

}  // namespace oai::nas

#endif
