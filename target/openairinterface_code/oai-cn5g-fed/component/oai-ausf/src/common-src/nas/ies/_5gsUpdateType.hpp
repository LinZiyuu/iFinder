/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_UPDATE_TYPE_H
#define _5GS_UPDATE_TYPE_H

#include "Type4NasIe.hpp"

constexpr uint8_t k5gsUpdateTypeLength = 3;
constexpr uint8_t k5gsUpdateTypeContentLength =
    k5gsUpdateTypeLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr auto k5gsUpdateTypeIeName = "5GS Update Type";

namespace oai::nas {

class _5gsUpdateType : public Type4NasIe {
 public:
  _5gsUpdateType();
  _5gsUpdateType(
      uint8_t eps_PNB_CIoT, uint8_t _5gs_PNB_CIoT, bool ng_RAN, bool sms);
  virtual ~_5gsUpdateType();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return k5gsUpdateTypeIeName; }

  void SetEpsPnbCiot(uint8_t value);
  uint8_t GetEpsPnbCiot() const;

  void Set5gsPnbCiot(uint8_t value);
  uint8_t Get5gsPnbCiot() const;

  void SetNgRan(uint8_t value);
  bool GetNgRan() const;

  void SetSms(uint8_t value);
  bool GetSms() const;

 private:
  uint8_t eps_pnb_ciot_;   // bit 4,5
  uint8_t _5gs_pnb_ciot_;  // bit 2,3
  bool ng_ran_;            // bit 1
  bool sms_;               // bit 0
};

}  // namespace oai::nas

#endif
