/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NETWORK_SLICING_INDICATION_H_
#define _NETWORK_SLICING_INDICATION_H_

#include "Type1NasIeFormatTv.hpp"

constexpr uint8_t kNetworkSlicingIndicationLength = 1;
constexpr auto kNetworkSlicingIndicationIeName = "Network Slicing Indication";

namespace oai::nas {

class NetworkSlicingIndication : public Type1NasIeFormatTv {
 public:
  NetworkSlicingIndication();
  NetworkSlicingIndication(uint8_t iei);
  NetworkSlicingIndication(uint8_t iei, bool dcni, bool nssci);
  NetworkSlicingIndication(bool dcni, bool nssci);
  virtual ~NetworkSlicingIndication();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kNetworkSlicingIndicationIeName; }

  void SetValue();
  void GetValue();

  void SetDcni(bool value);
  bool GetDcni() const;

  void SetNssci(bool value);
  bool GetNssci() const;

 private:
  bool dcni_;
  bool nssci_;
};
}  // namespace oai::nas

#endif
