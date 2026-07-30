/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _MICO_INDICATION_H
#define _MICO_INDICATION_H

#include "Type1NasIeFormatTv.hpp"

constexpr uint8_t kMicoIndicationIELength = 1;
constexpr auto kMicoIndicationIeName      = "MICO Indication";

namespace oai::nas {

class MicoIndication : public Type1NasIeFormatTv {
 public:
  MicoIndication();
  MicoIndication(uint8_t _iei, bool sprti, bool raai);
  MicoIndication(bool sprti, bool raai);
  virtual ~MicoIndication();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kMicoIndicationIeName; }

  void SetSprti(bool value);
  bool GetSprti() const;

  void SetRaai(bool value);
  bool GetRaai() const;

  void SetValue();

 private:
  bool sprti_;
  bool raai_;
};

}  // namespace oai::nas

#endif
