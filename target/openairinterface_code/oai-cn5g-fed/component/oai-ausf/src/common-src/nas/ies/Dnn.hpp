/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DNN_HPP_
#define _DNN_HPP_

#include "Type4NasIe.hpp"

constexpr uint8_t kDnnMinimumLength = 3;
constexpr uint8_t kDnnContentMinimumLength =
    kDnnMinimumLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kDnnMaximumLength = 102;
constexpr auto kDnnIeName           = "DNN";

namespace oai::nas {

class Dnn : public Type4NasIe {
 public:
  Dnn();
  Dnn(const bstring& dnn);
  Dnn(bool iei);
  virtual ~Dnn();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kDnnIeName; }

  void SetValue(const bstring& dnn);
  void GetValue(bstring& dnn) const;

 private:
  bstring dnn_;
};

}  // namespace oai::nas

#endif
