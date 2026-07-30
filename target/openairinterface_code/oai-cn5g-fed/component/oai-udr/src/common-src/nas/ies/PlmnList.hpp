/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PLMN_LIST_H_
#define _PLMN_LIST_H_

#include "Struct.hpp"
#include "Type4NasIe.hpp"

constexpr uint8_t kPlmnListMinimumLength = 5;
constexpr uint8_t kPlmnListContentMinimumLength =
    kPlmnListMinimumLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kPlmnListMaximumLength = 47;
constexpr auto kPlmnListIeName           = "PLMN List";

namespace oai::nas {

class PlmnList : public Type4NasIe {
 public:
  PlmnList();
  PlmnList(uint8_t iei);
  virtual ~PlmnList();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kPlmnListIeName; }

  void Set(uint8_t iei, const std::vector<nas_plmn_t>& list);
  void Get(std::vector<nas_plmn_t>& list) const;

 private:
  std::vector<nas_plmn_t> plmn_list_;
};
}  // namespace oai::nas

#endif
