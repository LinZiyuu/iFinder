/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NAS_KEY_SET_IDENTIFIER_H
#define _NAS_KEY_SET_IDENTIFIER_H

#include "Type1NasIe.hpp"

constexpr auto kNasKeySetIdentifierName = "NAS Key Set Identifier";

namespace oai::nas {

class NasKeySetIdentifier : public Type1NasIe {
 public:
  NasKeySetIdentifier();
  NasKeySetIdentifier(uint8_t iei, bool tsc, uint8_t key_id);
  NasKeySetIdentifier(bool tsc,
                      uint8_t key_id);  // Default: low position
  virtual ~NasKeySetIdentifier();

  static std::string GetIeName() { return kNasKeySetIdentifierName; }

  void Set(bool high_pos);
  // void Set(bool tsc, uint8_t key_id);
  // void Set(bool tsc, uint8_t key_id, uint8_t iei);
  void Get(bool& tsc, uint8_t& key_id);

  void SetTypeOfSecurityContext(bool type);
  bool GetTypeOfSecurityContext() const;

  void SetNasKeyIdentifier(uint8_t id);
  uint8_t GetNasKeyIdentifier() const;

  uint8_t GetNgKsi() const;

 private:
  void SetValue() override;
  void GetValue() override;

  bool tsc_;
  uint8_t key_id_;
};

}  // namespace oai::nas

#endif
