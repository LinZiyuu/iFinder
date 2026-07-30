/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PROCEDURE_TRANSACTION_IDENTITY_H_
#define _PROCEDURE_TRANSACTION_IDENTITY_H_

#include "NasIe.hpp"

constexpr uint8_t kProcedureTransactionIdentityLength = 1;
constexpr auto kProcedureTransactionIdentityIeName =
    "Procedure Transaction Identity";

namespace oai::nas {

class ProcedureTransactionIdentity : public NasIe {
 public:
  ProcedureTransactionIdentity();
  ProcedureTransactionIdentity(uint8_t value);
  virtual ~ProcedureTransactionIdentity();

  bool Validate(int len) const override;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kProcedureTransactionIdentityIeName; }
  uint32_t GetIeLength() const override;

  void Set(uint8_t value);
  uint8_t Get() const;

 private:
  uint8_t value_;
};
}  // namespace oai::nas

#endif
