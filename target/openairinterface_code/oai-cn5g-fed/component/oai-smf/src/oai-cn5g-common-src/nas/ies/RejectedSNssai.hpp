/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _REJECTED_SNSSAI_H_
#define _REJECTED_SNSSAI_H_

#include <stdint.h>

#include <optional>

namespace oai::nas {

class RejectedSNssai {
 public:
  RejectedSNssai();
  RejectedSNssai(uint8_t cause, uint8_t sst, uint32_t sd);
  virtual ~RejectedSNssai();

  int Encode(uint8_t* buf, int len) const;
  int Decode(const uint8_t* const buf, int len);

  uint8_t GetLength() const;

  void SetSST(uint8_t sst);
  uint8_t GetSST() const;
  void GetSST(uint8_t& sst) const;

  void SetSd(uint32_t sd);
  bool GetSd(uint32_t& sd) const;
  void GetSd(std::optional<uint32_t>& sd) const;

  void SetCause(uint8_t cause);
  uint8_t GetCause() const;
  void GetCause(uint8_t& cause) const;

 private:
  uint8_t length_;
  uint8_t cause_;
  uint8_t sst_;
  std::optional<uint32_t> sd_;
};

}  // namespace oai::nas

#endif
