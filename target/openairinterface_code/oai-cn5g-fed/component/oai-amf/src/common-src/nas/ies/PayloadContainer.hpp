/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PAYLOAD_CONTAINER_H_
#define _PAYLOAD_CONTAINER_H_

#include "Type6NasIe.hpp"
#include "Struct.hpp"

constexpr uint8_t kPayloadContainerMinimumLength = 4;
constexpr uint8_t kPayloadContainerContentMinimumLength =
    kPayloadContainerMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint32_t kPayloadContainerMaximumLength = 65538;
constexpr auto kPayloadContainerIeName            = "Payload Container";

namespace oai::nas {
class PayloadContainer : public Type6NasIe {
 public:
  PayloadContainer();
  PayloadContainer(uint8_t iei);
  PayloadContainer(const bstring& b);
  PayloadContainer(uint8_t iei, const bstring& b);
  PayloadContainer(const std::vector<PayloadContainerEntry>& content);
  PayloadContainer(
      uint8_t iei, const std::vector<PayloadContainerEntry>& content);
  virtual ~PayloadContainer();

  int Encode(uint8_t* buf, int len, uint8_t type) const;
  int Decode(const uint8_t* const buf, int len, bool is_iei, uint8_t type);

  static std::string GetIeName() { return kPayloadContainerIeName; }

  void SetValue(const bstring& cnt);
  bool GetValue(bstring& cnt) const;

  void SetValue(const std::vector<PayloadContainerEntry>& content);
  bool GetValue(std::vector<PayloadContainerEntry>& content) const;

 private:
  std::optional<bstring> content_;
  std::optional<std::vector<PayloadContainerEntry>> contents_;
};

}  // namespace oai::nas

#endif
