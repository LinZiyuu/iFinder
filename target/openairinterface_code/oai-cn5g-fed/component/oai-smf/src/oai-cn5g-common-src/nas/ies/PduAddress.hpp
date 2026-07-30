/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_ADDRESS_H_
#define _PDU_ADDRESS_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kPduAddressMinimumLength = 7;
constexpr uint8_t kPduAddressContentMinimumLength =
    kPduAddressMinimumLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kPduAddressMaximumLength = 31;
constexpr auto kPduAddressIeName           = "PDU Address";

constexpr uint8_t kPduAddressPduSessionTypeIpv4   = 0b001;
constexpr uint8_t kPduAddressPduSessionTypeIpv6   = 0b010;
constexpr uint8_t kPduAddressPduSessionTypeIpv4v6 = 0b011;

namespace oai::nas {

class PduAddress : public Type4NasIe {
 public:
  PduAddress();
  PduAddress(uint8_t iei);
  virtual ~PduAddress();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() { return kPduAddressIeName; }
  bool Validate(int len) const;

  void SetSi6lla(bool si6lla);
  bool GetSi6lla() const;

  void SetPduSessionType(uint8_t pdu_session_type);
  uint8_t GetPduSessionType() const;

  void SetIpv4Address(struct in_addr ipv4_address);
  std::optional<struct in_addr> GetIpv4Address() const;

  void SetIpv6Address(struct in6_addr ipv6_address);
  std::optional<struct in6_addr> GetIpv6Address() const;

  void SetIpv4v6Address(
      struct in_addr ipv4_address, struct in6_addr ipv6_address);
  void GetIpv4v6Address(
      std::optional<struct in_addr>& ipv4_address,
      std::optional<struct in6_addr>& ipv6_address) const;

  void SetSmfIpv6LinkLocalAddress(struct in6_addr smf_ipv6_link_local_address);
  std::optional<struct in6_addr> GetSmfIpv6LinkLocalAddress() const;

 private:
  bool si6lla_;
  uint8_t pdu_session_type_;
  std::optional<struct in_addr> ipv4_address_;
  std::optional<struct in6_addr> ipv6_address_;
  std::optional<struct in6_addr> smf_ipv6_link_local_address_;
};

}  // namespace oai::nas

#endif
