/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NetworkSlicingIndication.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
NetworkSlicingIndication::NetworkSlicingIndication()
    : Type1NasIeFormatTv(), dcni_(), nssci_() {
  SetValue();
}

//------------------------------------------------------------------------------
NetworkSlicingIndication::NetworkSlicingIndication(uint8_t iei)
    : Type1NasIeFormatTv(iei) {
  dcni_  = false;
  nssci_ = false;
  SetValue();
}

//------------------------------------------------------------------------------
NetworkSlicingIndication::NetworkSlicingIndication(bool dcni, bool nssci)
    : Type1NasIeFormatTv() {
  dcni_  = dcni;
  nssci_ = nssci;
  SetValue();
}

//------------------------------------------------------------------------------
NetworkSlicingIndication::NetworkSlicingIndication(
    uint8_t iei, bool dcni, bool nssci)
    : Type1NasIeFormatTv(iei) {
  dcni_  = dcni;
  nssci_ = nssci;
  SetValue();
}

//------------------------------------------------------------------------------
NetworkSlicingIndication::~NetworkSlicingIndication() {}

//------------------------------------------------------------------------------
void NetworkSlicingIndication::SetValue() {
  value_ = 0x0f | (dcni_ << 1) | nssci_;
}

//------------------------------------------------------------------------------
void NetworkSlicingIndication::GetValue() {
  dcni_  = value_ & 0x02;
  nssci_ = value_ & 0x01;
}

//------------------------------------------------------------------------------
void NetworkSlicingIndication::SetDcni(bool value) {
  dcni_ = value;
  SetValue();
}

//------------------------------------------------------------------------------
void NetworkSlicingIndication::SetNssci(bool value) {
  nssci_ = value;
  SetValue();
}

//------------------------------------------------------------------------------
bool NetworkSlicingIndication::GetDcni() const {
  return dcni_;
}

//------------------------------------------------------------------------------
bool NetworkSlicingIndication::GetNssci() const {
  return nssci_;
}

//------------------------------------------------------------------------------
int NetworkSlicingIndication::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  encoded_size     = Type1NasIeFormatTv::Encode(buf, len);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int NetworkSlicingIndication::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());
  int decoded_size = 0;
  decoded_size     = Type1NasIeFormatTv::Decode(buf, len, is_iei);
  // Get DCNI/NSSCI from value
  GetValue();

  oai::logger::logger_common::nas().debug(
      "DCNI 0x%x, NSSCI 0x%x", dcni_, nssci_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
