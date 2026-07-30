/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DataForwardingNotPossible.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DataForwardingNotPossible::DataForwardingNotPossible() {}

//------------------------------------------------------------------------------
DataForwardingNotPossible::~DataForwardingNotPossible() {}

//------------------------------------------------------------------------------
void DataForwardingNotPossible::set(const long& value) {
  m_DataForwardingNotPossible = value;
}

//------------------------------------------------------------------------------
void DataForwardingNotPossible::get(long& value) const {
  value = m_DataForwardingNotPossible;
}
//------------------------------------------------------------------------------
bool DataForwardingNotPossible::encode(
    Ngap_DataForwardingNotPossible_t& value) const {
  // TODO:
  value = Ngap_DataForwardingNotPossible_data_forwarding_not_possible;

  return true;
}

//------------------------------------------------------------------------------
bool DataForwardingNotPossible::decode(
    const Ngap_DataForwardingNotPossible_t& value) {
  // TODO:
  if (value != Ngap_DataForwardingNotPossible_data_forwarding_not_possible)
    return false;

  return true;
}

}  // namespace oai::ngap
