/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NgEnbId.hpp"

extern "C" {
#include "conversions.h"
}

namespace oai::ngap {

NgEnbId::NgEnbId() {
  m_Present = Ngap_NgENB_ID_PR_NOTHING;
}

//------------------------------------------------------------------------------
NgEnbId::~NgEnbId() {
  m_Present = Ngap_NgENB_ID_PR_NOTHING;
}

//------------------------------------------------------------------------------
void NgEnbId::get(uint32_t& id, Ngap_NgENB_ID_PR& present) const {
  present = m_Present;
  switch (m_Present) {
    case Ngap_NgENB_ID_PR_macroNgENB_ID: {
      id = m_Id.macro_ngenb_id;
    } break;
    case Ngap_NgENB_ID_PR_shortMacroNgENB_ID: {
      id = m_Id.short_macro_ngENB_id;
    } break;
    case Ngap_NgENB_ID_PR_longMacroNgENB_ID: {
      id = m_Id.short_macro_ngENB_id;
    } break;
    default: {
      present = Ngap_NgENB_ID_PR_NOTHING;
    }
  }
}

//------------------------------------------------------------------------------
void NgEnbId::set(const uint32_t& id, const Ngap_NgENB_ID_PR& present) {
  m_Present = present;
  switch (present) {
    case Ngap_NgENB_ID_PR_macroNgENB_ID: {
      m_Id.macro_ngenb_id = id;
    } break;
    case Ngap_NgENB_ID_PR_shortMacroNgENB_ID: {
      m_Id.short_macro_ngENB_id = id;
    } break;
    case Ngap_NgENB_ID_PR_longMacroNgENB_ID: {
      m_Id.short_macro_ngENB_id = id;
    } break;
    default: {
      m_Present = Ngap_NgENB_ID_PR_NOTHING;
    }
  }
}

//------------------------------------------------------------------------------
bool NgEnbId::encode(Ngap_NgENB_ID_t& ng_enb_id) const {
  ng_enb_id.present = m_Present;
  switch (m_Present) {
    case Ngap_NgENB_ID_PR_macroNgENB_ID: {
      INT24_TO_BIT_STRING(
          m_Id.macro_ngenb_id && 0x00ffffff, &ng_enb_id.choice.macroNgENB_ID,
          20);
    } break;
    case Ngap_NgENB_ID_PR_shortMacroNgENB_ID: {
      INT24_TO_BIT_STRING(
          m_Id.short_macro_ngENB_id && 0x00ffffff,
          &ng_enb_id.choice.shortMacroNgENB_ID, 18);
    } break;
    case Ngap_NgENB_ID_PR_longMacroNgENB_ID: {
      INT24_TO_BIT_STRING(
          m_Id.long_macro_ngENB_id && 0x00ffffff,
          &ng_enb_id.choice.longMacroNgENB_ID, 21);
    } break;
    default: {
      ng_enb_id.present = Ngap_NgENB_ID_PR_NOTHING;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
bool NgEnbId::decode(const Ngap_NgENB_ID_t& ng_enb_id) {
  m_Present = ng_enb_id.present;
  switch (m_Present) {
    case Ngap_NgENB_ID_PR_macroNgENB_ID: {
      BIT_STRING_TO_INT24(&ng_enb_id.choice.macroNgENB_ID, m_Id.macro_ngenb_id);
    } break;
    case Ngap_NgENB_ID_PR_shortMacroNgENB_ID: {
      BIT_STRING_TO_INT24(
          &ng_enb_id.choice.shortMacroNgENB_ID, m_Id.short_macro_ngENB_id);
    } break;
    case Ngap_NgENB_ID_PR_longMacroNgENB_ID: {
      BIT_STRING_TO_INT24(
          &ng_enb_id.choice.shortMacroNgENB_ID, m_Id.long_macro_ngENB_id);
    } break;
    default: {
      m_Present = Ngap_NgENB_ID_PR_NOTHING;
    }
  }
  return true;
}

}  // namespace oai::ngap
