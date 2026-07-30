/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UP_NGU_UP_TNL_MODIFY_ITEM_H_
#define _UP_NGU_UP_TNL_MODIFY_ITEM_H_

#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_UPTransportLayerInformation.h"
#include "Ngap_UL-NGU-UP-TNLModifyItem.h"
}

namespace oai::ngap {

class UlNgUUpTnlModifyItem {
 public:
  UlNgUUpTnlModifyItem();
  virtual ~UlNgUUpTnlModifyItem();

  void set(
      const UpTransportLayerInformation& ulNgUUpTnlInformation,
      const UpTransportLayerInformation& dlNgUUpTnlInformation);
  void get(
      UpTransportLayerInformation& ulNgUUpTnlInformation,
      UpTransportLayerInformation& dlNgUUpTnlInformation) const;

  void setUlNgUUpTnlInformation(
      const UpTransportLayerInformation& ulNgUUpTnlInformation);
  void getUlNgUUpTnlInformation(
      UpTransportLayerInformation& ulNgUUpTnlInformation) const;

  void setDlNgUUpTnlInformation(
      const UpTransportLayerInformation& dlNgUUpTnlInformation);
  void getDlNgUUpTnlInformation(
      UpTransportLayerInformation& dlNgUUpTnlInformation) const;

  bool encode(Ngap_UL_NGU_UP_TNLModifyItem_t& ulNgUUpTnlModifyItem) const;
  bool decode(const Ngap_UL_NGU_UP_TNLModifyItem_t& ulNgUUpTnlModifyItem);

 private:
  // UL NG-U UP TNL Information (Mandatory)
  UpTransportLayerInformation m_UlNgUUpTnlInformation;
  // UL NG-U UP TNL Information (Mandatory)
  UpTransportLayerInformation m_DlNgUUpTnlInformation;
  // TODO: Redundant UL NG-U UP TNL Information (Optional)
  // TODO: Redundant DL NG-U UP TNL Information (Optional)
};

}  // namespace oai::ngap

#endif
