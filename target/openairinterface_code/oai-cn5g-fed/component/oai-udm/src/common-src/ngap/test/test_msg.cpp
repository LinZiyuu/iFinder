/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
extern "C" {
#include "Ngap_InitiatingMessage.h"
#include "Ngap_NGAP-PDU.h"
}
#include "UplinkNasTransport.hpp"
#include "ngap_utils.hpp"
#include <glog/logging.h>
#include <gtest/gtest.h>

#include <string>

using ::testing::Test;

extern std::vector<uint8_t> hexStringToByteArray(const std::string& hexString);

TEST(TestSuiteNGAPMsg, positiveTestingRegistrationRequest) {
  uint8_t packet_bytes[] = {
      0x00, 0x2e, 0x40, 0x3c, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x02,
      0x00, 0x01, 0x00, 0x55, 0x00, 0x02, 0x00, 0x01, 0x00, 0x26, 0x00,
      0x16, 0x15, 0x7e, 0x00, 0x57, 0x2d, 0x10, 0x00, 0x28, 0xbf, 0x2f,
      0x1d, 0xe1, 0xbb, 0x67, 0x9c, 0x56, 0x16, 0xd3, 0xb5, 0xde, 0x1a,
      0x94, 0x00, 0x79, 0x40, 0x0f, 0x40, 0x02, 0xf8, 0x29, 0x00, 0x00,
      0xe0, 0x00, 0x00, 0x02, 0xf8, 0x29, 0x00, 0x00, 0x01};
  /*
NG Application Protocol (UplinkNASTransport)
  NGAP-PDU: initiatingMessage (0)
      initiatingMessage
          procedureCode: id-UplinkNASTransport (46)
          criticality: ignore (1)
          value
              UplinkNASTransport
                  protocolIEs: 4 items
                      Item 0: id-AMF-UE-NGAP-ID
                          ProtocolIE-Field
                              id: id-AMF-UE-NGAP-ID (10)
                              criticality: reject (0)
                              value
                                  AMF-UE-NGAP-ID: 1
                      Item 1: id-RAN-UE-NGAP-ID
                          ProtocolIE-Field
                              id: id-RAN-UE-NGAP-ID (85)
                              criticality: reject (0)
                              value
                                  RAN-UE-NGAP-ID: 1
                      Item 2: id-NAS-PDU
                          ProtocolIE-Field
                              id: id-NAS-PDU (38)
                              criticality: reject (0)
                              value
                                  NAS-PDU:
7e00572d100028bf2f1de1bb679c5616d3b5de1a94 Non-Access-Stratum 5GS (NAS)PDU Plain
NAS 5GS Message Extended protocol discriminator: 5G mobility management messages
(126) 0000 .... = Spare Half Octet: 0
                                              .... 0000 = Security header type:
Plain NAS message, not security protected (0) Message type: Authentication
response (0x57) Authentication response parameter Element ID: 0x2d Length: 16
                                                  RES:
0028bf2f1de1bb679c5616d3b5de1a94 Item 3: id-UserLocationInformation
                          ProtocolIE-Field
                              id: id-UserLocationInformation (121)
                              criticality: ignore (1)
                              value
                                  UserLocationInformation:
userLocationInformationNR (1) userLocationInformationNR nR-CGI pLMNIdentity:
02f829 Mobile Country Code (MCC): France (208) Mobile Network Code (MNC):
Unknown (92) nRCellIdentity: 0x00000e0000 tAI pLMNIdentity: 02f829 Mobile
Country Code (MCC): France (208) Mobile Network Code (MNC): Unknown (92) tAC: 1
(0x000001)
*/

  Ngap_NGAP_PDU_t* ngap_msg_pdu =
      (Ngap_NGAP_PDU_t*) calloc(1, sizeof(Ngap_NGAP_PDU_t));
  asn_dec_rval_t dec_ret;

  dec_ret = aper_decode(
      NULL, &asn_DEF_Ngap_NGAP_PDU, (void**) &ngap_msg_pdu, packet_bytes,
      sizeof(packet_bytes), 0, 0);

  oai::ngap::ngap_utils::print_asn_msg(&asn_DEF_Ngap_NGAP_PDU, ngap_msg_pdu);

  oai::ngap::UplinkNasTransportMsg* uplink_nas_transport =
      new oai::ngap::UplinkNasTransportMsg();
  EXPECT_NE(uplink_nas_transport->decode(ngap_msg_pdu), 0);
}
