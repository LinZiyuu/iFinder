/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "AuthenticationResponse.hpp"
#include "AuthenticationFailure.hpp"
#include "IdentityResponse.hpp"
#include "RegistrationComplete.hpp"
#include "RegistrationRequest.hpp"
#include "SecurityModeComplete.hpp"
#include "ServiceRequest.hpp"
#include "endian.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <array>
#include <string>

using ::testing::Test;

TEST(TestSuiteNasMsg, positiveTestingRegistrationRequestSuci) {
  /* Non - Access - Stratum 5GS(NAS)PDU
      Plain NAS 5GS Message
          Extended protocol discriminator: 5G mobility management messages (126)
          0000 .... = Spare Half Octet: 0
          .... 0000 = Security header type: Plain NAS message, not security
     protected (0) Message type: Registration request (0x41) 5GS registration
     type
              .... 1... = Follow-On Request bit (FOR): Follow-on request pending
              .... .001 = 5GS registration type: initial registration (1)
          NAS key set identifier
              0... .... = Type of security context flag (TSC): Native security
     context (for KSIAMF) .001 .... = NAS key set identifier: 1 5GS mobile
     identity Length: 13 0... .... = Spare: 0 .000 .... = SUPI format: IMSI (0)
              .... 0... = Spare: 0
              .... .001 = Type of identity: SUCI (1)
              Mobile Country Code (MCC): Unknown (1)
              Mobile Network Code (MNC): Unknown (01)
              Routing indicator: 0000
              .... 0000 = Protection scheme Id: NULL scheme (0)
              Home network public key identifier: 0
              MSIN: 0000000100
          UE security capability
              Element ID: 0x2e
              Length: 8
              1... .... = 5G-EA0: Supported
              .0.. .... = 128-5G-EA1: Not supported
              ..0. .... = 128-5G-EA2: Not supported
              ...0 .... = 128-5G-EA3: Not supported
              .... 0... = 5G-EA4: Not supported
              .... .0.. = 5G-EA5: Not supported
              .... ..0. = 5G-EA6: Not supported
              .... ...0 = 5G-EA7: Not supported
              0... .... = 5G-IA0: Not #include "RegistrationRequest.hppSupported
              ...0 .... = 128-5G-IA3: Not supported
              .... 0... = 5G-IA4: Not supported
              .... .0.. = 5G-IA5: Not supported
              .... ..0. = 5G-IA6: Not supported
              .... ...0 = 5G-IA7: Not supported
              0... .... = EEA0: Not supported
              .0.. .... = 128-EEA1: Not supported
              ..0. .... = 128-EEA2: Not supported
              ...0 .... = 128-EEA3: Not supported
              .... 0... = EEA4: Not supported
              .... .0.. = EEA5: Not supported
              .... ..0. = EEA6: Not supported
              .... ...0 = EEA7: Not supported
              0... .... = EIA0: Not supported
              .0.. .... = 128-EIA1: Not supported
              ..0. .... = 128-EIA2: Not supported
              ...0 .... = 128-EIA3: Not supported
              .... 0... = EIA4: Not supported
              .... .0.. = EIA5: Not supported
              .... ..0. = EIA6: Not supported
              .... ...0 = EIA7: Not supported */
  uint8_t packet_bytes[] = {0x7e, 0x00, 0x41, 0x19, 0x00, 0x0d, 0x01, 0x02,
                            0xf8, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x11, 0x2e, 0x08, 0x80, 0x20, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00};

  oai::nas::RegistrationRequest rr = {};
  int decode_result = rr.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));

  // TODO Decide if necessary to test this for all unit tests
  // (may be usefull if common nas used for UE)
  // std::vector<uint8_t> msg_encoded_bin(sizeof(packet_bytes));
  // int encode_result = rr.Encode(msg_encoded_bin.data(),
  // msg_encoded_bin.size()); EXPECT_EQ(encode_result, msg_encoded_bin.size());
}

TEST(TestSuiteNasMsg, positiveTestingRegistrationRequestSuci2) {
  /*
    Plain NAS 5GS Message
        Extended protocol discriminator: 5G mobility management messages (126)
        0000 .... = Spare Half Octet: 0
        .... 0000 = Security header type: Plain NAS message, not security
    protected (0) Message type: Registration request (0x41) 5GS registration
    type
            .... 1... = Follow-On Request bit (FOR): Follow-on request pending
            .... .001 = 5GS registration type: initial registration (1)
        NAS key set identifier
            0... .... = Type of security context flag (TSC): Native security
    context (for KSIAMF) .111 .... = NAS key set identifier: 7 5GS mobile
    identity Length: 57 0... .... = Spare: 0 .000 .... = SUPI format: IMSI (0)
            .... 0... = Spare: 0
            .... .001 = Type of identity: SUCI (1)
            Mobile Country Code (MCC): Italy (222)
            Mobile Network Code (MNC): Unknown (456)
            Routing indicator: 0
            .... 0001 = Protection scheme Id: ECIES scheme profile A (1)
            Home network public key identifier: 5
            Scheme output:
    25b6b6df89af58b0e70787fe5277a6317c2cc47d764a81aa3eccbea37bd05740aee0d554…
                ECC ephemeral public key:
    25b6b6df89af58b0e70787fe5277a6317c2cc47d764a81aa3eccbea37bd05740 Ciphertext:
    aee0d55470bff47c08 MAC tag: 0xe31df9b855991248 UE security capability
            Element ID: 0x2e
            Length: 2
            1... .... = 5G-EA0: Supported
            .1.. .... = 128-5G-EA1: Supported
            ..1. .... = 128-5G-EA2: Supported
            ...1 .... = 128-5G-EA3: Supported
            .... 0... = 5G-EA4: Not supported
            .... .0.. = 5G-EA5: Not supported
            .... ..0. = 5G-EA6: Not supported
            .... ...0 = 5G-EA7: Not supported
            1... .... = 5G-IA0: Supported
            .1.. .... = 128-5G-IA1: Supported
            ..1. .... = 128-5G-IA2: Supported
            ...1 .... = 128-5G-IA3: Supported
            .... 0... = 5G-IA4: Not supported
            .... .0.. = 5G-IA5: Not supported
            .... ..0. = 5G-IA6: Not supported
            .... ...0 = 5G-IA7: Not supported
 */
  uint8_t packet_bytes[] = {
      0x7e, 0x00, 0x41, 0x79, 0x00, 0x39, 0x01, 0x22, 0x62, 0x54, 0xf0, 0xff,
      0x01, 0x05, 0x25, 0xb6, 0xb6, 0xdf, 0x89, 0xaf, 0x58, 0xb0, 0xe7, 0x07,
      0x87, 0xfe, 0x52, 0x77, 0xa6, 0x31, 0x7c, 0x2c, 0xc4, 0x7d, 0x76, 0x4a,
      0x81, 0xaa, 0x3e, 0xcc, 0xbe, 0xa3, 0x7b, 0xd0, 0x57, 0x40, 0xae, 0xe0,
      0xd5, 0x54, 0x70, 0xbf, 0xf4, 0x7c, 0x08, 0xe3, 0x1d, 0xf9, 0xb8, 0x55,
      0x99, 0x12, 0x48, 0x2e, 0x02, 0xf0, 0xf0};

  oai::nas::RegistrationRequest rr = {};
  int decode_result = rr.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingRegistrationRequestSuciNullScheme) {
  /*
    Plain NAS 5GS Message
        Extended protocol discriminator: 5G mobility management messages (126)
        0000 .... = Spare Half Octet: 0
        .... 0000 = Security header type: Plain NAS message, not security
    protected (0) Message type: Registration request (0x41) 5GS registration
    type
            .... 1... = Follow-On Request bit (FOR): Follow-on request pending
            .... .001 = 5GS registration type: initial registration (1)
        NAS key set identifier
            0... .... = Type of security context flag (TSC): Native security
    context (for KSIAMF) .111 .... = NAS key set identifier: 7 5GS mobile
    identity Length: 13 0... .... = Spare: 0 .000 .... = SUPI format: IMSI (0)
            .... 0... = Spare: 0
            .... .001 = Type of identity: SUCI (1)
            Mobile Country Code (MCC): Italy (222)
            Mobile Network Code (MNC): Unknown (456)
            Routing indicator: 0000
            .... 0000 = Protection scheme Id: NULL scheme (0)
            Home network public key identifier: 0
            MSIN: 0000000010
        UE security capability
            Element ID: 0x2e
            Length: 8
            1... .... = 5G-EA0: Supported
            .0.. .... = 128-5G-EA1: Not supported
            ..0. .... = 128-5G-EA2: Not supported
            ...0 .... = 128-5G-EA3: Not supported
            .... 0... = 5G-EA4: Not supported
            .... .0.. = 5G-EA5: Not supported
            .... ..0. = 5G-EA6: Not supported
            .... ...0 = 5G-EA7: Not supported
            0... .... = 5G-IA0: Not supported
            .0.. .... = 128-5G-IA1: Not supported
            ..1. .... = 128-5G-IA2: Supported
            ...0 .... = 128-5G-IA3: Not supported
            .... 0... = 5G-IA4: Not supported
            .... .0.. = 5G-IA5: Not supported
            .... ..0. = 5G-IA6: Not supported
            .... ...0 = 5G-IA7: Not supported
            0... .... = EEA0: Not supported
            .0.. .... = 128-EEA1: Not supported
            ..0. .... = 128-EEA2: Not supported
            ...0 .... = 128-EEA3: Not supported
            .... 0... = EEA4: Not supported
            .... .0.. = EEA5: Not supported
            .... ..0. = EEA6: Not supported
            .... ...0 = EEA7: Not supported
            0... .... = EIA0: Not supported
            .0.. .... = 128-EIA1: Not supported
            ..0. .... = 128-EIA2: Not supported
            ...0 .... = 128-EIA3: Not supported
            .... 0... = EIA4: Not supported
            .... .0.. = EIA5: Not supported
            .... ..0. = EIA6: Not supported
            .... ...0 = EIA7: Not supported
 */
  uint8_t packet_bytes[] = {0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x22,
                            0x62, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x01, 0x2e, 0x08, 0x80, 0x20, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00};

  oai::nas::RegistrationRequest rr = {};
  int decode_result = rr.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingRegistrationRequestPlmnMismatch) {
  /*
    Plain NAS 5GS Message
        Extended protocol discriminator: 5G mobility management messages (126)
        0000 .... = Spare Half Octet: 0
        .... 0000 = Security header type: Plain NAS message, not security
    protected (0) Message type: Registration request (0x41) 5GS registration
    type
            .... 1... = Follow-On Request bit (FOR): Follow-on request pending
            .... .001 = 5GS registration type: initial registration (1)
        NAS key set identifier
            0... .... = Type of security context flag (TSC): Native security
    context (for KSIAMF) .111 .... = NAS key set identifier: 7 5GS mobile
    identity Length: 13 0... .... = Spare: 0 .000 .... = SUPI format: IMSI (0)
            .... 0... = Spare: 0
            .... .001 = Type of identity: SUCI (1)
            Mobile Country Code (MCC): Unknown (1)
            Mobile Network Code (MNC): Unknown (019)
            Routing indicator: 0
            .... 0000 = Protection scheme Id: NULL scheme (0)
            Home network public key identifier: 0
            MSIN: 976545664
        UE security capability
            Element ID: 0x2e
            Length: 2
            1... .... = 5G-EA0: Supported
            .1.. .... = 128-5G-EA1: Supported
            ..1. .... = 128-5G-EA2: Supported
            ...1 .... = 128-5G-EA3: Supported
            .... 0... = 5G-EA4: Not supported
            .... .0.. = 5G-EA5: Not supported
            .... ..0. = 5G-EA6: Not supported
            .... ...0 = 5G-EA7: Not supported
            1... .... = 5G-IA0: Supported
            .1.. .... = 128-5G-IA1: Supported
            ..1. .... = 128-5G-IA2: Supported
            ...1 .... = 128-5G-IA3: Supported
            .... 0... = 5G-IA4: Not supported
            .... .0.. = 5G-IA5: Not supported
            .... ..0. = 5G-IA6: Not supported
            .... ...0 = 5G-IA7: Not supported
 */
  uint8_t packet_bytes[] = {0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x00,
                            0x91, 0x10, 0xf0, 0xff, 0x00, 0x00, 0x79, 0x56,
                            0x54, 0x66, 0xf4, 0x2e, 0x02, 0xf0, 0xf0};

  oai::nas::RegistrationRequest rr = {};
  int decode_result = rr.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingRegistrationRequestGuti) {
  /*
  // TODO security header
  Plain NAS 5GS Message
    Extended protocol discriminator: 5G mobility management messages (126)
    0000 .... = Spare Half Octet: 0
    .... 0000 = Security header type: Plain NAS message, not security protected
  (0) Message type: Registration request (0x41) 5GS registration type
        .... 1... = Follow-On Request bit (FOR): Follow-on request pending
        .... .001 = 5GS registration type: initial registration (1)
    NAS key set identifier
        0... .... = Type of security context flag (TSC): Native security context
  (for KSIAMF) .000 .... = NAS key set identifier: 0 5GS mobile identity Length:
  11 1... .... = Spare: 1 .1.. .... = Spare: 1
        ..1. .... = Spare: 1
        ...1 .... = Spare: 1
        .... 0... = Spare: 0
        .... .010 = Type of identity: 5G-GUTI (2)
        Mobile Country Code (MCC): Italy (222)
        Mobile Network Code (MNC): Unknown (456)
        AMF Region ID: 1
        0000 0000 01.. .... = AMF Set ID: 1
        ..00 0000 = AMF Pointer: 0
        5G-TMSI: 309346679 (0x12704177)
    5GMM capability
        Element ID: 0x10
        Length: 1
        0... .... = Service gap control (SGC): Not supported
        .0.. .... = IP header compression for control plane CIoT 5GS
  optimization (5G-IPHC-CP CIoT): Not supported
        ..0. .... = N3 data transfer (N3 data): Not supported
        ...0 .... = Control plane CIoT 5GS optimization (5G-CP CIoT): Not
  supported
        .... 0... = Restriction on use of enhanced coverage support
  (RestrictEC): Not supported
        .... .0.. = LTE Positioning Protocol (LPP) capability: Not supported
        .... ..1. = ATTACH REQUEST message containing PDN CONNECTIVITY REQUEST
  message for handover support (HO attach): Supported
        .... ...1 = EPC NAS supported (S1 mode): Supported
    UE security capability
        Element ID: 0x2e
        Length: 4
        1... .... = 5G-EA0: Supported
        .0.. .... = 128-5G-EA1: Not supported
        ..0. .... = 128-5G-EA2: Not supported
        ...0 .... = 128-5G-EA3: Not supported
        .... 0... = 5G-EA4: Not supported
        .... .0.. = 5G-EA5: Not supported
        .... ..0. = 5G-EA6: Not supported
        .... ...0 = 5G-EA7: Not supported
        1... .... = 5G-IA0: Supported
        .1.. .... = 128-5G-IA1: Supported
        ..1. .... = 128-5G-IA2: Supported
        ...0 .... = 128-5G-IA3: Not supported
        .... 0... = 5G-IA4: Not supported
        .... .0.. = 5G-IA5: Not supported
        .... ..0. = 5G-IA6: Not supported
        .... ...0 = 5G-IA7: Not supported
        1... .... = EEA0: Supported
        .0.. .... = 128-EEA1: Not supported
        ..0. .... = 128-EEA2: Not supported
        ...0 .... = 128-EEA3: Not supported
        .... 0... = EEA4: Not supported
        .... .0.. = EEA5: Not supported
        .... ..0. = EEA6: Not supported
        .... ...0 = EEA7: Not supported
        1... .... = EIA0: Supported
        .1.. .... = 128-EIA1: Supported
        ..1. .... = 128-EIA2: Supported
        ...0 .... = 128-EIA3: Not supported
        .... 0... = EIA4: Not supported
        .... .0.. = EIA5: Not supported
        .... ..0. = EIA6: Not supported
        .... ...0 = EIA7: Not supported
    NSSAI - Requested NSSAI
        Element ID: 0x2f
        Length: 2
        S-NSSAI 1
            Length: 1
            Slice/service type (SST): eMBB (1)
    5GS tracking area identity - Last visited registered TAI
        Element ID: 0x52
        Mobile Country Code (MCC): Italy (222)
        Mobile Network Code (MNC): Unknown (456)
        TAC: 1
    UE network capability
        Element ID: 0x17
        Length: 7
        1... .... = EEA0: Supported
        .0.. .... = 128-EEA1: Not supported
        ..0. .... = 128-EEA2: Not supported
        ...0 .... = 128-EEA3: Not supported
        .... 0... = EEA4: Not supported
        .... .0.. = EEA5: Not supported
        .... ..0. = EEA6: Not supported
        .... ...0 = EEA7: Not supported
        1... .... = EIA0: Supported
        .1.. .... = 128-EIA1: Supported
        ..1. .... = 128-EIA2: Supported
        ...0 .... = 128-EIA3: Not supported
        .... 0... = EIA4: Not supported
        .... .0.. = EIA5: Not supported
        .... ..0. = EIA6: Not supported
        .... ...0 = EIA7: Not supported
        1... .... = UEA0: Supported
        .1.. .... = UEA1: Supported
        ..1. .... = UEA2: Supported
        ...0 .... = UEA3: Not supported
        .... 0... = UEA4: Not supported
        .... .0.. = UEA5: Not supported
        .... ..0. = UEA6: Not supported
        .... ...0 = UEA7: Not supported
        0... .... = UCS2 support (UCS2): The UE has a preference for the default
  alphabet .1.. .... = UMTS integrity algorithm UIA1: Supported
        ..1. .... = UMTS integrity algorithm UIA2: Supported
        ...0 .... = UMTS integrity algorithm UIA3: Not supported
        .... 0... = UMTS integrity algorithm UIA4: Not supported
        .... .0.. = UMTS integrity algorithm UIA5: Not supported
        .... ..0. = UMTS integrity algorithm UIA6: Not supported
        .... ...0 = UMTS integrity algorithm UIA7: Not supported
        0... .... = ProSe direct discovery: Not supported
        .0.. .... = ProSe: Not supported
        ..0. .... = H.245 After SRVCC Handover: Not supported
        ...0 .... = Access class control for CSFB: Not supported
        .... 0... = LTE Positioning Protocol: Not supported
        .... .0.. = Location services (LCS) notification mechanisms: Not
  supported
        .... ..0. = SRVCC from E-UTRAN to cdma2000 1xCS: Not supported
        .... ...0 = Notification procedure: Not supported
        0... .... = Extended protocol configuration options: Not supported
        .0.. .... = Header compression for control plane CIoT EPS optimization:
  Not supported
        ..0. .... = EMM-REGISTERED w/o PDN connectivity: Not supported
        ...1 .... = S1-U data transfer: Supported
        .... 1... = User plane CIoT EPS optimization: Supported
        .... .1.. = Control plane CIoT EPS optimization: Supported
        .... ..0. = ProSe UE-to-network relay: Not supported
        .... ...0 = ProSe direct communication: Not supported
        0... .... = Signalling for a maximum number of 15 EPS bearer contexts:
  Not supported .0.. .... = Service gap control: Not supported
        ..1. .... = N1 mode: Supported
        ...1 .... = Dual connectivity with NR: Supported
        .... 0... = Control plane data backoff: Not supported
        .... .0.. = Restriction on use of enhanced coverage: Not supported
        .... ..0. = V2X communication over PC5: Not supported
        .... ...0 = Multiple DRB: Not supported
    UE's usage setting
        Element ID: 0x18
        Length: 1
        .... 0... = Spare: 0
        .... .0.. = Spare: 0
        .... ..0. = Spare: 0
        .... ...0 = UE's usage setting: Voice centric
    LADN indication
        Element ID: 0x74
        Length: 10
        LADN DNN value 1
            Length: 9
            DNN: internet
    5GS update type
        Element ID: 0x53
        Length: 1
        0... .... = Spare: 0
        .0.. .... = Spare: 0
        ..00 .... = EPS Preferred CIoT network behaviour (EPS-PNB-CIoT): no
  additional information (0)
        .... 00.. = 5GS Preferred CIoT network behaviour (5GS PNB-CIoT): no
  additional information (0)
        .... ..0. = NG-RAN Radio Capability Update (NG-RAN-RCU): Not Needed
        .... ...1 = SMS over NAS transport requested (SMS requested): Supported
  */
  uint8_t packet_bytes[] = {
      // TODO security header
      // 0x7e, 0x01, 0x67, 0xb7, 0x6f, 0xc6, 0x03, 0x7e, 0x00, 0x41, 0x09,
      // 0x00, 0x0b, 0xf2, 0x22, 0x62, 0x54, 0x01, 0x00, 0x40, 0x12, 0x70,
      // 0x41, 0x77, 0x2e, 0x04, 0x80, 0xe0, 0x80, 0xe0, 0x71, 0x00, 0x41,
      0x7e, 0x00, 0x41, 0x09, 0x00, 0x0b, 0xf2, 0x22, 0x62, 0x54, 0x01,
      0x00, 0x40, 0x12, 0x70, 0x41, 0x77, 0x10, 0x01, 0x03, 0x2e, 0x04,
      0x80, 0xe0, 0x80, 0xe0, 0x2f, 0x02, 0x01, 0x01, 0x52, 0x22, 0x62,
      0x54, 0x00, 0x00, 0x01, 0x17, 0x07, 0x80, 0xe0, 0xe0, 0x60, 0x00,
      0x1c, 0x30, 0x18, 0x01, 0x00, 0x74, 0x00, 0x0a, 0x09, 0x08, 0x69,
      0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x53, 0x01, 0x01};

  oai::nas::RegistrationRequest rr = {};
  int decode_result = rr.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingReRegistrationRequestGuti) {
  /*
Plain NAS 5GS Message
    Extended protocol discriminator: 5G mobility management messages (126)
    0000 .... = Spare Half Octet: 0
    .... 0000 = Security header type: Plain NAS message, not security protected
(0) Message type: Registration request (0x41) 5GS registration type
        .... 0... = Follow-On Request bit (FOR): No follow-on request pending
        .... .001 = 5GS registration type: initial registration (1)
    NAS key set identifier
        0... .... = Type of security context flag (TSC): Native security context
(for KSIAMF) .000 .... = NAS key set identifier: 0 5GS mobile identity Length:
11 1... .... = Spare: 1 .1.. .... = Spare: 1
        ..1. .... = Spare: 1
        ...1 .... = Spare: 1
        .... 0... = Spare: 0
        .... .010 = Type of identity: 5G-GUTI (2)
        Mobile Country Code (MCC): Italy (222)
        Mobile Network Code (MNC): Unknown (456)
        AMF Region ID: 1
        0000 0000 01.. .... = AMF Set ID: 1
        ..00 0000 = AMF Pointer: 0
        5G-TMSI: 3649718909 (0xd98a4a7d)
    5GMM capability
        Element ID: 0x10
        Length: 1
        0... .... = Service gap control (SGC): Not supported
        .0.. .... = IP header compression for control plane CIoT 5GS
optimization (5G-IPHC-CP CIoT): Not supported
        ..0. .... = N3 data transfer (N3 data): Not supported
        ...0 .... = Control plane CIoT 5GS optimization (5G-CP CIoT): Not
supported
        .... 0... = Restriction on use of enhanced coverage support
(RestrictEC): Not supported
        .... .0.. = LTE Positioning Protocol (LPP) capability: Not supported
        .... ..0. = ATTACH REQUEST message containing PDN CONNECTIVITY REQUEST
message for handover support (HO attach): Not supported
        .... ...0 = EPC NAS supported (S1 mode): Not supported
    UE security capability
        Element ID: 0x2e
        Length: 2
        1... .... = 5G-EA0: Supported
        .1.. .... = 128-5G-EA1: Supported
        ..0. .... = 128-5G-EA2: Not supported
        ...0 .... = 128-5G-EA3: Not supported
        .... 0... = 5G-EA4: Not supported
        .... .0.. = 5G-EA5: Not supported
        .... ..0. = 5G-EA6: Not supported
        .... ...0 = 5G-EA7: Not supported
        1... .... = 5G-IA0: Supported
        .1.. .... = 128-5G-IA1: Supported
        ..0. .... = 128-5G-IA2: Not supported
        ...0 .... = 128-5G-IA3: Not supported
        .... 0... = 5G-IA4: Not supported
        .... .0.. = 5G-IA5: Not supported
        .... ..0. = 5G-IA6: Not supported
        .... ...0 = 5G-IA7: Not supported
    NSSAI - Requested NSSAI
        Element ID: 0x2f
        Length: 2
        S-NSSAI 1
            Length: 1
            Slice/service type (SST): URLLC (2)
    UE network capability
        Element ID: 0x17
        Length: 2
        1... .... = EEA0: Supported
        .1.. .... = 128-EEA1: Supported
        ..0. .... = 128-EEA2: Not supported
        ...0 .... = 128-EEA3: Not supported
        .... 0... = EEA4: Not supported
        .... .0.. = EEA5: Not supported
        .... ..0. = EEA6: Not supported
        .... ...0 = EEA7: Not supported
        1... .... = EIA0: Supported
        .1.. .... = 128-EIA1: Supported
        ..0. .... = 128-EIA2: Not supported
        ...0 .... = 128-EIA3: Not supported
        .... 0... = EIA4: Not supported
        .... .0.. = EIA5: Not supported
        .... ..0. = EIA6: Not supported
        .... ...0 = EIA7: Not supported
    MICO indication
        1011 .... = Element ID: 0xb-
        .... 0... = Spare: 0
        .... .0.. = Spare: 0
        .... ..0. = Strictly Periodic Registration Timer Indication (SPRTI): Not
supported
        .... ...0 = Registration Area Allocation Indication (RAAI): all PLMN
registration area not allocated UE status Element ID: 0x2b Length: 1 0... .... =
Spare: 0 .0.. .... = Spare: 0
        ..0. .... = Spare: 0
        ...0 .... = Spare: 0
        .... 0... = Spare: 0
        .... .0.. = Spare: 0
        .... ..0. = N1 mode reg: UE is not in 5GMM-REGISTERED state
        .... ...0 = S1 mode reg: UE is not in EMM-REGISTERED state

  */
  uint8_t packet_bytes[] = {
      0x7e, 0x00, 0x41, 0x01, 0x00, 0x0b, 0xf2, 0x22, 0x62, 0x54, 0x01, 0x00,
      0x40, 0xd9, 0x8a, 0x4a, 0x7d, 0x10, 0x01, 0x00, 0x2e, 0x02, 0xc0, 0xc0,
      0x2f, 0x02, 0x01, 0x02, 0x17, 0x02, 0xc0, 0xc0, 0xb0, 0x2b, 0x01, 0x00};

  oai::nas::RegistrationRequest rr = {};
  int decode_result = rr.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingIdentityResponse) {
  /*
NAS-PDU: 7e01e21dd9e5047e005c000d01226254f0ff00000000000001
    Non-Access-Stratum 5GS (NAS)PDU
        Security protected NAS 5GS message
            Extended protocol discriminator: 5G mobility management messages
(126) 0000 .... = Spare Half Octet: 0
            .... 0001 = Security header type: Integrity protected (1)
            Message authentication code: 0xe21dd9e5
            Sequence number: 4
        Plain NAS 5GS Message
            Extended protocol discriminator: 5G mobility management messages
(126) 0000 .... = Spare Half Octet: 0
            .... 0000 = Security header type: Plain NAS message, not security
protected (0) Message type: Identity response (0x5c) 5GS mobile identity Length:
13 0... .... = Spare: 0 .000 .... = SUPI format: IMSI (0)
                .... 0... = Spare: 0
                .... .001 = Type of identity: SUCI (1)
                Mobile Country Code (MCC): Italy (222)
                Mobile Network Code (MNC): Unknown (456)
                Routing indicator: 0
                .... 0000 = Protection scheme Id: NULL scheme (0)
                Home network public key identifier: 0
                MSIN: 0000000010
  */
  uint8_t packet_bytes[] = {
      // TODO security header 0x7e, 0x01, 0xe2, 0x1d, 0xd9, 0xe5, 0x04,
      0x7e, 0x00, 0x5c, 0x00, 0x0d, 0x01, 0x22, 0x62, 0x54,
      0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

  oai::nas::IdentityResponse nas_obj = {};
  int decode_result = nas_obj.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingIdentityResponseProfileA) {
  /*
Plain NAS 5GS Message
    Extended protocol discriminator: 5G mobility management messages (126)
    0000 .... = Spare Half Octet: 0
    .... 0000 = Security header type: Plain NAS message, not security protected
(0) Message type: Identity response (0x5c) 5GS mobile identity Length: 53 0...
.... = Spare: 0 .000 .... = SUPI format: IMSI (0)
        .... 0... = Spare: 0
        .... .001 = Type of identity: SUCI (1)
        Mobile Country Code (MCC): Italy (222)
        Mobile Network Code (MNC): Unknown (456)
        Routing indicator: 0
        .... 0001 = Protection scheme Id: ECIES scheme profile A (1)
        Home network public key identifier: 1
        Scheme output:
a1ae7e561b544b7c74030989a92155d78bbf28535fb59423b4cb640e6c1ed43715e83c72… ECC
ephemeral public key:
a1ae7e561b544b7c74030989a92155d78bbf28535fb59423b4cb640e6c1ed437 Ciphertext:
15e83c7239 MAC tag: 0x1f158a9d7acc094b
  */
  uint8_t packet_bytes[] = {0x7e, 0x00, 0x5c, 0x00, 0x35, 0x01, 0x22, 0x62,
                            0x54, 0xf0, 0xff, 0x01, 0x01, 0xa1, 0xae, 0x7e,
                            0x56, 0x1b, 0x54, 0x4b, 0x7c, 0x74, 0x03, 0x09,
                            0x89, 0xa9, 0x21, 0x55, 0xd7, 0x8b, 0xbf, 0x28,
                            0x53, 0x5f, 0xb5, 0x94, 0x23, 0xb4, 0xcb, 0x64,
                            0x0e, 0x6c, 0x1e, 0xd4, 0x37, 0x15, 0xe8, 0x3c,
                            0x72, 0x39, 0x1f, 0x15, 0x8a, 0x9d, 0x7a, 0xcc,
                            0x09, 0x4b};  // TODO check may add 0x00 ?};

  oai::nas::IdentityResponse nas_obj = {};
  int decode_result = nas_obj.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingUeAuthResponse) {
  /*
Plain NAS 5GS Message
    Extended protocol discriminator: 5G mobility management messages (126)
    0000 .... = Spare Half Octet: 0
    .... 0000 = Security header type: Plain NAS message, not security protected
(0) Message type: Authentication response (0x57) Authentication response
parameter Element ID: 0x2d Length: 16 RES: 25706f9a5b90b6c957506c883d76cc63
  */
  uint8_t packet_bytes[] = {0x7e, 0x0,  0x57, 0x2d, 0x10, 0x25, 0x70,
                            0x6f, 0x9a, 0x5b, 0x90, 0xb6, 0xc9, 0x57,
                            0x50, 0x6c, 0x88, 0x3d, 0x76, 0xcc, 0x63};

  oai::nas::AuthenticationResponse nas_obj = {};
  int decode_result = nas_obj.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingUeAuthFailureSecurityCapabilityMismatch) {
  /*
Plain NAS 5GS Message
    Extended protocol discriminator: 5G mobility management messages (126)
    0000 .... = Spare Half Octet: 0
    .... 0000 = Security header type: Plain NAS message, not security protected
(0) Message type: Authentication failure (0x59) 5GMM cause 5GMM cause: UE
security capabilities mismatch (23)
  */
  uint8_t packet_bytes[] = {0x7e, 0x0, 0x59, 0x17};

  oai::nas::AuthenticationFailure nas_obj = {};
  int decode_result = nas_obj.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingUeAuthFailureSecurityModeReject) {
  /*
Non-Access-Stratum 5GS (NAS)PDU
    Plain NAS 5GS Message
        Extended protocol discriminator: 5G mobility management messages (126)
        0000 .... = Spare Half Octet: 0
        .... 0000 = Security header type: Plain NAS message, not security
protected (0) Message type: Authentication failure (0x59) 5GMM cause 5GMM cause:
Security mode rejected, unspecified (24)
  */
  uint8_t packet_bytes[] = {0x7e, 0x0, 0x59, 0x18};

  oai::nas::AuthenticationFailure nas_obj = {};
  int decode_result = nas_obj.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingSecurityModeComplete) {
  /*
Security protected NAS 5GS message
    Extended protocol discriminator: 5G mobility management messages (126)
    0000 .... = Spare Half Octet: 0
    .... 0100 = Security header type: Integrity protected and ciphered with new
5GS security context (4) Message authentication code: 0x54f6e12a Sequence
number: 0 Plain NAS 5GS Message Extended protocol discriminator: 5G mobility
management messages (126) 0000 .... = Spare Half Octet: 0
    .... 0000 = Security header type: Plain NAS message, not security protected
(0) Message type: Security mode complete (0x5e) 5GS mobile identity Element ID:
0x77 Length: 9
        .... 0... = Odd/even indication: Even number of identity digits
        .... .101 = Type of identity: IMEISV (5)
        IMEISV: 4370816125816151
    NAS message container
        Element ID: 0x71
        Length: 35
        Non-Access-Stratum 5GS (NAS)PDU
            Plain NAS 5GS Message
                Extended protocol discriminator: 5G mobility management messages
(126) 0000 .... = Spare Half Octet: 0
                .... 0000 = Security header type: Plain NAS message, not
security protected (0) Message type: Registration request (0x41) 5GS
registration type
                    .... 1... = Follow-On Request bit (FOR): Follow-on request
pending
                    .... .001 = 5GS registration type: initial registration (1)
                NAS key set identifier
                    0... .... = Type of security context flag (TSC): Native
security context (for KSIAMF) .111 .... = NAS key set identifier: 7 5GS mobile
identity Length: 13 0... .... = Spare: 0 .000 .... = SUPI format: IMSI (0)
                    .... 0... = Spare: 0
                    .... .001 = Type of identity: SUCI (1)
                    Mobile Country Code (MCC): Italy (222)
                    Mobile Network Code (MNC): Unknown (456)
                    Routing indicator: 0000
                    .... 0000 = Protection scheme Id: NULL scheme (0)
                    Home network public key identifier: 0
                    MSIN: 000000001
                5GMM capability
                    Element ID: 0x10
                    Length: 1
                    0... .... = Service gap control (SGC): Not supported
                    .0.. .... = IP header compression for control plane CIoT 5GS
optimization (5G-IPHC-CP CIoT): Not supported
                    ..0. .... = N3 data transfer (N3 data): Not supported
                    ...0 .... = Control plane CIoT 5GS optimization (5G-CP
CIoT): Not supported
                    .... 0... = Restriction on use of enhanced coverage support
(RestrictEC): Not supported
                    .... .0.. = LTE Positioning Protocol (LPP) capability: Not
supported
                    .... ..0. = ATTACH REQUEST message containing PDN
CONNECTIVITY REQUEST message for handover support (HO attach): Not supported
                    .... ...0 = EPC NAS supported (S1 mode): Not supported
                UE security capability
                    Element ID: 0x2e
                    Length: 8
                    1... .... = 5G-EA0: Supported
                    .0.. .... = 128-5G-EA1: Not supported
                    ..0. .... = 128-5G-EA2: Not supported
                    ...0 .... = 128-5G-EA3: Not supported
                    .... 0... = 5G-EA4: Not supported
                    .... .0.. = 5G-EA5: Not supported
                    .... ..0. = 5G-EA6: Not supported
                    .... ...0 = 5G-EA7: Not supported
                    0... .... = 5G-IA0: Not supported
                    .0.. .... = 128-5G-IA1: Not supported
                    ..1. .... = 128-5G-IA2: Supported
                    ...0 .... = 128-5G-IA3: Not supported
                    .... 0... = 5G-IA4: Not supported
                    .... .0.. = 5G-IA5: Not supported
                    .... ..0. = 5G-IA6: Not supported
                    .... ...0 = 5G-IA7: Not supported
                    0... .... = EEA0: Not supported
                    .0.. .... = 128-EEA1: Not supported
                    ..0. .... = 128-EEA2: Not supported
                    ...0 .... = 128-EEA3: Not supported
                    .... 0... = EEA4: Not supported
                    .... .0.. = EEA5: Not supported
                    .... ..0. = EEA6: Not supported
                    .... ...0 = EEA7: Not supported
                    0... .... = EIA0: Not supported
                    .0.. .... = 128-EIA1: Not supported
                    ..0. .... = 128-EIA2: Not supported
                    ...0 .... = 128-EIA3: Not supported
                    .... 0... = EIA4: Not supported
                    .... .0.. = EIA5: Not supported
                    .... ..0. = EIA6: Not supported
                    .... ...0 = EIA7: Not supported

  */
  uint8_t packet_bytes[] = {
      // TODO Security protected NAS 5G msg
      // 0x7e, 0x4, 0x54, 0xf6, 0xe1, 0x2a, 0x0,
      0x7e, 0x00, 0x5e, 0x77, 0x00, 0x09, 0x45, 0x73, 0x80, 0x61, 0x21,
      0x85, 0x61, 0x51, 0xf1, 0x71, 0x00, 0x23, 0x7e, 0x00, 0x41, 0x79,
      0x00, 0x0d, 0x01, 0x22, 0x62, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0xf1, 0x10, 0x01, 0x00, 0x2e, 0x08, 0x80, 0x20,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x02, 0x01};
  //, 0x01, 0x53, 0x01,
  //    0x00};

  oai::nas::SecurityModeComplete nas_obj = {};
  int decode_result = nas_obj.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingRegistrationComplete) {
  /*
NAS-PDU: 7e025d5f4918017e0043
    Non-Access-Stratum 5GS (NAS)PDU
        Security protected NAS 5GS message
            Extended protocol discriminator: 5G mobility management messages
(126) 0000 .... = Spare Half Octet: 0
            .... 0010 = Security header type: Integrity protected and ciphered
(2) Message authentication code: 0x5d5f4918 Sequence number: 1 Plain NAS 5GS
Message Extended protocol discriminator: 5G mobility management messages (126)
            0000 .... = Spare Half Octet: 0
            .... 0000 = Security header type: Plain NAS message, not security
protected (0) Message type: Registration complete (0x43)

  */
  uint8_t packet_bytes[] = {// TODO Security protected NAS 5G msg with
                            // 0x7e, 0x02, 0x5d, 0x5f, 0x49, 0x18, 0x01,
                            0x7e, 0x00, 0x43};

  oai::nas::RegistrationComplete nas_obj = {};
  int decode_result = nas_obj.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));
}

TEST(TestSuiteNasMsg, positiveTestingServiceRequestWithPdu) {
  /*
  Plain NAS 5GS Message
      Extended protocol discriminator: 5G mobility management messages (126)
      0000 .... = Spare Half Octet: 0
      .... 0000 = Security header type: Plain NAS message, not security
  protected (0) Message type: Service request (0x4c) NAS key set identifier
          .... 0... = Type of security context flag (TSC): Native security
  context (for KSIAMF)
          .... .000 = NAS key set identifier: 0
      Service type
          .010 .... = Service type: Mobile terminated services (2)
      5GS mobile identity
          Length: 7
          .... 0... = Odd/even indication: Even number of identity digits
          .... .100 = Type of identity: 5G-S-TMSI (4)
          0000 0000 01.. .... = AMF Set ID: 1
          ..00 0000 = AMF Pointer: 0
          5G-TMSI: 4294967295 (0xffffffff)
      Uplink data status
          Element ID: 0x40
          Length: 2
          0... .... = PSI(7): no uplink data are pending
          .0.. .... = PSI(6): no uplink data are pending
          ..1. .... = PSI(5): uplink data are pending
          ...0 .... = PSI(4): no uplink data are pending
          .... 0... = PSI(3): no uplink data are pending
          .... .0.. = PSI(2): no uplink data are pending
          .... ..0. = PSI(1): no uplink data are pending
          .... ...0 = Spare: False
          0... .... = PSI(15): no uplink data are pending
          .0.. .... = PSI(14): no uplink data are pending
          ..0. .... = PSI(13): no uplink data are pending
          ...0 .... = PSI(12): no uplink data are pending
          .... 0... = PSI(11): no uplink data are pending
          .... .0.. = PSI(10): no uplink data are pending
          .... ..0. = PSI(9): no uplink data are pending
          .... ...0 = PSI(8): no uplink data are pending
      PDU session status
          Element ID: 0x50
          Length: 2
          0... .... = PSI(7): PDU SESSION INACTIVE
          .0.. .... = PSI(6): PDU SESSION INACTIVE
          ..1. .... = PSI(5): Not PDU SESSION INACTIVE
          ...0 .... = PSI(4): PDU SESSION INACTIVE
          .... 0... = PSI(3): PDU SESSION INACTIVE
          .... .0.. = PSI(2): PDU SESSION INACTIVE
          .... ..0. = PSI(1): PDU SESSION INACTIVE
          .... ...0 = Spare: False
          0... .... = PSI(15): PDU SESSION INACTIVE
          .0.. .... = PSI(14): PDU SESSION INACTIVE
          ..0. .... = PSI(13): PDU SESSION INACTIVE
          ...0 .... = PSI(12): PDU SESSION INACTIVE
          .... 0... = PSI(11): PDU SESSION INACTIVE
          .... .0.. = PSI(10): PDU SESSION INACTIVE
          .... ..0. = PSI(9): PDU SESSION INACTIVE
          .... ...0 = PSI(8): PDU SESSION INACTIVE
  */
  uint8_t packet_bytes[] = {
      // TODO Security protected NAS 5G msg with
      // Mobility mgmt msg with security header and auth code
      // 0x7e, 0x01, 0xca, 0x3f, 0x92, 0xbe,
      // seq no
      // 0x03,
      // Plain NAS 5G msg with
      0x7e, 0x00, 0x4c, 0x20, 0x00, 0x07, 0xf4, 0x00, 0x40, 0xff, 0xff,
      0xff, 0xff, 0x40, 0x02, 0x20, 0x00, 0x50, 0x02, 0x20, 0x00};

  oai::nas::ServiceRequest nas_obj = {};
  int decode_result = nas_obj.Decode(packet_bytes, sizeof(packet_bytes));
  ASSERT_EQ(decode_result, sizeof(packet_bytes));

  // First quartet
  uint8_t service_type;
  nas_obj.GetServiceType(service_type);
  // pending issue in gitlab EXPECT_EQ(service_type, 0x02);

  // Last quartet
  uint8_t ng_ksi;
  nas_obj.GetNgKsi(ng_ksi);
  EXPECT_EQ(ng_ksi, 0x00);

  uint16_t amf_set_id;
  uint8_t amf_pointer;
  std::string tmsi;
  ASSERT_TRUE(nas_obj.Get5gSTmsi(amf_set_id, amf_pointer, tmsi));
  EXPECT_EQ(amf_set_id, 0x0001);
  EXPECT_EQ(amf_pointer, 0x00);
  // warning base10 format
  EXPECT_STREQ(tmsi.c_str(), "4294967295");

  uint16_t uplink_data_status;
  nas_obj.GetUplinkDataStatus(uplink_data_status);
  EXPECT_EQ(uplink_data_status, 0x2000);

  uint16_t pdu_session_status;
  nas_obj.GetPduSessionStatus(pdu_session_status);
  EXPECT_EQ(pdu_session_status, 0x2000);
}
