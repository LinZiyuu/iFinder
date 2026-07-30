/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_3GPP_COMMONS_SEEN
#define FILE_3GPP_COMMONS_SEEN

#include <stdint.h>

// 8.2 Recovery
typedef struct recovery_s {
  uint8_t restart_counter;
} recovery_t;

// Bit rate's unit, used by NAS and NGAP (3GPP TS 24.501)
constexpr uint8_t kBitRateUnitValueIsNotUsed                       = 0b00000000;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf1Kbps = 0b00000001;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf4Kbps = 0b00000010;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf16Kbps =
    0b00000011;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf64Kbps =
    0b00000100;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf256Kbps =
    0b00000101;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf1Mbps = 0b00000110;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf4Mbps = 0b00000111;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf16Mbps =
    0b00001000;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf64Mbps =
    0b00001001;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf256Mbps =
    0b00001010;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf1Gbps = 0b00001011;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf4Gbps = 0b00001100;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf16Gbps =
    0b00001101;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf64Gbps =
    0b00001110;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf256Gbps =
    0b00001111;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf1Tbps = 0b00010000;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf4Tbps = 0b00010001;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf16Tbps =
    0b00010010;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf64Tbps =
    0b00010011;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf256Tbps =
    0b00010100;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf1Pbps = 0b00010101;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf4Pbps = 0b00010110;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf16Pbps =
    0b00010111;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf64Pbps =
    0b00011000;
constexpr uint8_t kBitRateUnitValueIsIncrementedInMultiplesOf256Pbps =
    0b00011001;

typedef struct {
  uint8_t unit;
  uint16_t value;
} BitRate;

#endif /* FILE_3GPP_COMMONS_SEEN */
