/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <optional>

#include "common_defs.hpp"
#include "logger_base.hpp"

namespace oai::nas {

class NasHelper {
 public:
  template<typename T>
  static int Encode(
      std::optional<T>& ie, uint8_t*& buf, int& len,
      int& encoded_size) noexcept {
    if (!ie.has_value()) {
      oai::logger::logger_common::nas().debug(
          "IE %s is not available", T::GetIeName().c_str());
      return KEncodeDecodeOK;
    } else {
      int encoded_ie_size =
          ie.value().Encode(buf + encoded_size, len - encoded_size);
      if (encoded_ie_size != KEncodeDecodeError) {
        encoded_size += encoded_ie_size;
        return KEncodeDecodeOK;
      } else {
        oai::logger::logger_common::nas().error(
            "Encoding %s error", T::GetIeName().c_str());
        return KEncodeDecodeError;
      }
    }
  }

  template<typename T>
  static int Encode(
      T& ie, uint8_t*& buf, int& len, int& encoded_size) noexcept {
    int encoded_ie_size = ie.Encode(buf + encoded_size, len - encoded_size);
    if (encoded_ie_size != KEncodeDecodeError) {
      encoded_size += encoded_ie_size;
      return KEncodeDecodeOK;
    } else {
      oai::logger::logger_common::nas().error(
          "Encoding %s error", T::GetIeName().c_str());
      return KEncodeDecodeError;
    }
  }

  template<typename T>
  static int Decode(
      std::optional<T>& ie, uint8_t*& buf, int& len, int& decoded_size,
      bool iei) noexcept {
    T ie_tmp = {};
    int decoded_result =
        ie_tmp.Decode(buf + decoded_size, len - decoded_size, iei);
    if (decoded_result == KEncodeDecodeError) {
      oai::logger::logger_common::nas().error(
          "Decoding %s error", T::GetIeName().c_str());
      return KEncodeDecodeError;
    }
    decoded_size += decoded_result;
    ie = std::optional<T>(ie_tmp);
    return KEncodeDecodeOK;
  }

  template<typename T>
  static int Decode(
      std::optional<T>& ie, uint8_t iei_value, uint8_t*& buf, int& len,
      int& decoded_size, bool iei) noexcept {
    T ie_tmp(iei_value);
    int decoded_result =
        ie_tmp.Decode(buf + decoded_size, len - decoded_size, iei);
    if (decoded_result == KEncodeDecodeError) {
      oai::logger::logger_common::nas().error(
          "Decoding %s error", T::GetIeName().c_str());
      return KEncodeDecodeError;
    }
    decoded_size += decoded_result;
    ie = std::optional<T>(ie_tmp);
    return KEncodeDecodeOK;
  }

  template<typename T>
  static int Decode(
      std::optional<T>& ie, uint8_t*& buf, int& len, int& decoded_size,
      bool high_pos, bool iei) noexcept {
    T ie_tmp = {};
    int decoded_result =
        ie_tmp.Decode(buf + decoded_size, len - decoded_size, high_pos, iei);
    if (decoded_result == KEncodeDecodeError) {
      oai::logger::logger_common::nas().error(
          "Decoding %s error", T::GetIeName().c_str());
      return KEncodeDecodeError;
    }
    decoded_size += decoded_result;
    ie = std::optional<T>(ie_tmp);
    return KEncodeDecodeOK;
  }

  template<typename T>
  static int Decode(
      T& ie, uint8_t*& buf, int& len, int& decoded_size, bool iei) noexcept {
    int decoded_result = ie.Decode(buf + decoded_size, len - decoded_size, iei);
    if (decoded_result == KEncodeDecodeError) {
      oai::logger::logger_common::nas().error(
          "Decoding %s error", T::GetIeName().c_str());
      return KEncodeDecodeError;
    }
    decoded_size += decoded_result;
    return KEncodeDecodeOK;
  }

  template<typename T>
  static int Decode(
      T& ie, uint8_t*& buf, int& len, int& decoded_size, bool high_pos,
      bool iei) noexcept {
    int decoded_result =
        ie.Decode(buf + decoded_size, len - decoded_size, high_pos, iei);
    if (decoded_result == KEncodeDecodeError) {
      oai::logger::logger_common::nas().error(
          "Decoding %s error", T::GetIeName().c_str());
      return KEncodeDecodeError;
    }
    decoded_size += decoded_result;
    return KEncodeDecodeOK;
  }
};

}  // namespace oai::nas
