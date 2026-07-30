################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
cmake_minimum_required (VERSION 3.22.1)
enable_testing()
include(GoogleTest)

include_directories(${COMMON_DIR})
include_directories(${LOGGER_DIR})
include_directories(${MODEL_DIR}/common_model)
include_directories(${NGAP_DIR}/libngap)
include_directories(${NGAP_DIR}/libngap_ies)
include_directories(${NGAP_DIR}/ngap_ies)
include_directories(${NGAP_DIR}/ngap_msgs)
include_directories(${NGAP_DIR}/utils)
include_directories(${UTILS_DIR})
include_directories(${UTILS_DIR}/bstr)

file(GLOB NGAP_TEST_src_files
    ${NGAP_TEST_DIR}/*.cpp
)

