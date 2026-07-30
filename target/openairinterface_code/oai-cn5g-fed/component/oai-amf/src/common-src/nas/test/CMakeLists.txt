################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
cmake_minimum_required (VERSION 3.22.1)
enable_testing()
include(GoogleTest)

include_directories(${3GPP_DIR})
include_directories(${COMMON_DIR})
include_directories(${LOGGER_DIR})
include_directories(${MODEL_DIR})
include_directories(${NAS_DIR}/5gmm-msgs)
include_directories(${NAS_DIR}/common)
include_directories(${NAS_DIR}/ies)
include_directories(${NAS_DIR}/utils)
include_directories(${UTILS_DIR})
include_directories(${UTILS_DIR}/bstr)

file(GLOB NAS_TEST_src_files
    ${NAS_TEST_DIR}/*.cpp
)
