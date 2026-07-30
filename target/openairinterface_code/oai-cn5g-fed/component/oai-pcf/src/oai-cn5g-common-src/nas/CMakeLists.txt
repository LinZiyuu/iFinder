# SPDX-License-Identifier: LicenseRef-CSSL-1.0

cmake_minimum_required (VERSION 3.22.1)
project( NAS )

include_directories(${3GPP_DIR})
include_directories(${COMMON_DIR})
include_directories(${LOGGER_DIR})
include_directories(${MODEL_DIR}/common_model)
include_directories(${NAS_DIR}/5gmm-msgs)
include_directories(${NAS_DIR}/common)
include_directories(${NAS_DIR}/ies)
include_directories(${NAS_DIR}/utils)
include_directories(${UTILS_DIR})
include_directories(${UTILS_DIR}/bstr)

file(GLOB NAS_src_files
    ${NAS_DIR}/common/*.cpp
    ${NAS_DIR}/5gmm-msgs/*.cpp
    ${NAS_DIR}/ies/*.cpp
    ${NAS_DIR}/utils/*.cpp
    ${NAS_DIR}/utils/*.c
)

add_library(NAS STATIC ${NAS_src_files})

target_link_libraries( NAS -Wl,--start-group LOGGER COMMON -lfmt -lspdlog -Wl,--end-group )

