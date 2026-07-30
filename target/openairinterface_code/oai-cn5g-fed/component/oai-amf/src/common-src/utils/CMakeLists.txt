################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
cmake_minimum_required (VERSION 3.22.1)
project( UTILS )

include_directories(${3GPP_DIR})
include_directories(${COMMON_DIR})
include_directories(${ITTI_DIR})
include_directories(${MODEL_DIR})
include_directories(${UTILS_DIR})
include_directories(${UTILS_DIR}/bstr)
include_directories(${LOGGER_DIR})
include_directories(${NAS_DIR}/common)
include_directories(${NAS_DIR}/utils)

file(GLOB UTILS_src_files
    ${UTILS_DIR}/bstr/*.c
    ${UTILS_DIR}/*.cpp
    ${UTILS_DIR}/*.c
)

add_library(UTILS STATIC ${UTILS_src_files})

target_link_libraries( UTILS -Wl,--start-group LOGGER -lfmt -lyaml-cpp -Wl,--end-group )

