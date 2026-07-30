# SPDX-License-Identifier: LicenseRef-CSSL-1.0

cmake_minimum_required (VERSION 3.22.1)
project( COMMON )

include_directories(${COMMON_DIR})
include_directories(${LOGGER_DIR})
include_directories(${UTILS_DIR})
include_directories(${UTILS_DIR}/bstr)

file(GLOB COMMON_src_files
    ${COMMON_DIR}/*.cpp
    ${COMMON_DIR}/*.c
)

add_library(COMMON STATIC ${COMMON_src_files})

target_link_libraries( COMMON -Wl,--start-group UTILS LOGGER -lfmt -Wl,--end-group )

