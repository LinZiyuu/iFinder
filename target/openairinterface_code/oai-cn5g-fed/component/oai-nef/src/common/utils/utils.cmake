# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(UTILS_DIR ${SRC_TOP_DIR}/common/utils)

## Logger used in NF_TARGET (main)
target_include_directories(${NF_TARGET} PUBLIC ${UTILS_DIR})
target_sources(${NF_TARGET} PRIVATE
    ${UTILS_DIR}/conversions.cpp
    ${UTILS_DIR}/3gpp_conversions.cpp
    ${UTILS_DIR}/if.cpp
    ${UTILS_DIR}/pid_file.cpp
    ${UTILS_DIR}/string.cpp
    ${UTILS_DIR}/thread_sched.cpp
    ${UTILS_DIR}/fqdn.cpp
        )
