################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################

SET(UTILS_DIR ${SRC_TOP_DIR}/common/utils)

target_include_directories(${NF_TARGET} PUBLIC ${UTILS_DIR})
target_sources(${NF_TARGET} PRIVATE
        ${UTILS_DIR}/fqdn.cpp
        ${UTILS_DIR}/nf_launch.cpp
        ${UTILS_DIR}/options.cpp
        )
