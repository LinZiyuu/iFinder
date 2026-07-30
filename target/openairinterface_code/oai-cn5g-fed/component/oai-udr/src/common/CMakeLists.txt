################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)

add_library(3GPP_COMMON_TYPES STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/conversions.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pid_file.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/string.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/fqdn.cpp
)


