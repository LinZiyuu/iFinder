# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/nssf)
include_directories(${SRC_TOP_DIR}/api-server/api)
include_directories(${SRC_TOP_DIR}/api-server/impl)
include_directories(${SRC_TOP_DIR}/api-server/)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nssf)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)

add_library (NSSF STATIC
  nssf_app.cpp
  nssf_config.cpp
  nssf_config_types.cpp
  nssf_slice_selection.cpp
  nssf_slice_availability.cpp
  )
