################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
set(NGAP_DIR "${SRC_TOP_DIR}/${MOUNTED_COMMON}/ngap")
file(GLOB NGAP_lib_c_src_files
  *.c
   ${NGAP_DIR}/libngap_ies/*.c
)
add_library (NGAP_LIB_C STATIC
  ${NGAP_lib_c_src_files}
)


target_include_directories(NGAP_LIB_C PUBLIC ${NGAP_DIR}/libngap)
