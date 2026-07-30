# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(CONFIG_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)

SET(CONFIG_SRC_FILES
        ${CONFIG_DIR}/config.cpp
        ${CONFIG_DIR}/config_types.cpp
        ${CONFIG_DIR}/config_yaml_file.cpp
        )

## CONFIG used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
target_include_directories(${NF_TARGET} PUBLIC ${CONFIG_DIR})
target_sources(${NF_TARGET} PRIVATE
        ${CONFIG_SRC_FILES}
        )
endif()
