# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(PCF_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/pcf)

include_directories(${PCF_MODEL_DIR})

list(REMOVE_DUPLICATES USED_PCF_MODEL_SRC_FILES)

# Here, we expect that in NF build directory or in other models (e.g. NRF) selected common_models are written to
# ${USED_COMMON_MODEL_SRC_FILES} to speed up the build (more performant than just adding all models)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${PCF_MODEL_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${USED_PCF_MODEL_SRC_FILES}
            )
endif()
