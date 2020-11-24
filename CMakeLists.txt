# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(mbed-os-atecc608a INTERFACE)

add_subdirectory(mbed-cryptoauthlib)

target_include_directories(mbed-os-atecc608a
    INTERFACE
        .
)

target_sources(mbed-os-atecc608a
    INTERFACE
        atecc608a_se.c
)

target_link_libraries(mbed-os-atecc608a
    INTERFACE
        mbed-cryptoauthlib
)
