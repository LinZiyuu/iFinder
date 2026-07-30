#!/usr/bin/env bash

cd scripts/upg-patches/
find . -iname '*.patch' -execdir sh -c 'patch -p1 -N -d ../../vpp < $0' {} \;
