#!/bin/bash
# SPDX-License-Identifier: MIT

STATUS=0

RESULT=$(ps aux | grep -v nohup || true)
SUB='/openair-nef/bin/oai_nef -c /openair-nef/etc/nef.conf -o'
if [[ $RESULT =~ $SUB ]]; then
    STATUS=0
else
   STATUS=-1
fi

exit $STATUS
