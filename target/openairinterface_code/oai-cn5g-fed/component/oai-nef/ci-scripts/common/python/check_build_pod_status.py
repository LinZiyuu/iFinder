#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import logging
import re
import sys
import time
import cls_cmd

logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stdout,
    format="[%(asctime)s] %(levelname)8s: %(message)s"
)

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Checking Build Pod Status')

    parser.add_argument(
        '--pod-name', '-pn',
        action='store',
        required=True,
        help='Build Pod name',
    )

    parser.add_argument(
        '--log-file', '-l',
        action='store',
        required=True,
        help='Log file location',
    )
    return parser.parse_args()

if __name__ == '__main__':
    args = _parse_args()
    status = 0
    cnt = 0
    myCmds = cls_cmd.LocalCmd()
    while cnt < 6*30:
        ret = myCmds.run(f'oc get pods | grep {args.pod_name}', silent = True)
        if ret.stdout.count('Completed') > 0:
            cnt = 1000
            status = 0
        elif ret.stdout.count('Error') > 0:
            cnt = 1000
            status = -1
        else:
            cnt += 1
            time.sleep(10)
    if cnt < 500:
        status = -2
    # Storing the build logs all the time
    myCmds.run(f'oc logs {args.pod_name} > {args.log_file} 2>&1')
    myCmds.close()
    sys.exit(status)
