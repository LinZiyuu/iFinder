# SPDX-License-Identifier: MIT

import logging
import subprocess as sp

class LocalCmd():
    def __init__(self, d = None):
        self.cwd = d
        self.cp = sp.CompletedProcess(args='', returncode=0, stdout='')

    def run(self, line, timeout=300, silent=False, reportNonZero=True):
        if not silent:
            logging.info(line)
        try:
            ret = sp.run(line, shell=True, cwd=self.cwd, stdout=sp.PIPE, stderr=sp.STDOUT, timeout=timeout)
        except Exception as e:
            ret = sp.CompletedProcess(args=line, returncode=255, stdout=f'Exception: {str(e)}'.encode('utf-8'))
        if ret.stdout is None:
            ret.stdout = b''
        ret.stdout = ret.stdout.decode('utf-8').strip()
        if reportNonZero and ret.returncode != 0:
            logging.warning(f'command "{line}" returned non-zero returncode {ret.returncode}: output:\n{ret.stdout}')
        self.cp = ret
        return ret

    def close(self):
        pass
