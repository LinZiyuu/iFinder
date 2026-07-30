# SPDX-License-Identifier: MIT

import argparse
import re

def _parse_args() -> argparse.Namespace:
    """Parse the command line args

    Returns:
        argparse.Namespace: the created parser
    """
    example_text = '''example:
        ./generateHtmlReport.py --help'''

    parser = argparse.ArgumentParser(description='OAI 5G CORE NETWORK Utility tool',
                                    epilog=example_text,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)

    # Pipeline Name
    parser.add_argument(
        '--job-name', '-jn',
        action='store',
        help='Pipeline name',
    )

    # Build Number
    parser.add_argument(
        '--build-id', '-id',
        action='store',
        help='Build ID or number',
    )

    # Build URL
    parser.add_argument(
        '--build-url',
        action='store',
        help='Build URL',
    )

    # GIT repo URL
    parser.add_argument(
        '--git-url',
        action='store',
        help='GIT repo URL',
    )

    # GIT source branch
    parser.add_argument(
        '--git-src-branch',
        action='store',
        help='GIT source branch',
    )

    # GIT source commit
    parser.add_argument(
        '--git-src-commit',
        action='store',
        help='GIT source commit (SHA-ONE)',
    )

    # GIT MR or PR
    parser.add_argument(
        '--git-merge-request',
        action='store_true',
        default=False,
        help='GIT source commit (SHA-ONE)',
    )

    # GIT destination branch
    parser.add_argument(
        '--git-dst-branch',
        action='store',
        help='GIT destination branch',
    )

    # GIT destination commit
    parser.add_argument(
        '--git-dst-commit',
        action='store',
        help='GIT destination commit (SHA-ONE)',
    )

    args, unknown = parser.parse_known_args()
    return args
