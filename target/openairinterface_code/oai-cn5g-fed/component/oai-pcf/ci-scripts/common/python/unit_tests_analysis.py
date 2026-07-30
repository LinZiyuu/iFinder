# SPDX-License-Identifier: MIT

import os
import re
import common.python.cls_cmd as cls_cmd
from common.python.generate_html import (
    generate_chapter,
    generate_button_header,
    generate_button_footer,
    generate_unit_test_table_header,
    generate_unit_test_table_footer,
    generate_unit_test_table_row,
)

class UnitTest():
    def __init__(self):
        self.id=''
        self.suite=''
        self.name=''
        self.status=False

def analyze_unit_tests_run():
    cwd = os.getcwd()
    details = ''
    chapterName = 'Unit Tests Run Analysis'
    ctest_section = False
    nb_started_tests = 0
    nb_passed_tests = 0
    list_of_tests = []
    if os.path.isfile(cwd + '/archives/build-unit-tests.log'):
        with open(f'{cwd}/archives/build-unit-tests.log', 'r') as logfile:
            for line in logfile:
                if re.search('RUN ctest -V', line) is not None:
                    ctest_section = True
                if ctest_section and re.search('Start *[0-9]*:', line) is not None:
                    nb_started_tests += 1
                    myUnitTest = UnitTest()
                ret = re.search(' (?P<test_nb>[0-9]+):.*RUN *.* (?P<test_suite>[a-zA-Z0-9]+)\\.(?P<test_name>[a-zA-Z0-9]+)', line)
                if ctest_section and ret is not None:
                    myUnitTest.id = ret.group('test_nb')
                    myUnitTest.suite = ret.group('test_suite')
                    myUnitTest.name = ret.group('test_name')
                ret_passed = re.search(' (?P<test_nb>[0-9]+): .*PASSED .* 1 ', line)
                ret_failed = re.search(' (?P<test_nb>[0-9]+): .*FAILED .* 1 ', line)
                if ctest_section and ret_passed is not None:
                    if ret_passed.group('test_nb') == myUnitTest.id:
                        myUnitTest.status = True
                        nb_passed_tests += 1
                        list_of_tests.append(myUnitTest)
                elif ctest_section and ret_failed is not None:
                    if ret_failed.group('test_nb') == myUnitTest.id:
                        list_of_tests.append(myUnitTest)

        if not ctest_section:
            details += generate_chapter(chapterName, 'Unit Tests were NOT run.', False)
        elif nb_started_tests > 0 and nb_passed_tests == nb_started_tests:
            details += generate_chapter(chapterName, f'All Unit Tests were run and PASSED ({nb_passed_tests}/{nb_started_tests}).', True)
        else:
            details += generate_chapter(chapterName, f'Some Unit Tests were run and FAILED ({nb_passed_tests}/{nb_started_tests}).', False)

        if ctest_section:
            details += generate_button_header('oai-unit-test-details', 'More details on Unit Test results')
            details += generate_unit_test_table_header()
            for test in list_of_tests:
                details += generate_unit_test_table_row(test.id, test.suite, test.name, test.status)
            details += generate_unit_test_table_footer()
            details += generate_button_footer()
    else:
        details += generate_chapter(chapterName, 'Was NOT performed.', False)
    return details
