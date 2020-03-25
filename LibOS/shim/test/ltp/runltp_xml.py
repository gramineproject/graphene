#!/usr/bin/env python3

#
# Copyright (C) 2019  Wojtek Porczyk <woju@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import abc
import argparse
import asyncio
import configparser
import logging
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import time

from lxml import etree

try:
    fspath = os.fspath
except AttributeError:
    # python < 3.6
    fspath = str

DEFAULT_CONFIG = 'ltp.cfg'
ERRORHANDLER = 'backslashreplace'

argparser = argparse.ArgumentParser()
argparser.add_argument('--config', '-c', metavar='FILENAME',
    action='append',
    type=argparse.FileType('r'),
    help='config file (default: {}); may be given multiple times'.format(
        DEFAULT_CONFIG))

argparser.add_argument('--option', '-o', metavar='KEY=VALUE',
    action='append',
    help='set an option')

argparser.add_argument('--verbose', '-v',
    action='count',
    help='increase verbosity')

argparser.add_argument('--list-executables',
    action='store_true', default=False,
    help='only list executables needed to run the suite')

argparser.add_argument('cmdfile', metavar='FILENAME',
    type=argparse.FileType('r'),
    nargs='?',
    help='cmdfile (default: stdin)')

argparser.set_defaults(
    config=None,
    option=[],
    verbose=0,
    cmdfile='-')

_log = logging.getLogger('LTP')  # pylint: disable=invalid-name


class AbnormalTestResult(Exception):
    '''Raised in some cases of test not succeeding.

    Args:
        message (str): a message to be logged
    '''

    loglevel = logging.WARNING

    def __init__(self, message, *, loglevel=None):
        super().__init__()
        self.message = message
        if loglevel is not None:
            self.loglevel = loglevel

    @abc.abstractmethod
    def apply_to(self, runner):
        '''Apply a status to a runner.

        Args:
            runner (TestRunner): runner to apply the status to
        '''
        raise NotImplementedError()

class Fail(AbnormalTestResult):
    '''Raised when test fails nominally.'''
    def apply_to(self, runner):
        runner.failure(self.message, loglevel=self.loglevel)

class Skip(AbnormalTestResult):
    '''Raised when test is skipped.'''
    def apply_to(self, runner):
        runner.skipped(self.message, loglevel=self.loglevel)

class Error(AbnormalTestResult):
    '''Raised when test fails for external or grave reason.'''
    loglevel = logging.ERROR
    def apply_to(self, runner):
        runner.error(self.message, loglevel=self.loglevel)


class TestRunner:
    '''A runner which will run a single scenario.

    The arguments *tag* and *cmd* most likely come from parsing a scenario file.
    The command should be a simple invocation, limited to a single executable
    with arguments. Compound commands (i.e. with pipes) are not supported and
    will result in :py:exc:`Error`.

    Args:
        suite (TestSuite): a suite, for which this runner will add a result
        tag (str): a name of the test
        cmd (iterable): the command (full *argv*)
    '''
    def __init__(self, suite, tag, cmd):
        self.suite = suite
        self.tag = tag
        self.cmd = tuple(cmd)

        try:
            self.cfgsection = self.suite.config[self.tag]
        except (configparser.NoSectionError, KeyError):
            self.cfgsection = self.suite.config[
                self.suite.config.default_section]

        self.classname = self.cfgsection.get('junit-classname')
        self.log = _log.getChild(self.tag)

        self.stdout = None
        self.stderr = None
        self.time = None
        self.props = {}

        self._added_result = False


    def _add_result(self):
        if self._added_result:
            raise RuntimeError('multiple results for a testcase')
        self._added_result = True

        element = etree.Element('testcase',
            classname=self.classname, name=self.tag)

        self.suite.add_result(element)
        self.suite.inc('tests')

        if self.time is not None:
            element.set('time', '{:.3f}'.format(self.time))
            self.suite.inc('time', self.time, type=float, fmt='.3f')

        if self.stdout is not None:
            etree.SubElement(element, 'system-out').text = self.stdout
        if self.stderr is not None:
            etree.SubElement(element, 'system-err').text = self.stderr

        if self.props:
            properties = etree.SubElement(element, 'properties')
            for name, value in self.props.items():
                etree.SubElement(properties, 'property',
                    name=str(name), value=str(value))

        return element

    def success(self, *, loglevel=logging.INFO):
        '''Add a success to the report'''
        # pylint: disable=redefined-outer-name
        self.log.log(loglevel, '-> PASS')
        self._add_result()

    def failure(self, message, *, loglevel=logging.WARNING):
        '''Add a nominal failure to the report

        Args:
            message (str): a message to display (“Stack Trace” in Jenkins)
        '''
        # pylint: disable=redefined-outer-name
        self.log.log(loglevel, '-> FAIL (%s)', message)
        etree.SubElement(self._add_result(), 'failure', message=message)
        self.suite.inc('failures')

    def error(self, message, *, loglevel=logging.ERROR):
        '''Add an error to the report

        Args:
            message (str): a message to display
        '''
        # pylint: disable=redefined-outer-name
        self.log.log(loglevel, '-> ERROR (%s)', message)
        etree.SubElement(self._add_result(), 'error').text = message
        self.suite.inc('errors')

    def skipped(self, message, *, loglevel=logging.WARNING):
        '''Add a skipped test to the report

        Args:
            message (str): a message to display (“Skip Message” in Jenkins)
        '''
        # pylint: disable=redefined-outer-name
        self.log.log(loglevel, '-> SKIP (%s)', message)
        etree.SubElement(self._add_result(), 'skipped').text = message
        self.suite.inc('skipped')


    def _prepare(self):
        '''Common initalisation

        This is used in two ways, so was refactored to a separate function
        '''

        if self.cfgsection.getboolean('skip', fallback=False):
            raise Skip('skipped via config', loglevel=logging.INFO)

        if any(c in self.cmd for c in ';|&'):
            # This is a shell command which would spawn multiple processes.
            # We don't run those in unit tests.
            if 'must-pass' in self.cfgsection:
                raise Error('invalid shell command with must-pass')
            else:
                raise Skip('invalid shell command')

    def get_executable_name(self):
        '''Return the executable name, or :py:obj:`None` if the test will not
        run.'''
        try:
            self._prepare()
        except AbnormalTestResult:
            return None
        else:
            return self.cmd[0]

    async def _run_cmd(self):
        '''Actually run the test and possibly set various attributes that result
        from the test run.

        Raises:
            AbnormalTestResult: for assorted failures
        '''
        cmd = [*self.suite.loader, *self.cmd]
        timeout = self.cfgsection.getfloat('timeout')
        self.log.info('starting %r with timeout %d', cmd, timeout)
        start_time = time.time()

        # pylint: disable=subprocess-popen-preexec-fn
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=fspath(self.suite.bindir),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
            close_fds=True)

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout)

        except asyncio.TimeoutError:
            self.time = time.time() - start_time

            if sys.version_info >= (3, 7):
                # https://bugs.python.org/issue32751 (fixed in 3.7) causes
                # proc.communicate() task inside wait_for() to be cancelled,
                # but it most likely didn't get scheduled, so the coroutine
                # inside is still waiting for CancelledError delivery and is not
                # actually done waiting for stdio. No two tasks should await the
                # same input. Rather than reimplement fix for the bug, better
                # update, hence the warning.
                self.stdout = (await proc.stdout.read()).decode(
                    errors=ERRORHANDLER)
                self.stderr = (await proc.stderr.read()).decode(
                    errors=ERRORHANDLER)
            else:
                self.log.warning('cannot extract stdio on python < 3.7')

            raise Error('Timed out after {} s.'.format(timeout))

        finally:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

        self.time = time.time() - start_time

        assert proc.pid is not None
        self.log.info('finished pid=%d time=%.3f returncode=%d stdout=%r',
            proc.pid, self.time, proc.returncode, stdout)
        if stderr:
            self.log.info('stderr=%r', stderr)

        self.props['returncode'] = proc.returncode

        self.stdout, self.stderr = (stream.decode(errors=ERRORHANDLER)
            for stream in (stdout, stderr))

        return proc.returncode

    async def execute(self):
        '''Execute the test, parse the results and add report in the suite.'''
        try:
            self._prepare()

            async with self.suite.semaphore:
                returncode = await self._run_cmd()

            must_pass = self.cfgsection.getintset('must-pass')
            if must_pass is None:
                if returncode != 0:
                    raise Fail('returncode={}'.format(returncode))
                return

            self._parse_test_output(must_pass)

        except AbnormalTestResult as result:
            result.apply_to(self)

        else:
            self.success()

    def _parse_test_output(self, must_pass):
        '''Parse the output

        This is normally done only for a test that has non-empty ``must-pass``
        config directive.
        '''
        # pylint: disable=too-many-branches

        notfound = must_pass.copy()
        passed = set()
        failed = set()
        skipped = set()
        dontcare = set()

        # on empty must_pass, it is always needed
        maybe_unneeded_must_pass = bool(must_pass)

        subtest = 0
        for line in self.stdout.split('\n'):
            self.log.debug('<- %r', line)

            if line == 'Summary:':
                break

            # Drop this line so that we get consistent offsets
            if line == 'WARNING: no physical memory support, process creation may be slow.':
                continue

            tokens = line.split()
            if len(tokens) < 2:
                continue

            if 'INFO' in line:
                continue

            if tokens[1].isdigit():
                subtest = int(tokens[1])
            else:
                subtest += 1

            try:
                notfound.remove(subtest)
            except KeyError:
                # subtest is not in must-pass
                maybe_unneeded_must_pass = False

            if 'TPASS' in line or 'PASS:' in line:
                if subtest in must_pass:
                    passed.add(subtest)
                else:
                    dontcare.add(subtest)
                continue

            if any(t in line for t in (
                    'TFAIL', 'FAIL:', 'TCONF', 'CONF:', 'TBROK', 'BROK:')):
                if subtest in must_pass:
                    failed.add(subtest)
                    maybe_unneeded_must_pass = False
                else:
                    skipped.add(subtest)
                continue

            #self.error(line, subtest=subtest)
            self.log.info('additional info: %s', line)


        self.props.update(
            must_pass=', '.join(str(i) for i in sorted(must_pass)),
            passed=', '.join(str(i) for i in sorted(passed)),
            failed=', '.join(str(i) for i in sorted(failed)),
            skipped=', '.join(str(i) for i in sorted(skipped)),
            notfound=', '.join(str(i) for i in sorted(notfound)),
            dontcare=', '.join(str(i) for i in sorted(dontcare)),
        )

        stat = (
            'FAILED=[{failed}] '
            'NOTFOUND=[{notfound}] '
            'passed=[{passed}] '
            'dontcare=[{dontcare}] '
            'skipped=[{skipped}] '
            'returncode={returncode}'
        ).format(**self.props)

        if not (passed or failed or skipped or dontcare):
            if must_pass:
                raise Error('binary did not provide any subtests, see stdout '
                    '(returncode={returncode}, must-pass=[{must_pass}])'.format(
                        **self.props))
            else:
                raise Skip('binary without subtests, see stdout '
                        '(returncode={returncode})'.format(**self.props))

        if maybe_unneeded_must_pass and not notfound:
            # all subtests passed and must-pass specified exactly all subtests
            raise Error(
                'must-pass is unneeded, remove it from config ({})'.format(stat)
            )

        if failed or notfound:
            raise Fail('some required subtests failed or not attempted, '
                'see stdout ({})'.format(stat))

        if not passed:
            raise Skip('all subtests skipped ({})'.format(stat))


class TestSuite:
    '''A test suite and result generator.

    Args:
        config (configparser.Configparser): configuration
    '''
    def __init__(self, config):
        self.config = config
        self.sgx = self.config.getboolean(config.default_section, 'sgx')

        self.loader = [
            fspath(config.getpath(config.default_section, 'loader').resolve())]
        if self.sgx:
            self.loader.append('SGX')

        self.bindir = (
            config.getpath(config.default_section, 'ltproot') / 'testcases/bin')

        # Running parallel tests under SGX is risky, see README.
        # However, if user wanted to do that, we shouldn't stand in the way,
        # just issue a warning.
        processes = config.getint(config.default_section, 'jobs',
            fallback=(1 if self.sgx else len(os.sched_getaffinity(0))))
        if self.sgx and processes != 1:
            _log.warning('WARNING: SGX is enabled and jobs = %d (!= 1);'
                ' expect stability issues', processes)

        self.semaphore = asyncio.BoundedSemaphore(processes)
        self.queue = []
        self.xml = etree.Element('testsuite')
        self.time = 0

    def add_test(self, tag, cmd):
        '''Instantiate appropriate :py:class:`TestRunner` and add it to the
        suite

        Args:
            tag (str): test case name
            cmd (iterable): command (full *argv*)
        '''
        self.queue.append(TestRunner(self, tag, cmd))

    def add_result(self, element):
        '''Add a result.

        This should only be invoked from the :py:class:`TestRunner`.

        Args:
            element (lxml.etree.Element): XML element
        '''
        self.xml.append(element)

    def get_executable_names(self):
        '''Return a list for all executables that would be run, without acutally
        running them.'''
        names = {runner.get_executable_name() for runner in self.queue}
        names.discard(None)
        return sorted(names)

    def _get(self, accumulator, *, default=0, type=int):
        # pylint: disable=redefined-builtin
        return type(self.xml.get(accumulator, default))

    def inc(self, accumulator, value=1, *, type=int, fmt=''):
        '''Increase a counter on the report.

        Args:
            accumulator (str): the counter name
            value (int or float): the increment (default: 1)
            type: the type the existing value, or callable that given a string
                would parse and return it (default: :py:class:`int`)
            fmt (str): the desired format to be stored, as accepted by
                :py:func:`format`
                (default is equivalent to what :py:func:`repr` does)
        '''
        # pylint: disable=redefined-builtin
        self.xml.set(accumulator,
            format(self._get(accumulator, type=type) + value, fmt))

    @property
    def returncode(self):
        '''A suggested return code for the application that run this test suite
        '''
        return min(255, self._get('errors') + self._get('failures'))

    def write_report(self, stream):
        '''Write the XML report to a file

        Args:
            stream: a file-like object
        '''
        stream.write(etree.tostring(self.xml, pretty_print=True))

    def log_summary(self):
        _log.warning('LTP finished'
            ' tests=%d failures=%d errors=%d skipped=%d returncode=%d',
            self._get('tests'), self._get('failures'), self._get('errors'),
            self._get('skipped'), self.returncode)

    async def execute(self):
        '''Execute the suite'''
        await asyncio.gather(*(runner.execute() for runner in self.queue))


def _getintset(value):
    return set(int(i) for i in value.strip().split())

def load_config(files):
    '''Load the configuration from a given files

    Returns:
        configparser.ConfigParser:
    '''
    config = configparser.ConfigParser(
        converters={
            'path': pathlib.Path,
            'intset': _getintset,
        },
        defaults={
            'timeout': '30',
            'sgx': 'false',
            'loader': './pal_loader',
            'ltproot': './opt/ltp',
            'junit-classname': 'apps.LTP',
        })

    for file in files:
        with file:
            config.read_file(file)

    return config

def main(args=None):
    logging.basicConfig(
        format='%(asctime)s %(name)s: %(message)s',
        level=logging.WARNING)
    args = argparser.parse_args(args)
    _log.setLevel(_log.level - args.verbose * 10)

    if args.config is None:
        args.config = [open(DEFAULT_CONFIG)]

    config = load_config(args.config)
    for token in args.option:
        key, value = token.split('=', maxsplit=1)
        config[config.default_section][key] = value

    suite = TestSuite(config)
    with args.cmdfile as file:
        for line in file:
            if line[0] in '\n#':
                continue
            tag, *cmd = shlex.split(line)
            suite.add_test(tag, cmd)

    if args.list_executables:
        print('\n'.join(suite.get_executable_names()))
        return 0

    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(suite.execute())
    finally:
        loop.close()
    suite.write_report(sys.stdout.buffer)
    suite.log_summary()
    return suite.returncode

if __name__ == '__main__':
    sys.exit(main())
