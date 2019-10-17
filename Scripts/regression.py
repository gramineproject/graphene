import contextlib
import os
import pathlib
import signal
import subprocess
import unittest

HAS_SGX = os.environ.get('SGX') == '1'

def expectedFailureIf(predicate):
    if predicate:
        return unittest.expectedFailure
    return lambda func: func

class RegressionTestCase(unittest.TestCase):
    LOADER_ENV = 'PAL_LOADER'
    DEFAULT_TIMEOUT = (20 if HAS_SGX else 10)

    def get_manifest(self, filename):
        return filename + '.manifest' + ('.sgx' if HAS_SGX else '')

    def run_binary(self, args, *, timeout=None, **kwds):
        timeout = (max(self.DEFAULT_TIMEOUT, timeout) if timeout is not None
            else self.DEFAULT_TIMEOUT)

        try:
            loader = os.environ[self.LOADER_ENV]
        except KeyError:
            self.skipTest(
                'environment variable {} unset'.format(self.LOADER_ENV))

        if not pathlib.Path(loader).exists():
            self.skipTest('loader ({}) not found'.format(loader))

        with subprocess.Popen([loader, *args],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                preexec_fn=os.setpgrp,
                **kwds) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                self.fail('timeout ({} s) expired'.format(timeout))

            if process.returncode:
                raise subprocess.CalledProcessError(
                    process.returncode, args, stdout, stderr)

        return stdout.decode(), stderr.decode()

    def run_native_binary(self, args, *, timeout=None, **kwds):
        timeout = (max(self.DEFAULT_TIMEOUT, timeout) if timeout is not None
            else self.DEFAULT_TIMEOUT)

        with subprocess.Popen([*args],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                preexec_fn=os.setpgrp,
                **kwds) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                self.fail('timeout ({} s) expired'.format(timeout))

            if process.returncode:
                raise subprocess.CalledProcessError(
                    process.returncode, args, stdout, stderr)

        return stdout.decode(), stderr.decode()

    @contextlib.contextmanager
    def expect_returncode(self, returncode):
        if returncode == 0:
            raise ValueError('expected returncode should be nonzero')
        try:
            yield
            self.fail('did not fail (expected {})'.format(returncode))
        except subprocess.CalledProcessError as e:
            self.assertEqual(e.returncode, returncode,
                'failed with returncode {} (expected {})'.format(
                    e.returncode, returncode))
