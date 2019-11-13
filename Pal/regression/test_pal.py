#!/usr/bin/env python3

import ast
import collections
import mmap
import os
import pathlib
import random
import shutil
import string
import subprocess
import sys
import unittest

from regression import (
    HAS_SGX,
    RegressionTestCase,
    expectedFailureIf,
)

if HAS_SGX:
    sys.path.insert(0, os.path.dirname(__file__) + '/../src/host/Linux-SGX/signer')
    from pal_sgx_sign import read_manifest

CPUINFO_FLAGS_WHITELIST = [
    'fpu', 'vme', 'de', 'pse', 'tsc', 'msr', 'pae', 'mce', 'cx8', 'apic', 'sep',
    'mtrr', 'pge', 'mca', 'cmov', 'pat', 'pse36', 'pn', 'clflush', 'dts',
    'acpi', 'mmx', 'fxsr', 'sse', 'sse2', 'ss', 'ht', 'tm', 'ia64', 'pbe',
]


class TC_00_Basic(RegressionTestCase):
    def test_000_atomic_math(self):
        _, stderr = self.run_binary(['AtomicMath'])
        self.assertIn('Subtract INT_MIN: Both values match 2147483648', stderr)
        self.assertIn('Subtract INT_MAX: Both values match -2147483647', stderr)
        self.assertIn('Subtract LLONG_MIN: Both values match -9223372036854775808', stderr)
        self.assertIn('Subtract LLONG_MAX: Both values match -9223372036854775807', stderr)

    def test_001_path_normalization(self):
        _, stderr = self.run_binary(['normalize_path'])

        self.assertIn("Success!\n", stderr)

class TC_01_Bootstrap(RegressionTestCase):
    def test_100_basic_boostrapping(self):
        stdout, stderr = self.run_binary(['Bootstrap'])

        # Basic Bootstrapping
        self.assertIn('User Program Started', stderr)

        # Control Block: Executable Name
        self.assertIn('Loaded Executable: file:Bootstrap', stderr)

        # One Argument Given
        self.assertIn('# of Arguments: 1', stderr)
        self.assertIn('argv[0] = Bootstrap', stderr)

        # Control Block: Debug Stream (Inline)
        self.assertIn('Written to Debug Stream', stdout)

        # Control Block: Allocation Alignment
        self.assertIn('Allocation Alignment: {}'.format(mmap.ALLOCATIONGRANULARITY), stderr)

        # Control Block: Executable Range
        self.assertIn('Executable Range OK', stderr)

    def test_101_basic_boostrapping_five_arguments(self):
        _, stderr = self.run_binary(['Bootstrap', 'a', 'b', 'c', 'd'])

        # Five Arguments Given
        self.assertIn('# of Arguments: 5', stderr)
        self.assertIn('argv[1] = a', stderr)
        self.assertIn('argv[2] = b', stderr)
        self.assertIn('argv[3] = c', stderr)
        self.assertIn('argv[4] = d', stderr)

    def test_102_cpuinfo(self):
        with open('/proc/cpuinfo') as file_:
            cpuinfo = file_.read().strip().split('\n\n')[-1]
        cpuinfo = dict(map(str.strip, line.split(':'))
            for line in cpuinfo.split('\n'))
        if 'flags' in cpuinfo:
            cpuinfo['flags'] = ' '.join(flag for flag in cpuinfo['flags']
                if flag in CPUINFO_FLAGS_WHITELIST)

        _, stderr = self.run_binary(['Bootstrap'])

        self.assertIn('CPU num: {}'.format(int(cpuinfo['processor']) + 1),
            stderr)
        self.assertIn('CPU vendor: {[vendor_id]}'.format(cpuinfo), stderr)
        self.assertIn('CPU brand: {[model name]}'.format(cpuinfo), stderr)
        self.assertIn('CPU family: {[cpu family]}'.format(cpuinfo), stderr)
        self.assertIn('CPU model: {[model]}'.format(cpuinfo), stderr)
        self.assertIn('CPU stepping: {[stepping]}'.format(cpuinfo), stderr)
        self.assertIn('CPU flags: {[flags]}'.format(cpuinfo), stderr)

    def test_103_dotdot(self):
        _, stderr = self.run_binary(['..Bootstrap'])
        self.assertIn('User Program Started', stderr)

    def test_104_manifest_as_executable_name(self):
        manifest = self.get_manifest('Bootstrap2')
        _, stderr = self.run_binary([manifest])
        self.assertIn('User Program Started', stderr)
        self.assertIn('Loaded Manifest: file:' + manifest, stderr)

    def test_105_manifest_as_argument(self):
        manifest = self.get_manifest('Bootstrap4')
        _, stderr = self.run_binary([manifest])
        self.assertIn('Loaded Manifest: file:' + manifest, stderr)
        self.assertIn('Loaded Executable: file:Bootstrap', stderr)

    def test_106_manifest_with_shebang(self):
        manifest = self.get_manifest('Bootstrap4')
        _, stderr = self.run_binary(['./' + manifest])
        self.assertIn('Loaded Manifest: file:' + manifest, stderr)
        self.assertIn('Loaded Executable: file:Bootstrap', stderr)
        self.assertIn('argv[0] = Bootstrap', stderr)

    @unittest.skipUnless(HAS_SGX, 'need SGX')
    def test_107_manifest_with_nonelf_binary(self):
        manifest = self.get_manifest('nonelf_binary')
        #Expect return code is -ENOEXEC(248 as unsigned char)
        with self.expect_returncode(248):
            self.run_binary([manifest])

    def test_110_preload_libraries(self):
        _, stderr = self.run_binary(['Bootstrap3'])
        self.assertIn('Binary 1 Preloaded', stderr)
        self.assertIn('Binary 2 Preloaded', stderr)
        self.assertIn('Preloaded Function 1 Called', stderr)
        self.assertIn('Preloaded Function 2 Called', stderr)

    def test_111_preload_libraries(self):
        # Bootstrap without Executable but Preload Libraries
        _, stderr = self.run_binary([self.get_manifest('Bootstrap5')])
        self.assertIn('Binary 1 Preloaded', stderr)
        self.assertIn('Binary 2 Preloaded', stderr)

    @unittest.skipUnless(HAS_SGX, 'this test requires SGX')
    def test_120_8gb_enclave(self):
        manifest = self.get_manifest('Bootstrap6')
        _, stderr = self.run_binary([manifest], timeout=360)
        self.assertIn('Loaded Manifest: file:' + manifest, stderr)
        self.assertIn('Executable Range OK', stderr)

    def test_130_large_number_of_items_in_manifest(self):
        _, stderr = self.run_binary([self.get_manifest('Bootstrap7')])
        self.assertIn('key1000=na', stderr)
        self.assertIn('key1=na', stderr)

    @unittest.skip('this is broken on non-SGX, see #860')
    def test_140_missing_executable_and_manifest(self):
        try:
            _, stderr = self.run_binary(['fakenews'])
            self.fail(
                'expected non-zero returncode, stderr: {!r}'.format(stderr))
        except subprocess.CalledProcessError as e:
            self.assertIn('USAGE: ', e.stderr.decode())

class TC_02_Symbols(RegressionTestCase):
    ALL_SYMBOLS = [
        'DkVirtualMemoryAlloc',
        'DkVirtualMemoryFree',
        'DkVirtualMemoryProtect',
        'DkProcessCreate',
        'DkProcessExit',
        'DkStreamOpen',
        'DkStreamWaitForClient',
        'DkStreamRead',
        'DkStreamWrite',
        'DkStreamDelete',
        'DkStreamMap',
        'DkStreamUnmap',
        'DkStreamSetLength',
        'DkStreamFlush',
        'DkSendHandle',
        'DkReceiveHandle',
        'DkStreamAttributesQuery',
        'DkStreamAttributesQueryByHandle',
        'DkStreamAttributesSetByHandle',
        'DkStreamGetName',
        'DkStreamChangeName',
        'DkThreadCreate',
        'DkThreadDelayExecution',
        'DkThreadYieldExecution',
        'DkThreadExit',
        'DkThreadResume',
        'DkSetExceptionHandler',
        'DkExceptionReturn',
        'DkMutexCreate',
        'DkMutexRelease',
        'DkNotificationEventCreate',
        'DkSynchronizationEventCreate',
        'DkEventSet',
        'DkEventClear',
        'DkSynchronizationObjectWait',
        'DkStreamsWaitEvents',
        'DkObjectClose',
        'DkSystemTimeQuery',
        'DkRandomBitsRead',
        'DkInstructionCacheFlush',
        'DkSegmentRegister',
        'DkMemoryAvailableQuota',
    ]

    def test_000_symbols(self):
        _, stderr = self.run_binary(['Symbols'])
        found_symbols = dict(line.split(' = ')
            for line in stderr.strip().split('\n') if line.startswith('Dk'))
        self.assertCountEqual(found_symbols, self.ALL_SYMBOLS)
        for k, value in found_symbols.items():
            value = ast.literal_eval(value)
            self.assertNotEqual(value, 0, 'symbol {} has value 0'.format(k))

class TC_10_Exception(RegressionTestCase):
    def test_000_exception(self):
        _, stderr = self.run_binary(['Exception'])

        # Exception Handling (Div-by-Zero)
        self.assertIn('Arithmetic Exception Handler', stderr)

        # Exception Handling (Memory Fault)
        self.assertIn('Memory Fault Exception Handler', stderr)

        # Exception Handler Swap
        self.assertIn('Arithmetic Exception Handler 1', stderr)
        self.assertIn('Arithmetic Exception Handler 2', stderr)

        # Exception Handling (Set Context)
        self.assertIn('Arithmetic Exception Handler 1', stderr)

        # Exception Handling (Red zone)
        self.assertIn('Red zone test ok.', stderr)

class TC_20_SingleProcess(RegressionTestCase):
    def test_000_exit_code(self):
        with self.expect_returncode(112):
            self.run_binary(['Exit'])

    def test_100_file(self):
        try:
            pathlib.Path('file_nonexist.tmp').unlink()
        except FileNotFoundError:
            pass
        pathlib.Path('file_delete.tmp').touch()

        with open('File', 'rb') as file_:
            file_exist = file_.read()

        _, stderr = self.run_binary(['File'])

        # Basic File Opening
        self.assertIn('File Open Test 1 OK', stderr)
        self.assertIn('File Open Test 2 OK', stderr)
        self.assertIn('File Open Test 3 OK', stderr)

        # Basic File Creation
        self.assertIn('File Creation Test 1 OK', stderr)
        self.assertIn('File Creation Test 2 OK', stderr)
        self.assertIn('File Creation Test 3 OK', stderr)

        # File Reading
        self.assertIn('Read Test 1 (0th - 40th): {}'.format(
            file_exist[0:40].hex()), stderr)
        self.assertIn('Read Test 2 (0th - 40th): {}'.format(
            file_exist[0:40].hex()), stderr)
        self.assertIn('Read Test 3 (200th - 240th): {}'.format(
            file_exist[200:240].hex()), stderr)

        # File Writing
        with open('file_nonexist.tmp', 'rb') as file_:
            file_nonexist = file_.read()

        self.assertEqual(file_exist[0:40], file_nonexist[200:240])
        self.assertEqual(file_exist[200:240], file_nonexist[0:40])

        # File Attribute Query
        self.assertIn('Query: type = ', stderr)
        self.assertIn(', size = {}'.format(len(file_exist)), stderr)

        # File Attribute Query by Handle
        self.assertIn('Query by Handle: type = ', stderr)
        self.assertIn(', size = {}'.format(len(file_exist)), stderr)

        # File Mapping
        self.assertIn(
            'Map Test 1 (0th - 40th): {}'.format(file_exist[0:40].hex()),
            stderr)
        self.assertIn(
            'Map Test 2 (200th - 240th): {}'.format(file_exist[200:240].hex()),
            stderr)
        self.assertIn(
            'Map Test 3 (4096th - 4136th): {}'.format(file_exist[4096:4136].hex()),
            stderr)
        self.assertIn(
            'Map Test 4 (4296th - 4336th): {}'.format(file_exist[4296:4336].hex()),
            stderr)

        # Set File Length
        self.assertEqual(
            pathlib.Path('file_nonexist.tmp').stat().st_size,
            mmap.ALLOCATIONGRANULARITY)

        # File Deletion
        self.assertFalse(pathlib.Path('file_delete.tmp').exists())

    @unittest.skipUnless(HAS_SGX, 'this test requires SGX')
    def test_101_nonexist_file(self):
        # Explicitly remove the file file_nonexist_disallowed.tmp before
        # running binary. Otherwise this test will fail if these tests are
        # run repeatedly.
        os.remove('file_nonexist_disallowed.tmp')

        _, stderr = self.run_binary(['File'])

        # Run file creation for non-existing file. This behavior is
        # disallowed unless sgx.allow_file_creation is explicitly set to 1.
        self.assertIn('File Creation Test 4 OK', stderr)

    def test_110_directory(self):
        for path in ['dir_exist.tmp', 'dir_nonexist.tmp', 'dir_delete.tmp']:
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                pass

        path = pathlib.Path('dir_exist.tmp')
        files = [path / ''.join(random.choice(string.ascii_letters)
                                for _ in range(8))
                 for _ in range(5)]
        path.mkdir()
        for file_ in files:
            file_.touch()
        pathlib.Path('dir_delete.tmp').mkdir()

        _, stderr = self.run_binary(['Directory'])

        # Basic Directory Opening
        self.assertIn('Directory Open Test 1 OK', stderr)
        self.assertIn('Directory Open Test 2 OK', stderr)
        self.assertIn('Directory Open Test 3 OK', stderr)

        # Basic Directory Creation
        self.assertIn('Directory Creation Test 1 OK', stderr)
        self.assertIn('Directory Creation Test 2 OK', stderr)
        self.assertIn('Directory Creation Test 3 OK', stderr)

        # Directory Reading
        for file_ in files:
            self.assertIn('Read Directory: {}'.format(file_.name), stderr)

        # Directory Attribute Query
        self.assertIn('Query: type = ', stderr)

        # Directory Attribute Query by Handle
        self.assertIn('Query by Handle: type = ', stderr)

        # Directory Deletion
        self.assertFalse(pathlib.Path('dir_delete.tmp').exists())

    def test_200_event(self):
        _, stderr = self.run_binary(['Event'])
        self.assertIn('Wait with too short timeout ok.', stderr)
        self.assertIn('Wait with long enough timeout ok.', stderr)

    def test_210_semaphore(self):
        _, stderr = self.run_binary(['Semaphore'])

        # Semaphore: Timeout on Locked Semaphores
        self.assertIn('Locked binary semaphore timed out (1000).', stderr)
        self.assertIn('Locked binary semaphore timed out (0).', stderr)

        # Semaphore: Acquire Unlocked Semaphores
        self.assertIn('Locked binary semaphore successfully (-1).', stderr)
        self.assertIn('Locked binary semaphore successfully (0).', stderr)

    def test_300_memory(self):
        _, stderr = self.run_binary(['Memory'])

        # Memory Allocation
        self.assertIn('Memory Allocation OK', stderr)

        # Memory Allocation with Address
        self.assertIn('Memory Allocation with Address OK', stderr)

        # Get Memory Total Quota
        self.assertIn('Total Memory:', stderr)
        for line in stderr.split('\n'):
            if line.startswith('Total Memory:'):
                self.assertNotEqual(line, 'Total Memory: 0')

        # Get Memory Available Quota
        self.assertIn('Get Memory Available Quota OK', stderr)

    @expectedFailureIf(HAS_SGX)
    def test_301_memory_nosgx(self):
        _, stderr = self.run_binary(['Memory'])

        # SGX1 does not support unmapping a page or changing its permission
        # after enclave init. Therefore the memory protection and deallocation
        # tests will fail. By utilizing SGX2 it's possibile to fix this.

        # Memory Protection
        self.assertIn('Memory Allocation Protection (RW) OK', stderr)
        self.assertIn('Memory Protection (R) OK', stderr)

        # Memory Deallocation
        self.assertIn('Memory Deallocation OK', stderr)

    def test_400_pipe(self):
        _, stderr = self.run_binary(['Pipe'])

        # Pipe Creation
        self.assertIn('Pipe Creation 1 OK', stderr)

        # Pipe Attributes
        self.assertIn('Pipe Attribute Query 1 on pipesrv returned OK', stderr)

        # Pipe Connection
        self.assertIn('Pipe Connection 1 OK', stderr)

        # Pipe Transmission
        self.assertIn('Pipe Write 1 OK', stderr)
        self.assertIn('Pipe Read 1: Hello World 1', stderr)
        self.assertIn('Pipe Write 2 OK', stderr)
        self.assertIn('Pipe Read 2: Hello World 2', stderr)

    def test_410_socket(self):
        _, stderr = self.run_binary(['Socket'])

        # TCP Socket Creation
        self.assertIn('TCP Creation 1 OK', stderr)

        # TCP Socket Connection
        self.assertIn('TCP Connection 1 OK', stderr)

        # TCP Socket Transmission
        self.assertIn('TCP Write 1 OK', stderr)
        self.assertIn('TCP Read 1: Hello World 1', stderr)
        self.assertIn('TCP Write 2 OK', stderr)
        self.assertIn('TCP Read 2: Hello World 2', stderr)

        # UDP Socket Creation
        self.assertIn('UDP Creation 1 OK', stderr)

        # UDP Socket Connection
        self.assertIn('UDP Connection 1 OK', stderr)

        # UDP Socket Transmission
        self.assertIn('UDP Write 1 OK', stderr)
        self.assertIn('UDP Read 1: Hello World 1', stderr)
        self.assertIn('UDP Write 2 OK', stderr)
        self.assertIn('UDP Read 2: Hello World 2', stderr)

        # Bound UDP Socket Transmission
        self.assertIn('UDP Write 3 OK', stderr)
        self.assertIn('UDP Read 3: Hello World 1', stderr)
        self.assertIn('UDP Write 4 OK', stderr)
        self.assertIn('UDP Read 4: Hello World 2', stderr)

    def test_500_thread(self):
        _, stderr = self.run_binary(['Thread'])

        # Thread Creation
        self.assertIn('Child Thread Created', stderr)
        self.assertIn('Run in Child Thread: Hello World', stderr)

        # Multiple Threads Run in Parallel
        self.assertIn('Threads Run in Parallel OK', stderr)

        # Set Thread Private Segment Register
        self.assertIn('Private Message (FS Segment) 1: Hello World 1', stderr)
        self.assertIn('Private Message (FS Segment) 2: Hello World 2', stderr)

        # Thread Exit
        self.assertIn('Child Thread Exited', stderr)

    def test_510_thread2(self):
        _, stderr = self.run_binary(['Thread2'])

        # Thread Cleanup: Exit by return.
        self.assertIn('Thread 2 ok.', stderr)

        # Thread Cleanup: Exit by DkThreadExit.
        self.assertIn('Thread 3 ok.', stderr)
        self.assertNotIn('Exiting thread 3 failed.', stderr)

        # Thread Cleanup: Can still start threads.
        self.assertIn('Thread 4 ok.', stderr)

    @unittest.skipUnless(HAS_SGX, 'This test is only meaningful on SGX PAL')
    def test_511_thread2_exitless(self):
        manifest = self.get_manifest('Thread2_exitless')
        _, stderr = self.run_binary([manifest], timeout=60)

        # Thread Cleanup: Exit by return.
        self.assertIn('Thread 2 ok.', stderr)

        # Thread Cleanup: Exit by DkThreadExit.
        self.assertIn('Thread 3 ok.', stderr)
        self.assertNotIn('Exiting thread 3 failed.', stderr)

        # Thread Cleanup: Can still start threads.
        self.assertIn('Thread 4 ok.', stderr)

    def test_900_misc(self):
        _, stderr = self.run_binary(['Misc'])
        # Query System Time
        self.assertIn('Query System Time OK', stderr)

        # Delay Execution for 10000 Microseconds
        self.assertIn('Delay Execution for 10000 Microseconds OK', stderr)

        # Delay Execution for 3 Seconds
        self.assertIn('Delay Execution for 3 Seconds OK', stderr)

        # Generate Random Bits
        self.assertIn('Generate Random Bits OK', stderr)

    def test_910_hex(self):
        _, stderr = self.run_binary(['Hex'])
        # Hex 2 String Helper Function
        self.assertIn('Hex test 1 is deadbeef', stderr)
        self.assertIn('Hex test 2 is cdcdcdcdcdcdcdcd', stderr)

class TC_21_ProcessCreation(RegressionTestCase):
    def test_100_process(self):
        _, stderr = self.run_binary(['Process'], timeout=60)
        counter = collections.Counter(stderr.split('\n'))
        # Process Creation
        self.assertEqual(counter['Child Process Created'], 3)

        # Process Creation Arguments
        self.assertEqual(counter['argv[0] = Process'], 3)
        self.assertEqual(counter['argv[1] = Child'], 3)

        # Process Channel Transmission
        self.assertEqual(counter['Process Write 1 OK'], 3)
        self.assertEqual(counter['Process Read 1: Hello World 1'], 3)
        self.assertEqual(counter['Process Write 2 OK'], 3)
        self.assertEqual(counter['Process Read 2: Hello World 2'], 3)

    def test_200_process2(self):
        # Process Creation with a Different Binary
        _, stderr = self.run_binary(['Process2'])
        counter = collections.Counter(stderr.split('\n'))
        self.assertEqual(counter['User Program Started'], 1)

    def test_300_process3(self):
        # Process Creation without Executable
        _, stderr = self.run_binary(['Process3'])
        counter = collections.Counter(stderr.split('\n'))
        self.assertEqual(counter['Binary 1 Preloaded'], 2)
        self.assertEqual(counter['Binary 2 Preloaded'], 2)

class TC_23_SendHandle(RegressionTestCase):
    def test_000_send_handle(self):
        _, stderr = self.run_binary(['SendHandle'])
        counter = collections.Counter(stderr.split('\n'))

        # Send and Receive Handles across Processes
        self.assertEqual(counter['Send Handle OK'], 3)
        self.assertEqual(counter['Receive Handle OK'], 3)

        # Send Pipe Handle
        self.assertEqual(counter['Receive Pipe Handle: Hello World'], 1)

        # Send Socket Handle
        self.assertEqual(counter['Receive Socket Handle: Hello World'], 1)

        # Send File Handle
        self.assertEqual(counter['Receive File Handle: Hello World'], 1)


@unittest.skipUnless(HAS_SGX, 'need SGX')
class TC_40_AVXDisable(RegressionTestCase):
    @unittest.expectedFailure
    def test_000_avx_disable(self):
        # Disable AVX bit in XFRM
        _, stderr = self.run_binary(['AvxDisable'])
        self.assertIn('Illegal instruction executed in enclave', stderr)
