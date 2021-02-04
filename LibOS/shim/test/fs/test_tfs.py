#!/usr/bin/env python3

import filecmp
import os
import shutil

from regression import (
    HAS_SGX,
    RegressionTestCase,
    expectedFailureIf,
)

# Generic FS tests that mimic probable usage patterns in applications.
# pylint: disable=too-many-public-methods
class TC_00_FileSystem(RegressionTestCase):
    @classmethod
    def setUpClass(cls):
        cls.FILE_SIZES = [0, 1, 2, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 65535, 65536, 65537,
                          1048575, 1048576, 1048577]
        cls.TEST_DIR = 'tmp'
        cls.INDEXES = range(len(cls.FILE_SIZES))
        cls.INPUT_DIR = os.path.join(cls.TEST_DIR, 'input')
        cls.INPUT_FILES = [os.path.join(cls.INPUT_DIR, str(x)) for x in cls.FILE_SIZES]
        cls.OUTPUT_DIR = os.path.join('/mnt-tmpfs', '')
        cls.OUTPUT_FILES = [os.path.join(cls.OUTPUT_DIR, str(x)) for x in cls.FILE_SIZES]

        # create directory structure and test files
        os.mkdir(cls.TEST_DIR)
        os.mkdir(cls.INPUT_DIR)
        for i in cls.INDEXES:
            with open(cls.INPUT_FILES[i], 'wb') as file:
                file.write(os.urandom(cls.FILE_SIZES[i]))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.TEST_DIR)

    def setUp(self):
        # clean output for each test
        shutil.rmtree(self.OUTPUT_DIR, ignore_errors=True)

    # copy input file to output dir (for tests that alter the file so input remains untouched)
    # pylint: disable=no-self-use
    def copy_input(self, input_path, output_path):
        shutil.copy(input_path, output_path)

    def verify_open_close(self, stdout, stderr, path, mode):
        self.assertNotIn('ERROR: ', stderr)
        self.assertIn('open(' + path + ') ' + mode + ' OK', stdout)
        self.assertIn('close(' + path + ') ' + mode + ' OK', stdout)
        self.assertIn('open(' + path + ') ' + mode + ' 1 OK', stdout)
        self.assertIn('open(' + path + ') ' + mode + ' 2 OK', stdout)
        self.assertIn('close(' + path + ') ' + mode + ' 1 OK', stdout)
        self.assertIn('close(' + path + ') ' + mode + ' 2 OK', stdout)
        self.assertIn('fopen(' + path + ') ' + mode + ' OK', stdout)
        self.assertIn('fclose(' + path + ') ' + mode + ' OK', stdout)
        self.assertIn('fopen(' + path + ') ' + mode + ' 1 OK', stdout)
        self.assertIn('fopen(' + path + ') ' + mode + ' 2 OK', stdout)
        self.assertIn('fclose(' + path + ') ' + mode + ' 1 OK', stdout)
        self.assertIn('fclose(' + path + ') ' + mode + ' 2 OK', stdout)

    def test_100_open_close(self):
        output_path = os.path.join(self.OUTPUT_DIR, 'test_100') # new file to be created
        stdout, stderr = self.run_binary(['open_close', 'W', output_path])
        self.verify_open_close(stdout, stderr, output_path, 'output')

    def verify_open_flags(self, stdout, stderr):
        self.assertNotIn('ERROR: ', stderr)
        self.assertIn('open(O_CREAT | O_EXCL | O_RDWR) [doesn\'t exist] succeeded as expected',
                      stdout)
        self.assertIn('open(O_CREAT | O_EXCL | O_RDWR) [exists] failed as expected', stdout)
        self.assertIn('open(O_CREAT | O_RDWR) [exists] succeeded as expected', stdout)
        self.assertIn('open(O_CREAT | O_RDWR) [doesn\'t exist] succeeded as expected', stdout)
        self.assertIn('open(O_CREAT | O_TRUNC | O_RDWR) [doesn\'t exist] succeeded as expected',
                      stdout)
        self.assertIn('open(O_CREAT | O_TRUNC | O_RDWR) [exists] succeeded as expected', stdout)

    def test_101_open_flags(self):
        file_path = os.path.join(self.OUTPUT_DIR, 'test_101') # new file to be created
        stdout, stderr = self.run_binary(['open_flags', file_path])
        self.verify_open_flags(stdout, stderr)

    def test_110_read_write(self):
        file_path = os.path.join(self.OUTPUT_DIR, 'test_110') # new file to be created
        stdout, stderr = self.run_binary(['read_write', file_path])
        self.assertNotIn('ERROR: ', stderr)
        self.assertIn('open(' + file_path + ') RW OK', stdout)
        self.assertIn('write(' + file_path + ') RW OK', stdout)
        self.assertIn('seek(' + file_path + ') RW OK', stdout)
        self.assertIn('read(' + file_path + ') RW OK', stdout)
        self.assertIn('compare(' + file_path + ') RW OK', stdout)
        self.assertIn('close(' + file_path + ') RW OK', stdout)

    def do_copy_test(self, executable, timeout):
        stdout, stderr = self.run_binary([executable, self.INPUT_DIR, self.OUTPUT_DIR],
                                         timeout=timeout)

    def test_200_copy_dir_whole(self):
        self.do_copy_test('copy_whole', 30)

    def test_201_copy_dir_seq(self):
        self.do_copy_test('copy_seq', 60)

    def test_202_copy_dir_rev(self):
        self.do_copy_test('copy_rev', 60)

    def test_203_copy_dir_sendfile(self):
        self.do_copy_test('copy_sendfile', 60)

    @expectedFailureIf(HAS_SGX)
    def test_204_copy_dir_mmap_whole(self):
        self.do_copy_test('copy_mmap_whole', 30)

    @expectedFailureIf(HAS_SGX)
    def test_205_copy_dir_mmap_seq(self):
        self.do_copy_test('copy_mmap_seq', 60)

    @expectedFailureIf(HAS_SGX)
    def test_206_copy_dir_mmap_rev(self):
        self.do_copy_test('copy_mmap_rev', 60)

    def test_210_copy_dir_mounted(self):
        executable = 'copy_whole'
        stdout, stderr = self.run_binary([executable, '/mounted/input', '/mnt-tmpfs'],
                                         timeout=30)
