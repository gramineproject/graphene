#!/usr/bin/env python3

import filecmp
import os
import shutil
import unittest

from regression import (
    HAS_SGX,
    expectedFailureIf,
)

from test_fs import TC_00_FileSystem

# Do tmpfs tests.
# pylint: disable=too-many-public-methods
class TC_10_Tmpfs(TC_00_FileSystem):
    @classmethod
    def setUpClass(cls):
        cls.FILE_SIZES = [0, 1, 2, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 65535, 65536, 65537,
                          1048575, 1048576, 1048577]
        cls.TEST_DIR = 'tmp'
        cls.INDEXES = range(len(cls.FILE_SIZES))
        cls.INPUT_DIR = os.path.join(cls.TEST_DIR, 'input')
        cls.INPUT_FILES = [os.path.join(cls.INPUT_DIR, str(x)) for x in cls.FILE_SIZES]
        cls.OUTPUT_DIR = os.path.abspath('/mnt-tmpfs')
        cls.OUTPUT_FILES = [os.path.join(cls.OUTPUT_DIR, str(x)) for x in cls.FILE_SIZES]

        # create directory structure and test files
        os.mkdir(cls.TEST_DIR)
        os.mkdir(cls.INPUT_DIR)
        for i in cls.INDEXES:
            with open(cls.INPUT_FILES[i], 'wb') as file:
                file.write(os.urandom(cls.FILE_SIZES[i]))

    # overrides TC_00_FileSystem to skip unnecessary steps
    def setUp(self):
        pass

    # overrides TC_00_FileSystem to skip verification by python
    def test_100_open_close(self):
        output_path = os.path.join(self.OUTPUT_DIR, 'test_100') # new file to be created
        stdout, stderr = self.run_binary(['open_close', 'W', output_path])
        self.verify_open_close(stdout, stderr, output_path, 'output')

    # overrides TC_00_FileSystem to skip verification by python
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

    # TODO: will decide to drop or enchance it for tmpfs
    @unittest.skip("impossible to do setup on tmpfs with python only")
    def test_115_seek_tell(self):
        TC_00_FileSystem.test_115_seek_tell(self)

    # TODO: will decide to drop or enchance it for tmpfs
    @unittest.skip("impossible to do setup on tmpfs with python only")
    def test_120_file_delete(self):
        TC_00_FileSystem.test_120_file_delete(self)

    # TODO: will decide to drop or enchance it for tmpfs
    @unittest.skip("impossible to do setup on tmpfs with python only")
    def test_130_file_stat(self):
        TC_00_FileSystem.test_130_file_stat(self)

    # TODO: will decide to drop or enchance it for tmpfs
    @unittest.skip("impossible to do setup on tmpfs with python only")
    def test_140_file_truncate(self):
        TC_00_FileSystem.test_140_file_truncate(self)

    # overrides TC_00_FileSystem to skip verification by python
    def verify_copy_content(self, input_path, output_path):
        pass

    # mmap is not yet implemented in tmpfs
    @expectedFailureIf(HAS_SGX)
    def test_204_copy_dir_mmap_whole(self):
        TC_00_FileSystem.test_204_copy_dir_mmap_whole(self)

    # mmap is not yet implemented in tmpfs
    @expectedFailureIf(HAS_SGX)
    def test_205_copy_dir_mmap_seq(self):
        TC_00_FileSystem.test_205_copy_dir_mmap_seq(self)

    # mmap is not yet implemented in tmpfs
    @expectedFailureIf(HAS_SGX)
    def test_206_copy_dir_mmap_rev(self):
        TC_00_FileSystem.test_206_copy_dir_mmap_rev(self)

    # overrides TC_00_FileSystem to skip it
    @unittest.skip("not applicable for tmpfs")
    def test_210_copy_dir_mounted(self):
        skip
