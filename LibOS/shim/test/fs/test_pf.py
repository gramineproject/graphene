#!/usr/bin/env python3

import filecmp
import os
import shutil
import subprocess
import sys
import unittest

from test_fs import (
    TC_00_FileSystem,
)

from regression import (
    HAS_SGX,
)

@unittest.skipUnless(HAS_SGX, 'Protected files require SGX support')
class TC_50_ProtectedFiles(TC_00_FileSystem):
    @classmethod
    def setUpClass(c):
        c.PF_CRYPT = os.path.join(os.environ.get('PAL_TOOLS'), 'pf_crypt')
        c.PF_TAMPER = os.path.join(os.environ.get('PAL_TOOLS'), 'pf_tamper')
        c.WRAP_KEY = os.path.join(c.TEST_DIR, 'wrap-key')
        # CONST_WRAP_KEY must match the one in manifest
        c.CONST_WRAP_KEY = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]
        c.ENCRYPTED_DIR = os.path.join(c.TEST_DIR, 'pf_input')
        c.ENCRYPTED_FILES = [os.path.join(c.ENCRYPTED_DIR, str(v)) for v in c.FILE_SIZES]

        super().setUpClass()
        if not os.path.exists(c.ENCRYPTED_DIR):
            os.mkdir(c.ENCRYPTED_DIR)
        c.OUTPUT_DIR   = os.path.join(c.TEST_DIR, 'pf_output')
        c.OUTPUT_FILES = [os.path.join(c.OUTPUT_DIR, str(x)) for x in c.FILE_SIZES]
        # create encrypted files
        c.set_default_key(c)
        for i in c.INDEXES:
            cmd = [c.PF_CRYPT, 'e', '-w', c.WRAP_KEY, '-i', c.INPUT_FILES[i], '-o', c.ENCRYPTED_FILES[i], '-p', c.ENCRYPTED_DIR]
            c.run_native_binary(c, cmd)

    def set_default_key(self):
        with open(self.WRAP_KEY, 'wb') as file:
            file.write(bytes(self.CONST_WRAP_KEY))

    # override to encrypt the file
    def copy_input(self, input, output):
        self.encrypt_file(input, output, self.OUTPUT_DIR)

    def encrypt_file(self, input, output, prefix):
        cmd = [self.PF_CRYPT, 'e', '-w', self.WRAP_KEY, '-i', input, '-o', output, '-p', prefix]
        stdout, stderr = self.run_native_binary(cmd)
        return (stdout, stderr)

    def decrypt_file(self, input, output):
        cmd = [self.PF_CRYPT, 'd', '-w', self.WRAP_KEY, '-i', input, '-o', output]
        stdout, stderr = self.run_native_binary(cmd)
        return (stdout, stderr)

    def test_000_gen_key(self):
        # test random key generation
        cmd = [self.PF_CRYPT, 'g', '-w', self.WRAP_KEY]
        stdout, stderr = self.run_native_binary(cmd)
        self.assertIn('Wrap key saved to: ' + self.WRAP_KEY, stdout)
        self.assertEqual(os.path.getsize(self.WRAP_KEY), 16)
        # change key to the hardcoded one for remaining tests
        self.set_default_key()

    def test_010_encrypt_decrypt(self):
        for i in self.INDEXES:
            stdout, stderr = self.encrypt_file(self.INPUT_FILES[i], self.OUTPUT_FILES[i], '/'+self.OUTPUT_DIR)
            self.assertFalse(filecmp.cmp(self.INPUT_FILES[i], self.OUTPUT_FILES[i], shallow=False))
            dp = os.path.join(self.OUTPUT_DIR, os.path.basename(self.OUTPUT_FILES[i]) + '.decrypted')
            stdout, stderr = self.decrypt_file(self.OUTPUT_FILES[i], dp)
            self.assertTrue(filecmp.cmp(self.INPUT_FILES[i], dp, shallow=False))

    # override to change input dir (from plaintext to encrypted)
    def test_100_open_close(self):
        input_path = self.ENCRYPTED_FILES[-1] # existing file
        output_path = os.path.join(self.OUTPUT_DIR, 'test_100') # new file
        stdout, stderr = self.run_binary(['open_close', input_path, output_path])
        self.verify_open_close(stdout, stderr, input_path, output_path)

    # override to change input dir (from plaintext to encrypted)
    def test_115_seek_tell(self):
        plaintext_path = self.INPUT_FILES[-1]
        input_path = self.ENCRYPTED_FILES[-1] # existing file
        output_path_1 = os.path.join(self.OUTPUT_DIR, 'test_115a') # writable files
        output_path_2 = os.path.join(self.OUTPUT_DIR, 'test_115b')
        self.copy_input(plaintext_path, output_path_1) # encrypt
        self.copy_input(plaintext_path, output_path_2)
        stdout, stderr = self.run_binary(['seek_tell', input_path, output_path_1, output_path_2])
        self.verify_seek_tell(stdout, stderr, input_path, output_path_1, output_path_2, self.FILE_SIZES[-1])

    # override to change input dir (from plaintext to encrypted)
    def test_130_file_stat(self):
        for i in self.INDEXES:
            input_path = self.ENCRYPTED_FILES[i]
            output_path = self.OUTPUT_FILES[i]
            size = str(self.FILE_SIZES[i])
            self.copy_input(self.INPUT_FILES[i], output_path)
            stdout, stderr = self.run_binary(['stat', input_path, output_path])
            self.verify_stat(stdout, stderr, input_path, output_path, size)

    # override to decrypt output
    def verify_size(self, file, size):
        dp = os.path.join(self.OUTPUT_DIR, os.path.basename(file) + '.decrypted')
        self.decrypt_file(file, dp)
        self.assertEqual(os.stat(dp).st_size, size)

    # override to decrypt output
    def verify_copy_content(self, input, output):
        dp = os.path.join(self.OUTPUT_DIR, os.path.basename(output) + '.decrypted')
        self.decrypt_file(output, dp)
        self.assertTrue(filecmp.cmp(input, dp, shallow=False))

    # override to change input dir (from plaintext to encrypted)
    def do_copy_test(self, exec, timeout):
        stdout, stderr = self.run_binary([exec, self.ENCRYPTED_DIR, self.OUTPUT_DIR], timeout=timeout)
        self.verify_copy(stdout, stderr, self.ENCRYPTED_DIR, exec)

    # override copy_dir_mmap* to not skip them on SGX
    def test_203_copy_dir_mmap_whole(self):
        self.do_copy_test('copy_mmap_whole', 30)

    def test_204_copy_dir_mmap_seq(self):
        self.do_copy_test('copy_mmap_seq', 60)

    def test_205_copy_dir_mmap_rev(self):
        self.do_copy_test('copy_mmap_rev', 60)

    def test_210_copy_dir_mounted(self):
        exec = 'copy_whole'
        stdout, stderr = self.run_binary([exec, '/mounted/pf_input', '/mounted/pf_output'], timeout=30)
        self.verify_copy(stdout, stderr, '/mounted/pf_input', exec)

    def corrupt_file(self, input, output):
        cmd = [self.PF_TAMPER, '-w', self.WRAP_KEY, '-i', input, '-o', output]
        stdout, stderr = self.run_native_binary(cmd)
        return (stdout, stderr)

    # invalid/corrupted files
    def test_500_invalid(self):
        INVALID_DIR = os.path.join(self.TEST_DIR, 'pf_invalid')
        # files below should work normally (benign modifications)
        SHOULD_PASS = ['chunk_padding_1_fixed', 'chunk_padding_2_fixed', 'chunk_data_3', 'chunk_data_3_fixed', 'chunk_data_4', 'chunk_data_4_fixed']
        if not os.path.exists(INVALID_DIR):
            os.mkdir(INVALID_DIR)
        # prepare valid encrypted file (largest one for maximum possible corruptions)
        original_input = self.OUTPUT_FILES[-1]
        # target prefix is INVALID_DIR
        self.encrypt_file(self.INPUT_FILES[-1], original_input, INVALID_DIR)
        # generate invalid files based on the above
        self.corrupt_file(original_input, INVALID_DIR)
        # try to decrypt invalid files
        for name in os.listdir(INVALID_DIR):
            invalid = os.path.join(INVALID_DIR, name)
            output  = os.path.join(self.OUTPUT_DIR, name)
            input   = os.path.join(INVALID_DIR, os.path.basename(original_input))
            # copy the file so it has the original file name (for allowed path check)
            shutil.copy(invalid, input)
            should_pass = any(s in name for s in SHOULD_PASS)

            try:
                self.run_native_binary([self.PF_CRYPT, 'd', '-V', '-w', self.WRAP_KEY, '-i', input, '-o', output])
            except subprocess.CalledProcessError as e:
                if should_pass:
                    self.assertEqual(e.returncode, 0)
                else:
                    self.assertNotEqual(e.returncode, 0)
            else:
                if not should_pass:
                    print('[!] Fail: successfully decrypted file: ' + name)
                    self.fail()
