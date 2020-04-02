#!/usr/bin/env python3

import unittest

from regression import (
    RegressionTestCase,
)

class TC_00_Basic(RegressionTestCase):
    def test_Event(self):
        _, stderr = self.run_binary(['Event'])
        self.assertIn('Enter main thread', stderr)
        self.assertIn('In thread 1', stderr)
        self.assertIn('Success, leave main thread', stderr)

    def test_Exception(self):
        _, stderr = self.run_binary(['Exception'])
        self.assertIn('Enter Main Thread', stderr)
        self.assertIn('failure in the handler: 0x', stderr)
        self.assertNotIn('Leave Main Thread', stderr)

    def test_Failure(self):
        _, stderr = self.run_binary(['Failure'])
        self.assertIn('Enter Main Thread', stderr)
        self.assertIn('Failure notified: Function not supported', stderr)
        self.assertIn('Leave Main Thread', stderr)

    def test_File(self):
        _, stderr = self.run_binary(['File'])
        self.assertIn('Enter Main Thread', stderr)
        self.assertIn('Hello World', stderr)
        self.assertIn('Leave Main Thread', stderr)

    def test_HandleSend(self):
        _, stderr = self.run_binary(['HandleSend'])
        self.assertIn('Parent: Executing the program', stderr)
        self.assertIn('Parent: Creating handles', stderr)
        self.assertIn('Parent: Forking child', stderr)
        self.assertIn('Parent: Sending Handle 0', stderr)
        self.assertIn('Parent: Sending Handle 1', stderr)
        self.assertIn('Parent: Sending Handle 2', stderr)
        self.assertIn('Parent: Sending Handle 3', stderr)
        self.assertIn('Parent: Sending Handle 4', stderr)
        self.assertIn('Parent: Finished execution', stderr)
        self.assertIn('Child: Receiving Handle 0', stderr)
        self.assertIn('Child: Receiving Handle 1', stderr)
        self.assertIn('Child: Receiving Handle 2', stderr)
        self.assertIn('Child: Receiving Handle 3', stderr)
        self.assertIn('Child: Receiving Handle 4', stderr)
        self.assertIn('Child: Reading the handles', stderr)
        self.assertIn('Child: Handle 0 Type Pipe', stderr)
        self.assertIn('Child: Handle 1 Type Udp', stderr)
        self.assertIn('hild: Handle 2 Type File Data: Hello World2', stderr)
        self.assertIn('Child: Handle 3 Type File Data: Hello World3', stderr)
        self.assertIn('Child: Handle 4 Type File Data: Hello World4', stderr)
        self.assertIn('Child: Finished execution', stderr)

    def test_HelloWorld(self):
        stdout, _ = self.run_binary(['HelloWorld'])
        self.assertIn('Hello World', stdout)

    def test_Memory(self):
        _, _ = self.run_binary(['Memory'])

    def test_Pie(self):
        stdout, stderr = self.run_binary(['Pie'])
        self.assertIn('start program: file:Pie', stderr)
        self.assertIn('Hello World', stdout)

    def test_Pipe(self):
        stdout, stderr = self.run_binary(['Pipe'])
        self.assertIn('pipe connect as pipe:', stderr)
        self.assertIn('pipe accepted as pipe.srv:', stderr)
        self.assertIn('read from server: Hello World', stderr)

    def test_Process(self):
        stdout, stderr = self.run_binary(['Process'], timeout=12)
        self.assertIn('In process: Process', stderr)
        self.assertIn('wall time = ', stderr)
        for i in range(100):
            self.assertIn('In process: Process %d ' % i, stderr)

    def test_Segment(self):
        _, stderr = self.run_binary(['Segment'])
        self.assertIn('TLS = 0x', stderr)

    def test_Select(self):
        _, stderr = self.run_binary(['Select'])
        self.assertIn('Enter main thread', stderr)
        self.assertIn('Waiting on event', stderr)
        self.assertIn('Enter thread', stderr)
        self.assertIn('Thread sets event', stderr)
        self.assertIn('Event was called', stderr)
        self.assertIn('Leave main thread', stderr)
        self.assertIn('Leave thread', stderr)

    def test_Sleep(self):
        _, stderr = self.run_binary(['Sleep'], timeout=3)
        self.assertIn('Enter Main Thread', stderr)
        self.assertIn('Sleeping 3000000 microsecond...', stderr)
        self.assertIn('Leave Main Thread', stderr)

    def test_Tcp(self):
        _, stderr = self.run_binary(['Tcp'])
        self.assertIn('start time = ', stderr)
        self.assertIn('server bound on tcp.srv:127.0.0.1:8000', stderr)
        self.assertIn('client accepted on tcp:127.0.0.1:8000:127.0.0.1:', stderr)
        self.assertIn('client connected on tcp:127.0.0.1:', stderr)
        self.assertIn('read from server: Hello World', stderr)

    def test_Thread(self):
        _, stderr = self.run_binary(['Thread'])
        self.assertIn('Enter Main Thread', stderr)
        self.assertIn('Leave Main Thread', stderr)
        self.assertIn('Enter Thread 2', stderr)
        self.assertIn('Parent do suspension', stderr)
        self.assertIn('Enter Thread 1', stderr)
        self.assertIn('Parent do reload', stderr)
        self.assertIn('Leave Thread 2', stderr)
        self.assertIn('Leave Thread 1', stderr)

    def test_Udp(self):
        _, stderr = self.run_binary(['Udp'])
        self.assertIn('server bound on udp.srv:127.0.0.1:8000', stderr)
        self.assertIn('client connected on udp:127.0.0.1:8000', stderr)
        self.assertIn('read on server (from udp:127.0.0.1:', stderr)
        self.assertIn('Hello World', stderr)
        self.assertIn('wall time = ', stderr)

    def test_Wait(self):
        _, stderr = self.run_binary(['Wait'])
        self.assertIn('Enter Main Thread', stderr)
        self.assertIn('DkStreamsWaitEvents did not return any events', stderr)
        self.assertIn('Enter thread 2', stderr)
        self.assertIn('Enter thread 1', stderr)
        self.assertIn('Leave thread 2', stderr)
        self.assertIn('Leave thread 1', stderr)

    def test_Yield(self):
        _, stderr = self.run_binary(['Yield'])
        self.assertIn('Enter Parent Thread', stderr)
        self.assertIn('Enter Child Thread', stderr)
        self.assertIn('child yielded', stderr)
        self.assertIn('parent yielded', stderr)
