import subprocess
import csv
import os
import threading
import time
import signal
import tempfile

class RunCmd(threading.Thread):
    def __init__(self, cmd, timeout, test):
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.timeout = int(timeout)*100
        self.output = ""
        self.test = test
        self.test_subtest = test

    def run(self):
        name = tempfile.NamedTemporaryFile(mode='w+b')
        self.p = subprocess.Popen(self.cmd, shell=True, stdout=name, stderr=subprocess.STDOUT, preexec_fn=os.setsid, close_fds=True)
        self.curtime = time.time()
        self.endtime = self.curtime + self.timeout
        needed_times = self.timeout
        sleep_time = 0
        finish = False
        while sleep_time < self.timeout:
            if self.p.poll() is not None:
                finish = True
                break
            sleep_time += 1
            time.sleep(.01)

        if not finish and self.p.poll() is None:
            timed_out = True
            print CRED + "[Hanged ] " + self.test_subtest + CEND
            current_hanged[self.test_subtest] = 1
            os.killpg(os.getpgid(self.p.pid), signal.SIGKILL)
            del self.p

        if (finish):
            reported = False
            name.seek(0)
            for output in name.readlines():
                toks = output.split()
                if len(toks)<2 or (toks[0] != self.test and self.test != "memcmp01" and self.test != "memcpy01"):
                    continue
                test_subtest = self.test + "," + toks[1]
                self.test_subtest = test_subtest
                if "TINFO" in output or test_subtest in current_passed or test_subtest in current_failed or self.test in current_hanged or test_subtest in current_broken:
                    continue
                if output:
                    output = output.strip()
                    print >>f1, output
                if "TFAIL" in output:
                    print >>failed_tests_fh, test_subtest
                    print CRED + "[Fail   ] " + test_subtest + CEND
                    current_failed[test_subtest] = 1
                    reported = True
                elif "TPASS" in output:
                    print >>passed_tests_fh, test_subtest
                    print CGREEN + "[Pass   ] " + test_subtest + CEND
                    current_passed[test_subtest] = 1
                    reported = True
                elif "TCONF" in output or "TBROK" in output or "error" in output:
                    print >>broken_tests_fh, test_subtest
                    print "[Broken ] " + test_subtest      #Syscall not implemented or test preparation failed
                    current_broken[test_subtest] = 1
                    reported = True
            #else:
            #    print "[Broken ] " + self.test      #Syscall not implemented or test preparation failed
            if (not reported):
                print >>broken_tests_fh, self.test
                print CRED + "[Broken ] " + self.test + CEND
                current_broken[self.test] = 1
    def Run(self):
        self.start()
        self.join()

CRED = '\033[91m'
CGREEN = '\033[92m'
CEND = '\033[0m'
DEFAULT_TIMEOUT = 20

resultfile = "run_output"
stablePass = "PASSED"
timeouts = "TIMEOUTS"
failed_tests_file = "Failed.csv"
passed_tests_file = "Passed.csv"
broken_tests_file = "Broken.csv"

f1 = open(resultfile, 'w')
failed_tests_fh = open(failed_tests_file, 'w', 0)
passed_tests_fh = open(passed_tests_file, 'w', 0)
broken_tests_fh = open(broken_tests_file, 'w', 0)

failed_tests_fh.write("Test,Subtest number,Status\n")
passed_tests_fh.write("Test,Subtest number\n")
broken_tests_fh.write("Test,Subtest number,Status\n")

current_passed = dict()
current_failed = dict()
current_broken = dict()
current_hanged = dict()
timeouts_dict = dict()

with open(timeouts, 'rb') as csvfile:
    test_timeout = csv.reader(csvfile)
    test_timeout.next()
    for row in test_timeout:
        test = row[0]
        timeout = row[1]
        timeouts_dict[test] = timeout

os.chdir("opt/ltp/testcases/bin")
with open('../../../../syscalls.graphene') as testcases:
    for line in testcases:
        tokens = line.split( )
        test = tokens[1]
        if test=="seq":
            test = tokens[6]     #splice02
        try: 
            timeout = timeouts_dict[test]
        except KeyError:
            timeout = DEFAULT_TIMEOUT
        RunCmd([line], timeout, test).Run()
        time.sleep(.1)
os.chdir("../../../..")
    
stable_passed = dict()
with open(stablePass, 'rb') as csvfile:
    test_subtest = csv.reader(csvfile)
    test_subtest.next()
    for row in test_subtest:
        tst = row[0] + "," + row[1]
        stable_passed[tst] = 1

print "\n\nRESULT [Difference] :\n---------------------\n"

for test in stable_passed:
    if not test in current_passed:
        print CRED + "Test '" + test + "' did not pass in the current run!!" + CEND

for test in current_passed:
    if not test in stable_passed:
        print CGREEN + "Test '" + test + "' passed in the current run!!" + CEND
print "\n"
