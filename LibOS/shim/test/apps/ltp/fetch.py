import subprocess
import csv
import os
import threading
import time
import signal

class RunCmd(threading.Thread):
    def __init__(self, cmd, timeout, test):
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.timeout = int(timeout)
        self.output = ""
        self.test = test

    def run(self):
        self.p = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        self.output, error = self.p.communicate()
        outt = self.output.split("\n")
        for output in outt:
            toks = output.split()
            subtest = "1"
            if output:
                output = output.strip()
                print >>f1, output
                out = output.split( )
            if "TFAIL" in output:
                subtest = str(toks[1])
                test_subtest = toks[0] + "," + subtest
                print >>failed_tests_fh, test_subtest
                if test_subtest not in current_failed:
                    print CRED + "[Fail   ] " + self.test + "," + str(subtest) + CEND
                    current_failed[test_subtest] = 1
            elif "TPASS" in output:
                subtest = toks[1]
                test_subtest = toks[0] + "," + subtest
                print >>passed_tests_fh, test_subtest
                if test_subtest not in current_passed:
                    current_passed[test_subtest] = 1
                    print CGREEN + "[Pass   ] " + self.test + "," + str(subtest) + CEND
            elif "TINFO" in output:
                continue
            elif "TCONF" in output or "TBROK" in output or "error" in output:
                if toks[0] == "self.test":
                    subtest = str(toks[1])
                test_subtest = toks[0] + "," + subtest
                print >>broken_tests_fh, toks[0] + "," + subtest
                if test_subtest not in current_blocked and toks[0] not in current_hanged:
                    print "[Broken ] " + self.test + "," + str(subtest)      #Syscall not implemented or test preparation failed
                    current_blocked[test_subtest] = 1
            #else:
            #    print "[Broken ] " + self.test      #Syscall not implemented or test preparation failed
        self.p.wait()

    def Run(self):
        self.start()
        self.join(self.timeout)

        if self.is_alive():
            os.killpg(os.getpgid(self.p.pid), signal.SIGTERM)
            print CRED + "[Hanged ] " + self.test + CEND
            current_hanged[self.test] = 1
            time.sleep(1)
            
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
current_blocked = dict()
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