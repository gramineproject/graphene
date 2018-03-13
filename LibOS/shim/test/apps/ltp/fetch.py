import subprocess
import csv
import os
import time
import signal
import tempfile
import multiprocessing
import sys

def run(cmd, timeout, test):
    try:
        timeout = timeout * 100
        result = {}
        result['test'] = test
        outfile = tempfile.NamedTemporaryFile(mode='w+b')
        p = subprocess.Popen(cmd, shell=True, stdout=outfile, stderr=subprocess.STDOUT, preexec_fn=os.setsid, close_fds=True)
        result['curtime'] = time.time()
        result['endtime'] = result['curtime'] + timeout
        sleep_time = 0
        finish = False
        while sleep_time < timeout:
            if p.poll() is not None:
                finish = True
                break
            sleep_time += 1
            time.sleep(.01)

        result['finish'] = finish
        outfile.seek(0)
        result['output'] = outfile.readlines()
        return result
    except Exception as e:
        print str(e)
        return None
    finally:
        if p is not None and p.poll() is None:
            print 'killing %s' % test
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)

def finish(result):
    try:
        test = result['test']
        if not result['finish']:
            print CRED + "[Hanged ] " + test + CEND
            current_hanged[test] = 1
        else:
            reported = False
            count = 1
            for output in result['output']:
                tokens = output.split()

                if len(tokens) < 2:
                    continue

                # Drop this line so that we get consistent offsets
                if output == "WARNING: no physical memory support, process creation may be slow.\n":
                    continue

                if tokens[1].isdigit():
                    test_subtest = test + "," + tokens[1]
                    count = int(tokens[1]) + 1
                else:
                    test_subtest = test + "," + str(count)
                    count = count + 1
                if "TINFO" in output or test_subtest in current_passed or test_subtest in current_failed or test in current_hanged or test_subtest in current_broken:
                    continue

                if output:
                    output = output.strip()
                    print >>f1, output

                if "TFAIL" in output:
                    print >>failed_tests_fh, test_subtest
                    print CRED + "[Fail   ] " + test_subtest + CEND
                    current_failed[test_subtest] = 1
                    reported = True

                elif "TPASS" in output or "PASS:" in output:
                    print >>passed_tests_fh, test_subtest
                    print CGREEN + "[Pass   ] " + test_subtest + CEND
                    current_passed[test_subtest] = 1
                    reported = True

                elif "TCONF" in output or "TBROK" in output or "BROK" in output or "error" in output:
                    print >>broken_tests_fh, test_subtest
                    # Syscall not implemented or test preparation failed
                    print "[Broken(a) ] " + test_subtest + CEND
                    current_broken[test_subtest] = 1
                    reported = True

            if (not reported):
                print >>broken_tests_fh, test
                print CRED + "[Broken(b) ] " + test + CEND
                for output in result['output']:
                    print output
                current_broken[test] = 1

    except Exception as e:
        print str(e)

CRED = '\033[91m'
CGREEN = '\033[92m'
CEND = '\033[0m'
DEFAULT_TIMEOUT = 30

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
        timeouts_dict[test] = int(timeout)

os.chdir("opt/ltp/testcases/bin")
pool = multiprocessing.Pool()
with open('../../../../syscalls.graphene') as testcases:
    for line in testcases:
        line = line.strip('\r\n\t')
        tokens = line.split( )
        if (tokens[1] == "SGX") :
            test = tokens[2]
        else :
            test = tokens[1]

        if test=="seq":
            test = tokens[6]     #splice02
        try: 
            timeout = timeouts_dict[test]
        except KeyError:
            timeout = DEFAULT_TIMEOUT
        pool.apply_async(run, args=([line], timeout, test), callback=finish)
os.chdir("../../../..")

pool.close()
pool.join()
    
stable_passed = dict()
with open(stablePass, 'rb') as csvfile:
    test_subtest = csv.reader(csvfile)
    test_subtest.next()
    for row in test_subtest:
        tst = row[0] + "," + row[1]
        stable_passed[tst] = 1

print "\n\nRESULT [Difference] :\n---------------------\n"

rv = 0

for test in sorted(stable_passed):
    if not test in current_passed:
        print CRED + "Test '" + test + "' did not pass in the current run!!" + CEND
        rv = -1

for test in sorted(current_passed):
    if not test in stable_passed:
        print CGREEN + "Test '" + test + "' passed in the current run!!" + CEND
print "\n"

sys.exit(rv)
