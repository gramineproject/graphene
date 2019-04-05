#!/usr/bin/env python2

import sys, os, subprocess, re, time, fcntl, errno, cStringIO

class Result:
    def __init__(self, out, log, code):
        self.out = out.split('\n')
        self.log = log.split('\n')
        self.code = code

class Regression:
    def __init__(self, loader = None, executable = '', prepare = None, timeout = 0):
        self.loader = loader
        self.executable = executable
        self.prepare = prepare
        self.runs = dict()
        default_timeout = int(os.getenv('TIMEOUT', '10000'))
        if default_timeout > timeout:
            self.timeout = default_timeout
        else:
            self.timeout = timeout
        self.keep_log = (os.getenv('KEEP_LOG', '0') == '1')

    def add_check(self, name, check, times = 1, ignore_failure=0, args = []):
        combined_args = ' '.join(args)
        if not combined_args in self.runs:
            self.runs[combined_args] = []
        self.runs[combined_args].append((name, check, ignore_failure, times))

    def run_checks(self):
        def set_non_blocking(f):
            flags = fcntl.fcntl(f, fcntl.F_GETFL)
            fcntl.fcntl(f, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        def read_to_buf(f, b):
            try:
                s = f.read()
            except IOError as err:
                if err.errno != errno.EWOULDBLOCK:
                    raise err
            else:
                b.write(s)

        something_failed = 0
        for combined_args in self.runs:
            needed_times = 1
            for (name, check, ignore_failure, times) in self.runs[combined_args]:
                if needed_times < times:
                    needed_times = times

            run_times = 0
            outputs = []
            timed_out = False
            while run_times < needed_times:
                args = []
                if self.loader:
                    args.append(self.loader)
                if self.executable:
                    args.append(self.executable)
                if combined_args:
                    args += combined_args.split(' ')

                if self.prepare:
                    self.prepare(args)

                time.sleep(0.1)

                p = subprocess.Popen(args,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)

                set_non_blocking(p.stdout)
                set_non_blocking(p.stderr)
                out_buf = cStringIO.StringIO()
                err_buf = cStringIO.StringIO()
                sleep_time = 0
                finish = False
                while sleep_time < self.timeout:
                    time.sleep(0.001)
                    read_to_buf(p.stdout, out_buf)
                    read_to_buf(p.stderr, err_buf)
                    if p.poll() is not None:
                        finish = True
                        break
                    sleep_time += 1

                if not finish and p.poll() is None:
                    timed_out = True
                    p.kill()


                time.sleep(0.1)

                read_to_buf(p.stdout, out_buf)
                read_to_buf(p.stderr, err_buf)
                out = str(out_buf.getvalue())
                log = str(err_buf.getvalue())
                out_buf.close()
                err_buf.close()

                outputs.append(Result(out, log, p.returncode))

                run_times = run_times + 1
                keep_log = False
                for (name, check, ignore_failure, times) in self.runs[combined_args]:
                    if run_times == times:
                        result = check(outputs)
                        if result:
                            print '\033[92m[Success       ]\033[0m', name
                        else:
                            if ignore_failure:
                                print '[Fail (Ignored)]', name
                            else:
                                print '\033[93m[Fail          ]\033[0m', name
                                something_failed = 1
                            if timed_out : print 'Test timed out!'
                            keep_log = True
                            
                if self.keep_log and keep_log:
                    sargs = [re.sub(r"\W", '_', a).strip('_') for a in args]
                    filename = 'log-' + '_'.join(sargs) + '_' + time.strftime("%Y%m%d_%H%M%S")
                    with open(filename, 'w') as f:
                        f.write(log + out)
                    print 'keep log to %s' % (filename)
        if something_failed:
            return -1
        else:
            return 0
