import sys, os, subprocess, re, time, signal

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

                p = subprocess.Popen(args,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     preexec_fn=os.setpgrp)
                try:
                    out, log = p.communicate(timeout=self.timeout * 0.001)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(p.pid, signal.SIGKILL)
                    out, log = p.communicate()

                out = out.decode('utf-8')
                log = log.decode('utf-8')

                outputs.append(Result(out, log, p.returncode))

                run_times = run_times + 1
                keep_log = False
                for (name, check, ignore_failure, times) in self.runs[combined_args]:
                    if run_times == times:
                        result = check(outputs)
                        if result:
                            print('\033[92m[Success       ]\033[0m', name)
                        else:
                            if ignore_failure:
                                print('[Fail (Ignored)]', name)
                            else:
                                print('\033[93m[Fail          ]\033[0m', name)
                                something_failed = 1
                            if timed_out : print('Test timed out!')
                            keep_log = True
                            
                if self.keep_log and keep_log:
                    sargs = [re.sub(r"\W", '_', a).strip('_') for a in args]
                    filename = 'log-' + '_'.join(sargs) + '_' + time.strftime("%Y%m%d_%H%M%S")
                    with open(filename, 'w') as f:
                        f.write(log + out)
                    print('keep log to %s' % (filename))
        if something_failed:
            return -1
        else:
            return 0
