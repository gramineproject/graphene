#!/usr/bin/python

import sys, os, subprocess, re, time

class Result:
    def __init__(self, out, log, code):
        self.out = out.split('\n')
        self.log = log.split('\n')
        self.code = code

class Regression:
    def __init__(self, loader = None, executable = '', prepare = None, timeout = 1000, keep_log = False):
        self.loader = loader
        self.executable = executable
        self.prepare = prepare
        self.runs = dict()
        self.timeout = timeout
        self.keep_log = keep_log

    def add_check(self, name, check, times = 1, args = []):
        combined_args = ' '.join(args)
        if not combined_args in self.runs:
            self.runs[combined_args] = []
        self.runs[combined_args].append((name, check, times))

    def run_checks(self):
        for combined_args in self.runs:
            needed_times = 1
            for (name, check, times) in self.runs[combined_args]:
                if needed_times < times:
                    needed_times = times

            run_times = 0
            outputs = []
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
                                     stderr=subprocess.PIPE)

                sleep_time = 0
                finish = False
                while sleep_time < self.timeout:
                    time.sleep(0.001)
                    if p.poll() is not None:
                        finish = True
                        break
                    sleep_time += 1

                if not finish and p.poll() is None:
                    p.kill()

                out = p.stdout.read()
                log = p.stderr.read()

                if self.keep_log:
                    sargs = [re.sub(r"\W", '_', a).strip('_') for a in args]
                    filename = '_'.join(sargs) + '_' + time.strftime("%Y%m%d_%H%M%S")
                    with open(filename + '.log', 'w') as f:
                        f.write(log)
                    with open(filename + '.out', 'w') as f:
                        f.write(out)

                outputs.append(Result(out, log, p.returncode))

                run_times = run_times + 1
                for (name, check, times) in self.runs[combined_args]:
                    if run_times == times:
                        result = check(outputs)
                        if result:
                            print '\033[92m[Success]\033[0m', name
                        else:
                            print '\033[93m[Fail   ]\033[0m', name
