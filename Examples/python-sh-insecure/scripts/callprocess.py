#!/usr/bin/env python3

import os
RESULT = os.system('python3 scripts/helloworld.py')
print('exit code of child process: {}'.format(RESULT))
