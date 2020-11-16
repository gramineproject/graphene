# see also another attempt at adapting asv to non-python builds:
# https://github.com/Warbo/asv-nix/blob/master/python/asv_nix/__init__.py

import os
import subprocess
import sys

import asv.environment
import asv.util
from asv.console import log

class MakeEnvironment(asv.environment.Environment):
    tool_name = 'make'

    def __init__(self, conf, python, requirements):
        assert python == 'system'
        assert not requirements

        self._python = python
        self._requirements = requirements
        self._executable = sys.executable

        super().__init__(conf, python, requirements)

    @staticmethod
    def matches(python):
        return python == 'system'

    def _setup(self):
        pass

    def _get_env_for_subprocess(self, env=None):
        _env = os.environ.copy()
        _env.update(self._env_vars)
        if env is not None:
            _env.update(env)
        return _env

    def _run(self, *args, env=None, **kwds):
        # when we don't need asv.util.check_*, do not use, because it may deadlock
        # (those functions have problems with their poor reimplementation of .communicate())
        # pylint: disable=subprocess-run-check
        return subprocess.run(*args, env=self._get_env_for_subprocess(env), **kwds)

    def run(self, args, *, env=None, **kwargs):
        # pylint: disable=arguments-differ
        # unfortunately, this has to use asv.util.check_*, because of the kwargs heavily used by
        # asv.runner, and those kwargs are incompatible with subprocess
        log.debug('Running {!r} in {}'.format(args, self.name))
        return asv.util.check_output([self._executable, *args],
            env=self._get_env_for_subprocess(env), **kwargs)

    def _build_project(self, repo, commit_hash, build_dir):
        commit_name = repo.get_decorated_hash(commit_hash, 8)
        log.info('Building {} for {}'.format(commit_name, self.name))
        if not self._build_command:
            log.info('Nothing to build')
            return

        for cmd in self._build_command:
            self._run(cmd, shell=True, cwd=build_dir, check=True,
                timeout=self._install_timeout)

    def _install_project(self, repo, commit_hash, build_dir):
        commit_name = repo.get_decorated_hash(commit_hash, 8)
        log.info('Installing {} into {}'.format(commit_name, self.name))
        if not self._install_command:
            log.info('Nothing to install')
            return

        for cmd in self._install_command:
            self._run(cmd, shell=True, cwd=build_dir, check=True,
                timeout=self._install_timeout)

    def _uninstall_project(self):
        self._set_installed_commit_hash(None)
        log.info('Uninstalling from {}'.format(self.name))
        if not self._uninstall_command:
            log.info('Nothing to uninstall')
            return

        for cmd in self._uninstall_command:
            self._run(cmd, shell=True, cwd=self._env_dir, check=True,
                timeout=self._install_timeout)
