# -*- coding: utf-8 -*-
'''
    tests.unit.doc_test
    ~~~~~~~~~~~~~~~~~~~~
'''

# Import Python libs
from __future__ import absolute_import
import os
import re
import logging

# Import Salt Testing libs
from tests.support.unit import TestCase
from tests.support.runtests import RUNTIME_VARS

# Import Salt libs
import salt.modules.cmdmod
import salt.utils.platform


log = logging.getLogger(__name__)


class DocTestCase(TestCase):
    '''
    Unit test case for testing doc files and strings.
    '''

    def test_check_for_doc_inline_markup(self):
        '''
        We should not be using the ``:doc:`` inline markup option when
        cross-referencing locations. Use ``:ref:`` or ``:mod:`` instead.

        This test checks for reference to ``:doc:`` usage.

        See Issue #12788 for more information.

        https://github.com/saltstack/salt/issues/12788
        '''
        salt_dir = RUNTIME_VARS.CODE_DIR

        if salt.utils.platform.is_windows():
            if salt.utils.path.which('bash'):
                # Use grep from git-bash when it exists.
                cmd = 'bash -c \'grep -r :doc: ./salt/'
                grep_call = salt.modules.cmdmod.run_stdout(cmd=cmd, cwd=salt_dir).split(os.linesep)
            else:
                # No grep in Windows, use findstr
                # findstr in windows doesn't prepend 'Binary` to binary files, so
                # use the '/P' switch to skip files with unprintable characters
                cmd = 'findstr /C:":doc:" /S /P {0}\\*'.format(salt_dir)
                grep_call = salt.modules.cmdmod.run_stdout(cmd=cmd).split(os.linesep)
        else:
            salt_dir += '/'
            cmd = 'grep -r :doc: ' + salt_dir
            grep_call = salt.modules.cmdmod.run_stdout(cmd=cmd).split(os.linesep)

        test_ret = {}
        for line in grep_call:
            # Skip any .pyc files that may be present
            if line.startswith('Binary'):
                continue

            # Only split on colons not followed by a '\' as is the case with
            # Windows Drives
            regex = re.compile(r':(?!\\)')
            try:
                key, val = regex.split(line, 1)
            except ValueError:
                log.error("Could not split line: %s", line)
                continue

            # Don't test man pages, this file, the tox or nox virtualenv files,
            # the page that documents to not use ":doc:", the doc/conf.py file
            # or the artifacts directory on nox CI test runs
            if 'man' in key \
                    or '.tox{}'.format(os.sep) in key \
                    or '.nox{}'.format(os.sep) in key \
                    or 'artifacts{}'.format(os.sep) in key \
                    or key.endswith('test_doc.py') \
                    or key.endswith(os.sep.join(['doc', 'conf.py'])) \
                    or key.endswith(os.sep.join(['conventions', 'documentation.rst'])) \
                    or key.endswith(os.sep.join(['doc', 'topics', 'releases', '2016.11.2.rst'])) \
                    or key.endswith(os.sep.join(['doc', 'topics', 'releases', '2016.11.3.rst'])) \
                    or key.endswith(os.sep.join(['doc', 'topics', 'releases', '2016.3.5.rst'])):
                continue

            # Set up test return dict
            if test_ret.get(key) is None:
                test_ret[key] = [val.strip()]
            else:
                test_ret[key].append(val.strip())

        # Allow test results to show files with :doc: ref, rather than truncating
        self.maxDiff = None

        # test_ret should be empty, otherwise there are :doc: references present
        self.assertEqual(test_ret, {})

    def _check_doc_files(self, module_skip, module_dir, doc_skip, module_doc_dir):
        '''
        Ensure various salt modules have associated documentation
        '''

        salt_dir = RUNTIME_VARS.CODE_DIR

        # Build list of module files
        module_files = []
        skip_module_files = module_skip
        full_module_dir = os.path.join(salt_dir, *module_dir)
        for file in os.listdir(full_module_dir):
            if file.endswith(".py"):
                module_name = os.path.splitext(file)[0]
                if module_name not in skip_module_files:
                    module_files.append(module_name)

        # Build list of beacon documentation files
        module_docs = []
        skip_doc_files = doc_skip
        full_module_doc_dir = os.path.join(salt_dir, *module_doc_dir)
        doc_prefix = '.'.join(module_dir) + '.'
        for file in os.listdir(full_module_doc_dir):
            if file.endswith(".rst"):
                doc_name = os.path.splitext(file)[0]
                if doc_name.startswith(doc_prefix):
                    doc_name = doc_name[len(doc_prefix):]
                if doc_name not in skip_doc_files:
                    module_docs.append(doc_name)

        # Check that every beacon has associated documentaiton file
        for module in module_files:
            self.assertIn(module,
                          module_docs,
                          'module file {0} is missing documentation in {1}'.format(module,
                                                                                   full_module_doc_dir))

        for doc_file in module_docs:
            self.assertIn(doc_file,
                          module_files,
                          'Doc file {0} is missing associated module in {1}'.format(doc_file,
                                                                                    full_module_dir))

    def test_module_doc_files(self):
        '''
        Ensure modules have associated documentation

        doc example: doc/ref/modules/all/salt.modules.zabbix.rst
        execution module example: salt/modules/zabbix.py
        '''

        skip_module_files = ['__init__']
        module_dir = ['salt', 'modules']
        skip_doc_files = ['index', 'group', 'inspectlib', 'inspectlib.collector', 'inspectlib.dbhandle',
                          'inspectlib.entities', 'inspectlib.exceptions', 'inspectlib.fsdb',
                          'inspectlib.kiwiproc', 'inspectlib.query', 'kernelpkg', 'pkg', 'user']
        module_doc_dir = ['doc', 'ref', 'modules', 'all']
        self._check_doc_files(skip_module_files, module_dir, skip_doc_files, module_doc_dir)

    def test_state_doc_files(self):
        '''
        Ensure states have associated documentation

        doc example: doc/ref/states/all/salt.states.zabbix_host.rst
        state example: salt/states/zabbix_host.py
        '''

        skip_state_files = ['__init__']
        state_dir = ['salt', 'states']
        skip_doc_files = ['index', 'all']
        state_doc_dir = ['doc', 'ref', 'states', 'all']
        self._check_doc_files(skip_state_files, state_dir, skip_doc_files, state_doc_dir)

    def test_auth_doc_files(self):
        '''
        Ensure auth modules have associated documentation

        doc example: doc/ref/auth/all/salt.auth.rest.rst
        auth module example: salt/auth/rest.py
        '''

        skip_auth_files = ['__init__']
        auth_dir = ['salt', 'auth']
        skip_doc_files = ['index', 'all']
        auth_doc_dir = ['doc', 'ref', 'auth', 'all']
        self._check_doc_files(skip_auth_files, auth_dir, skip_doc_files, auth_doc_dir)

    def test_beacon_doc_files(self):
        '''
        Ensure beacon modules have associated documentation

        doc example: doc/ref/beacons/all/salt.beacon.rest.rst
        beacon module example: salt/beacons/rest.py
        '''

        skip_beacon_files = ['__init__']
        beacon_dir = ['salt', 'beacons']
        skip_doc_files = ['index', 'all']
        beacon_doc_dir = ['doc', 'ref', 'beacons', 'all']
        self._check_doc_files(skip_beacon_files, beacon_dir, skip_doc_files, beacon_doc_dir)

    def test_cache_doc_files(self):
        '''
        Ensure cache modules have associated documentation

        doc example: doc/ref/cache/all/salt.cache.consul.rst
        cache module example: salt/cache/consul.py
        '''

        skip_module_files = ['__init__']
        module_dir = ['salt', 'cache']
        skip_doc_files = ['index', 'all']
        doc_dir = ['doc', 'ref', 'cache', 'all']
        self._check_doc_files(skip_module_files, module_dir, skip_doc_files, doc_dir)

    def test_cloud_doc_files(self):
        '''
        Ensure cloud modules have associated documentation

        doc example: doc/ref/clouds/all/salt.cloud.gce.rst
        cloud module example: salt/cloud/clouds/gce.py
        '''

        skip_module_files = ['__init__']
        module_dir = ['salt', 'cloud', 'clouds']
        skip_doc_files = ['index', 'all']
        doc_dir = ['doc', 'ref', 'clouds', 'all']
        self._check_doc_files(skip_module_files, module_dir, skip_doc_files, doc_dir)

    def test_engine_doc_files(self):
        '''
        Ensure engine modules have associated documentation

        doc example: doc/ref/engines/all/salt.engines.docker_events.rst
        engine module example: salt/engines/docker_events.py
        '''

        skip_module_files = ['__init__']
        module_dir = ['salt', 'engines']
        skip_doc_files = ['index', 'all']
        doc_dir = ['doc', 'ref', 'engines', 'all']
        self._check_doc_files(skip_module_files, module_dir, skip_doc_files, doc_dir)
