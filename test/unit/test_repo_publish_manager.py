#!/usr/bin/python
#
# Copyright (c) 2011 Red Hat, Inc.
#
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

# Python
import datetime
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)) + "/../common/")
import testutil
import mock_plugins

from pulp.common import dateutils
from pulp.server.db.model.gc_repository import Repo, RepoDistributor
import pulp.server.managers.repo.cud as repo_manager
import pulp.server.managers.repo.distributor as distributor_manager
import pulp.server.managers.repo.publish as publish_manager

# -- test cases ---------------------------------------------------------------

class RepoSyncManagerTests(testutil.PulpTest):

    def setUp(self):
        testutil.PulpTest.setUp(self)
        mock_plugins.install()

        # Create the manager instances for testing
        self.repo_manager = repo_manager.RepoManager()
        self.distributor_manager = distributor_manager.RepoDistributorManager()
        self.publish_manager = publish_manager.RepoPublishManager()

    def tearDown(self):
        testutil.PulpTest.tearDown(self)
        mock_plugins.reset()

    def clean(self):
        testutil.PulpTest.clean(self)
        Repo.get_collection().remove()
        RepoDistributor.get_collection().remove()

    def test_publish(self):
        """
        Tests publish under normal conditions when everything is configured
        correctly.
        """

        # Setup
        publish_config = {'foo' : 'bar'}
        self.repo_manager.create_repo('repo-1')
        self.distributor_manager.add_distributor('repo-1', 'mock-distributor', publish_config, False, distributor_id='dist-1')
        self.distributor_manager.add_distributor('repo-1', 'mock-distributor-2', publish_config, False, distributor_id='dist-2')

        # Test
        self.publish_manager.publish('repo-1', 'dist-1', None)

        # Verify

        #   Database
        repo_distributor = RepoDistributor.get_collection().find_one({'repo_id' : 'repo-1', 'id' : 'dist-1'})
        self.assertTrue(not repo_distributor['publish_in_progress'])
        self.assertTrue(repo_distributor['last_publish'] is not None)
        self.assertTrue(assert_last_sync_time(repo_distributor['last_publish']))

        #   Call into the correct distributor
        call_args = mock_plugins.MOCK_DISTRIBUTOR.publish_repo.call_args[0]

        self.assertEqual('repo-1', call_args[0].id)
        self.assertTrue(call_args[1] is not None)
        self.assertEqual({}, call_args[2].plugin_config)
        self.assertEqual(publish_config, call_args[2].repo_plugin_config)
        self.assertEqual({}, call_args[2].override_config)

        self.assertEqual(0, mock_plugins.MOCK_DISTRIBUTOR_2.publish_repo.call_count)
        
    def test_publish_with_config_override(self):
        """
        Tests a publish when passing in override values.
        """

        # Setup
        distributor_config = {'key-1' : 'orig-1', 'key-2' : 'orig-2'}
        self.repo_manager.create_repo('repo-1')
        self.distributor_manager.add_distributor('repo-1', 'mock-distributor', distributor_config, False, 'dist-2')

        # Test
        publish_overrides = {'key-1' : 'new-1', 'key-3' : 'new-3'}
        self.publish_manager.publish('repo-1', 'dist-2', publish_overrides)

        # Verify call into mock
        call_args = mock_plugins.MOCK_DISTRIBUTOR.publish_repo.call_args[0]

        self.assertEqual('repo-1', call_args[0].id)
        self.assertTrue(call_args[1] is not None)
        self.assertEqual({}, call_args[2].plugin_config)
        self.assertEqual(distributor_config, call_args[2].repo_plugin_config)
        self.assertEqual(publish_overrides, call_args[2].override_config)

    def test_publish_missing_repo(self):
        """
        Tests the proper error is raised when a non-existent repo is specified.
        """

        # Test
        try:
            self.publish_manager.publish('not-here', 'doesnt-matter', None)
            self.fail('Expected exception was not raised')
        except publish_manager.MissingRepo, e:
            self.assertEqual('not-here', e.repo_id)
            print(e) # for coverage

    def test_publish_no_distributor(self):
        """
        Tests the proper error is raised when a non-existed distributor is specified.
        """

        # Setup
        self.repo_manager.create_repo('no-dist')

        # Test
        try:
            self.publish_manager.publish('no-dist', 'fake-dist')
            self.fail('Expected exception was not raised')
        except publish_manager.NoDistributor, e:
            self.assertEqual('no-dist', e.repo_id)
            print(e) # for coverage

    def test_publish_bad_distributor(self):
        """
        Tests the proper error is raised when a distributor is set but the distributor
        is no longer present as a plugin.
        """

        # Setup
        self.repo_manager.create_repo('repo')
        self.distributor_manager.add_distributor('repo', 'mock-distributor', None, False, distributor_id='dist-1')

        #   Simulate bouncing the server and removing the distributor plugin
        mock_plugins.DISTRIBUTOR_MAPPINGS.pop('mock-distributor')

        # Test
        try:
            self.publish_manager.publish('repo', 'dist-1', None)
            self.fail('Expected exception was not raised')
        except publish_manager.MissingDistributorPlugin, e:
            self.assertEqual('repo', e.repo_id)
            print(e) # for coverage

    def test_publish_bad_database(self):
        """
        Tests the case where the database is in a bad state and no longer has the
        repo-distributor relationship collection.
        """

        # Setup
        self.repo_manager.create_repo('repo')
        self.distributor_manager.add_distributor('repo', 'mock-distributor', None, False, distributor_id='dist-1')

        RepoDistributor.get_collection().remove()

        # Test
        try:
            self.publish_manager.publish('repo', 'dist-1')
            self.fail('Expected exception was not raised')
        except publish_manager.NoDistributor, e:
            self.assertEqual('repo', e.repo_id)
            print(e) # for coverage

    def test_publish_with_error(self):
        """
        Tests a publish when the plugin raises an error.
        """

        # Setup
        mock_plugins.MOCK_DISTRIBUTOR.publish_repo.side_effect = Exception()

        self.repo_manager.create_repo('gonna-bail')
        self.distributor_manager.add_distributor('gonna-bail', 'mock-distributor', None, False, distributor_id='bad-dist')

        # Test
        try:
            self.publish_manager.publish('gonna-bail', 'bad-dist')
            self.fail('Expected exception was not raised')
        except publish_manager.RepoPublishException, e:
            self.assertEqual('gonna-bail', e.repo_id)
            print(e) # for coverage

        # Verify
        repo_distributor = RepoDistributor.get_collection().find_one({'repo_id' : 'gonna-bail', 'id' : 'bad-dist'})

        self.assertTrue(not repo_distributor['publish_in_progress'])
        self.assertTrue(repo_distributor is not None)
        self.assertTrue(assert_last_sync_time(repo_distributor['last_publish']))

        # Cleanup
        mock_plugins.MOCK_DISTRIBUTOR.publish_repo.side_effect = None

    def test_publish_in_progress(self):
        """
        Tests trying to publish while one is in progress raises the correct error.
        """

        # Setup
        self.repo_manager.create_repo('busy')
        self.distributor_manager.add_distributor('busy', 'mock-distributor', {}, False, 'dist-1')

        #   Trick the database into thinking it's publishing
        repo_distributor = RepoDistributor.get_collection().find_one({'repo_id' : 'busy'})
        repo_distributor['publish_in_progress'] = True
        RepoDistributor.get_collection().save(repo_distributor)

        # Test
        try:
            self.publish_manager.publish('busy', 'dist-1')
            self.fail('Expected exception was not raised')
        except publish_manager.PublishInProgress, e:
            self.assertEqual('busy', e.repo_id)
            print(e) # for coverage

    def test_auto_publish_for_repo(self):
        """
        Tests automatically publishing for a repo that has both auto and non-auto
        distributors configured.
        """

        # Setup
        self.repo_manager.create_repo('publish-me')
        self.distributor_manager.add_distributor('publish-me', 'mock-distributor', {}, True, 'auto')
        self.distributor_manager.add_distributor('publish-me', 'mock-distributor-2', {}, False, 'manual')

        # Test
        self.publish_manager.auto_publish_for_repo('publish-me')

        # Verify
        self.assertEqual(1, mock_plugins.MOCK_DISTRIBUTOR.publish_repo.call_count)
        self.assertEqual(0, mock_plugins.MOCK_DISTRIBUTOR_2.publish_repo.call_count)
        
    def test_auto_publish_no_repo(self):
        """
        Tests that calling auto publish on a repo that doesn't exist or one that
        doesn't have any distributors assigned will not error.
        """

        # Test
        self.publish_manager.auto_publish_for_repo('non-existent') # should not error

    def test_auto_publish_with_error(self):
        """
        Tests that if one auto distributor raises an error the other is still
        invoked and the error properly conveys the results.
        """

        # Setup
        mock_plugins.MOCK_DISTRIBUTOR.publish_repo.side_effect = Exception()

        self.repo_manager.create_repo('publish-me')
        self.distributor_manager.add_distributor('publish-me', 'mock-distributor', {}, True, 'auto-1')
        self.distributor_manager.add_distributor('publish-me', 'mock-distributor-2', {}, True, 'auto-2')

        # Test
        try:
            self.publish_manager.auto_publish_for_repo('publish-me')
            self.fail('Expected exception was not raised')
        except publish_manager.AutoPublishException, e:
            self.assertEqual('publish-me', e.repo_id)
            self.assertEqual(1, len(e.dist_traceback_tuples))
            self.assertEqual('auto-1', e.dist_traceback_tuples[0][0])
            self.assertTrue(e.dist_traceback_tuples[0][1] is not None)
            print(e) # for coverage
            print(e.dist_traceback_tuples[0][1]) # for curiosity of the exception format

        # Cleanup
        mock_plugins.MOCK_DISTRIBUTOR.publish_repo.side_effect = None

    def test_last_publish(self):
        """
        Tests retrieving the last publish instance.
        """

        # Setup
        expected = datetime.datetime(year=2020, month=4, day=12, hour=0, minute=23)
        date_str = dateutils.format_iso8601_datetime(expected)

        dist = RepoDistributor('repo-1', 'dist-1', 'type-1', None, True)
        dist['last_publish'] = date_str
        RepoDistributor.get_collection().save(dist)

        # Test
        last = self.publish_manager.last_publish('repo-1', 'dist-1')

        # Verify
        self.assertEqual(expected, last)

    def test_last_publish_never_published(self):
        """
        Tests getting the last publish date for an unpublished repo.
        """

        # Setup
        dist = RepoDistributor('repo-1', 'dist-1', 'type-1', None, True)
        RepoDistributor.get_collection().save(dist)

        # Test
        last = self.publish_manager.last_publish('repo-1', 'dist-1') # should not error

        # Verify
        self.assertTrue(last is None)

    # -- utility tests --------------------------------------------------------

    def test_auto_distributors(self):
        """
        Tests that the query for distributors on a repo that are configured for automatic distribution is correct.
        """

        # Setup
        dist_coll = RepoDistributor.get_collection()

        dist_coll.save(RepoDistributor('repo-1', 'dist-1', 'type', None, True))
        dist_coll.save(RepoDistributor('repo-1', 'dist-2', 'type', None, True))
        dist_coll.save(RepoDistributor('repo-1', 'dist-3', 'type', None, False))
        dist_coll.save(RepoDistributor('repo-2', 'dist-1', 'type', None, True))
        dist_coll.save(RepoDistributor('repo-2', 'dist-2', 'type', None, False))

        # Test
        repo1_dists = publish_manager._auto_distributors('repo-1')
        repo2_dists = publish_manager._auto_distributors('repo-2')
        repo3_dists = publish_manager._auto_distributors('repo-3')

        # Verify
        self.assertEqual(2, len(repo1_dists))
        repo1_dist_ids = [d['id'] for d in repo1_dists]
        self.assertTrue('dist-1' in repo1_dist_ids)
        self.assertTrue('dist-2' in repo1_dist_ids)

        self.assertEqual(1, len(repo2_dists))
        repo2_dist_ids = [d['id'] for d in repo2_dists]
        self.assertTrue('dist-1' in repo2_dist_ids)

        self.assertEqual(0, len(repo3_dists))

# -- testing utilities --------------------------------------------------------

def assert_last_sync_time(time_in_iso):
    now = datetime.datetime.now(dateutils.local_tz())
    finished = dateutils.parse_iso8601_datetime(time_in_iso)

    # Compare them within a threshold since they won't be exact
    difference = now - finished
    return difference.seconds < 2