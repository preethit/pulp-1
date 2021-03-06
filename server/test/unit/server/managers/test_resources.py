# -*- coding: utf-8 -*-
#
# Copyright © 2013 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
"""
This module contains tests for the pulp.server.managers.resources module.
"""
from datetime import datetime
import types

import mock
import pymongo

from ...base import ResourceReservationTests
from pulp.server.db.model.criteria import Criteria
from pulp.server.db.model.resources import AvailableQueue, ReservedResource
from pulp.server.managers import resources


class TestFilterAvailableQueues(ResourceReservationTests):
    """
    Test the filter_available_queues() function.
    """
    @mock.patch('pulp.server.db.model.resources.AvailableQueue.get_collection')
    def test_criteria_passed_to_mongo(self, get_collection):
        """
        Assert that the Criteria object is passed on to MongoDB.
        """
        criteria = Criteria(filters={'_id': 'some_id'})

        aqs = list(resources.filter_available_queues(criteria))

        get_collection.return_value.query.assert_called_once_with(criteria)
        self.assertEqual(aqs, list())

    def test_filter(self):
        """
        Test a filter operation to make sure the results appear to be correct.
        """
        # Make three queues. We'll filter for two of them.
        aq_1 = AvailableQueue('queue_1', 1)
        aq_1.save()
        aq_2 = AvailableQueue('queue_2', 2)
        aq_2.save()
        aq_3 = AvailableQueue('queue_3', 3)
        aq_3.save()
        criteria = Criteria(filters={'_id': {'$gt': 'queue_1'}}, sort=[('_id', pymongo.ASCENDING)])

        aqs = resources.filter_available_queues(criteria)

        # Let's assert that aqs is a generator, and then let's cast it to a list so it's easier to
        # test that we got the correct instances back.
        self.assertEqual(type(aqs), types.GeneratorType)
        aqs = list(aqs)
        self.assertEqual(all([isinstance(aq, AvailableQueue) for aq in aqs]), True)
        self.assertEqual(aqs[0].name, 'queue_2')
        self.assertEqual(aqs[0].num_reservations, 2)
        self.assertEqual(aqs[1].name, 'queue_3')
        self.assertEqual(aqs[1].num_reservations, 3)


class TestGetLeastBusyAvailableQueue(ResourceReservationTests):
    """
    Test the get_least_busy_available_queue_function().
    """
    def test_no_queues_available(self):
        """
        Test for the case when there are no reserved queues available at all.
        It should raise a NoAvailableQueues Exception.
        """
        # When no queues are available, a NoAvailableQueues Exception should be raised
        self.assertRaises(resources.NoAvailableQueues, resources.get_least_busy_available_queue)

    def test_picks_least_busy_queue(self):
        """
        Test that the function picks the least busy queue.
        """
        # Set up three available queues, with the least busy one in the middle so that we can
        # demonstrate that it did pick the least busy and not the last or first.
        available_queue_1 = AvailableQueue('busy_queue', 7)
        available_queue_1.save()
        available_queue_2 = AvailableQueue('less_busy_queue', 3)
        available_queue_2.save()
        available_queue_3 = AvailableQueue('most_busy_queue', 10)
        available_queue_3.save()

        queue = resources.get_least_busy_available_queue()

        self.assertEqual(type(queue), AvailableQueue)
        self.assertEqual(queue.num_reservations, 3)
        self.assertEqual(queue.name, 'less_busy_queue')


class TestGetOrCreateAvailableQueue(ResourceReservationTests):
    """
    Test the get_or_create_available_queue() function.
    """
    def test_create(self):
        """
        Test for the case when the requested queue does not exist.
        """
        # Let's add an AvailableQueue just to make sure that it doesn't return any existing queue.
        aq_1 = AvailableQueue('queue_1')
        aq_1.save()

        aq_2 = resources.get_or_create_available_queue('queue_2')

        # Assert that the returned instance is correct
        self.assertEqual(type(aq_2), AvailableQueue)
        self.assertEqual(aq_2.name, 'queue_2')
        # A new queue should default to 0 reservations
        self.assertEqual(aq_2.num_reservations, 0)
        # missing_since defaults to None
        self.assertEqual(aq_2.missing_since, None)
        # Now we need to assert that it made it to the database as well
        aqc = aq_2.get_collection()
        aq_bson = aqc.find_one({'_id': 'queue_2'})
        # Make sure the default values were set correctly
        self.assertEqual(aq_bson['num_reservations'], 0)
        self.assertEqual(aq_bson['missing_since'], None)

    def test_get(self):
        """
        Test for the case when the requested queue does exist.
        """
        # Let's add two AvailableQueues just to make sure that it doesn't return the wrong queue.
        aq_1 = AvailableQueue('queue_1')
        aq_1.save()
        missing_since = datetime(2013, 12, 16)
        aq_2 = AvailableQueue('queue_2', 7, missing_since)
        aq_2.save()

        aq_2 = resources.get_or_create_available_queue('queue_2')

        # Assert that the returned instance is correct
        self.assertEqual(type(aq_2), AvailableQueue)
        self.assertEqual(aq_2.name, 'queue_2')
        # Make sure the instance attributes are correct
        self.assertEqual(aq_2.num_reservations, 7)
        self.assertEqual(aq_2.missing_since, missing_since)
        # Now we need to assert that the DB is still correct
        aqc = aq_2.get_collection()
        aq_bson = aqc.find_one({'_id': 'queue_2'})
        self.assertEqual(aq_bson['num_reservations'], 7)
        self.assertEqual(aq_bson['missing_since'], missing_since)


class TestGetOrCreateReservedResource(ResourceReservationTests):
    """
    Test the get_or_create_reserved_resource() function.
    """
    def test_create(self):
        """
        Test for the case when the requested resource does not exist.
        """
        # Let's add an ReservedResource just to make sure that it doesn't return any existing
        # resource.
        rr_1 = ReservedResource('resource_1')
        rr_1.save()

        rr_2 = resources.get_or_create_reserved_resource('resource_2')

        # Assert that the returned instance is correct
        self.assertEqual(type(rr_2), ReservedResource)
        self.assertEqual(rr_2.name, 'resource_2')
        # By default, the assigned_queue should be set to None
        self.assertEqual(rr_2.assigned_queue, None)
        # A new resource should default to 1 reservations
        self.assertEqual(rr_2.num_reservations, 1)
        # Now we need to assert that it made it to the database as well
        rrc = rr_2.get_collection()
        self.assertEqual(rrc.find_one({'_id': 'resource_2'})['num_reservations'], 1)
        self.assertEqual(rrc.find_one({'_id': 'resource_2'})['assigned_queue'], None)

    def test_get(self):
        """
        Test for the case when the requested resource does exist.
        """
        # Let's add two ReservedResources just to make sure that it doesn't return the wrong
        # resource.
        rr_1 = ReservedResource('resource_1')
        rr_1.save()
        rr_2 = ReservedResource('resource_2', 'some_queue', 7)
        rr_2.save()

        rr_2 = resources.get_or_create_reserved_resource('resource_2')

        # Assert that the returned instance is correct
        self.assertEqual(type(rr_2), ReservedResource)
        self.assertEqual(rr_2.name, 'resource_2')
        self.assertEqual(rr_2.assigned_queue, 'some_queue')
        # The resource should have 7 reservations
        self.assertEqual(rr_2.num_reservations, 7)
        # Now we need to assert that the DB is still correct
        rrc = rr_2.get_collection()
        self.assertEqual(rrc.find_one({'_id': 'resource_2'})['num_reservations'], 7)
        self.assertEqual(rrc.find_one({'_id': 'resource_2'})['assigned_queue'], 'some_queue')
