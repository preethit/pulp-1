# Copyright (c) 2012 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

from pulp.server.db.model.base import Model

class MigrationTracker(Model):
    """
    This is used to track state about our migrations package. There will be one object for each
    migration package in pulp.server.db.migrations, and we will track which migration version each
    of those packages have been advanced to.

    :ivar id:      Uniquely identifies the package, and is the name of the package
    :type id:      str
    :ivar version: The version that the migration package is currently at
    :type version: int
    """

    collection_name = 'migration_trackers'
    unique_indices = ('id',)

    # TODO: Change id to package_name
    def __init__(self, id, version):
        """
        Initialize the MigrationTracker for id and version.

        :param id:      The id is used to store the name of the migration package this object is
                        tracking
        :type  id:      str
        :param version: The version we want to set for the MigrationTracker
        :type  version: int
        """
        super(self.__class__, self).__init__()

        self.id = id
        self.version = version
        self._collection = self.get_collection()

    def delete(self):
        """
        Remove this MigrationTracker from the database.
        """
        self._collection.remove({'id': self.id})

    # TODO: Use an upsert operation to do this
    def save(self):
        """
        Save any changes made to this MigrationTracker to the database. If it doesn't exist in the
        database already, insert a new record to represent it.
        """
        # Determine if this object exists in the DB or not
        existing_mt = self._collection.find_one({'id': self.id})
        if existing_mt:
            self._collection.update({'id': self.id}, {'$set': {'version': self.version}}, safe=True)
        else:
            self._collection.insert({'id': self.id, 'version': self.version}, safe=True)
