# -*- coding: utf-8 -*-
#
# Copyright © 2011 Red Hat, Inc.
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
Contains exceptions raised by repository-related managers.
"""

from gettext import gettext as _

# -- not found ----------------------------------------------------------------

class MissingRepo(Exception):
    """
    Indicates an operation was requested against a repo that doesn't exist. This
    is used in any repo-related operation when the repo doesn't exist.
    """
    def __init__(self, repo_id):
        Exception.__init__(self)
        self.repo_id = repo_id

    def __str__(self):
        return _('No repository with ID [%(id)s]' % {'id' : self.repo_id})

class MissingImporter(Exception):
    """
    Indicates an importer was requested that does not exist. No ID is included
    since only one importer is allowed on a repo.
    """
    pass

class MissingDistributor(Exception):
    """
    Indicates a distributor was requested that does not exist.
    """
    def __init__(self, distributor_id):
        Exception.__init__(self)
        self.distributor_id = distributor_id

    def __str__(self):
        return _('No distributor with ID [%(id)s]' % {'id' : self.distributor_id})

class InvalidDistributorType(Exception):
    """
    Indicates a distributor type was requested that doesn't exist.
    """
    def __init__(self, distributor_type_id):
        Exception.__init__(self)
        self.distributor_type_id = distributor_type_id

    def __str__(self):
        return _('No distributor type with id [%(id)s]' % {'id' : self.distributor_type_id})

class InvalidImporterType(Exception):
    """
    Indicates an importer type was requested that doesn't exist.
    """
    def __init__(self, importer_type_id):
        Exception.__init__(self)
        self.importer_type_id = importer_type_id

    def __str__(self):
        return _('No importer type with id [%(id)s]' % {'id' : self.importer_type_id})

# -- validation and configuration ---------------------------------------------

class InvalidRepoId(Exception):
    """
    Indicates a given repository ID was invalid.
    """
    def __init__(self, invalid_repo_id):
        Exception.__init__(self)
        self.invalid_repo_id = invalid_repo_id

    def __str__(self):
        return _('Invalid repository ID [%(repo_id)s]') % {'repo_id' : self.invalid_repo_id}

class InvalidRepoMetadata(Exception):
    """
    Indicates one or more metadata fields on a repository were invalid, either
    in a create or update operation. The invalid value will be included in
    the exception.
    """
    def __init__(self, invalid_data):
        Exception.__init__(self)
        self.invalid_data = invalid_data

    def __str__(self):
        return _('Invalid repo metadata [%(data)s]' % {'data' : str(self.invalid_data)})

class DuplicateRepoId(Exception):
    """
    Raised when a repository create conflicts with an existing repository ID.
    """
    def __init__(self, duplicate_id):
        Exception.__init__(self)
        self.duplicate_id = duplicate_id

    def __str__(self):
        return _('Existing repository with ID [%(repo_id)s]') % {'repo_id' : self.duplicate_id}

class InvalidDistributorId(Exception):
    """
    Indicates a given distributor ID was invalid.
    """
    def __init__(self, invalid_distributor_id):
        Exception.__init__(self)
        self.invalid_distributor_id = invalid_distributor_id

    def __str__(self):
        return _('Invalid distributor ID [%(id)s]' % {'id' : self.invalid_distributor_id})

class InvalidDistributorConfiguration(Exception):
    """
    Indicates a distributor configuration was specified (either at add_distributor
    time or later updated) but the distributor plugin indicated it was invalid.
    """
    pass

class InvalidImporterConfiguration(Exception):
    """
    Indicates an importer configuration was specified (either at set_importer
    time or later updated) but the importer plugin indicated it is invalid.
    """
    pass

# -- repo lifecycle -----------------------------------------------------------

class RepoDeleteException(Exception):
    """
    Aggregates all exceptions that occurred during a repo delete and tracks
    the general area in which they occurred.
    """

    CODE_IMPORTER = 'importer-error'
    CODE_DISTRIBUTOR = 'distributor-error'
    CODE_WORKING_DIR = 'working-dir-error'
    CODE_DATABASE = 'database-error'

    def __init__(self, codes):
        Exception.__init__(self)
        self.codes = codes

class DistributorInitializationException(Exception):
    """
    Wraps an exception coming out of a distributor while it tries to initialize
    itself when being added to a repository.
    """
    pass

class ImporterInitializationException(Exception):
    """
    Wraps an exception coming out of an importer while it tries to initialize
    itself when being added to a repository.
    """
    pass

# -- sync ---------------------------------------------------------------------

class RepoSyncException(Exception):
    """
    Raised when an error occurred during a repo sync. Subclass exceptions are
    used to further categorize the error encountered. The ID of the repository
    that caused the error is included in the exception.
    """
    def __init__(self, repo_id):
        Exception.__init__(self)
        self.repo_id = repo_id

    def __str__(self):
        return _('Exception [%(e)s] raised for repository [%(r)s]') % \
               {'e' : self.__class__.__name__, 'r' : self.repo_id}

class NoImporter(RepoSyncException):
    """
    Indicates a sync was requested on a repository that is not configured
    with an importer.
    """
    pass

class MissingImporterPlugin(RepoSyncException):
    """
    Indicates a repo is configured with an importer type that could not be
    found in the plugin manager.
    """
    pass

class SyncInProgress(RepoSyncException):
    """
    Indicates a sync was requested for a repo already in the process of
    synchronizing the repo.
    """
    pass

# -- publish ------------------------------------------------------------------

class RepoPublishException(Exception):
    """
    Raised when an error occurred during a repo publish. Subclass exceptions are
    used to further categorize the error encountered. The ID of the repository
    that caused the error is included in the exception.
    """
    def __init__(self, repo_id):
        Exception.__init__(self)
        self.repo_id = repo_id

    def __str__(self):
        return _('Exception [%(e)s] raised for repository [%(r)s]') % \
               {'e' : self.__class__.__name__, 'r' : self.repo_id}

class NoDistributor(RepoPublishException):
    """
    Indicates a sync was requested on a repository that is not configured
    with an distributor.
    """
    pass

class MissingDistributorPlugin(RepoPublishException):
    """
    Indicates a repo is configured with an distributor type that could not be
    found in the plugin manager.
    """
    pass

class PublishInProgress(RepoPublishException):
    """
    Indicates a publish was requested for a repo and distributor already in
    the process of publishing the repo.
    """
    pass

class AutoPublishException(Exception):
    """
    Raised when the automatic publishing of a repository results in an error
    for at least one of the distributors. This exception will
    """
    def __init__(self, repo_id, dist_traceback_tuples):
        Exception.__init__(self)
        self.repo_id = repo_id
        self.dist_traceback_tuples = dist_traceback_tuples

    def __str__(self):
        dist_ids = [d[0] for d in self.dist_traceback_tuples]
        return _('Exception [%(e)s] raised for repository [%(r)s] on distributors [%(d)s]' % \
               {'e' : self.__class__.__name__, 'r' : self.repo_id, 'd' : ', '.join(dist_ids)})
