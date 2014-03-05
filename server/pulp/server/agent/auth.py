# Copyright (c) 2014 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

from M2Crypto import RSA, BIO
from gofer.messaging.auth import ValidationFailed

from pulp.server.config import config as pulp_conf
from pulp.server.managers import factory as managers
from pulp.common.config import parse_bool


class Authenticator(object):

    @property
    def enabled(self):
        enabled = pulp_conf.get('messaging', 'auth_enabled')
        return parse_bool(enabled)

    @staticmethod
    def rsa_key():
        path = pulp_conf.get('messaging', 'rsa_key')
        with open(path) as fp:
            pem = fp.read()
            bfr = BIO.MemoryBuffer(pem)
            return RSA.load_key_bio(bfr)

    @staticmethod
    def rsa_pub(consumer_id):
        rsa_pub = 'rsa_pub'
        manager = managers.consumer_manager()
        consumer = manager.get_consumer(consumer_id, fields=[rsa_pub])
        pem = consumer[rsa_pub]
        bfr = BIO.MemoryBuffer(pem)
        return RSA.load_pub_key_bio(bfr)

    def sign(self, message):
        if not self.enabled:
            return ''
        key = self.rsa_key()
        signature = key.sign(message)
        return signature

    def validate(self, uuid, message, signature):
        if not self.enabled:
            return
        key = self.rsa_pub(uuid)
        try:
            if not key.verify(message, signature):
                raise ValidationFailed(message)
        except RSA.RSAError:
            raise ValidationFailed(message)
