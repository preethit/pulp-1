# -*- coding: utf-8 -*-
#
# Copyright © 2014 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

import os

from unittest import TestCase

from mock import patch, Mock
from M2Crypto import RSA, BIO
from gofer.messaging.auth import ValidationFailed

from pulp.common.config import Config

TEST_HOST = 'test-host'
TEST_PORT = '443'
TEST_CN = 'test-cn'

TEST_BUNDLE = """
-----BEGIN RSA PRIVATE KEY-----
KEY
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
CERTIFICATE
-----END CERTIFICATE-----
"""

TEST_ID_CERT_DIR = '/___fake18/cert-dir'
TEST_ID_CERT_FILE = 'test-cert'


CERT_PATH = os.path.join(TEST_ID_CERT_DIR, TEST_ID_CERT_FILE)


RSA_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDbZu3/ml//XLdb+n8fMklr3CkpBYfIqYFGQzcfDyIBGJUrWZRQ
gwkQn2P9J8QgVyNSrByFN1DbEJvrY9Lo6kzqy8flh9Ws1GKMRfqJZk99/Zae/Wbn
9dQqa9EYrMZR3pO5UMmpSRFzZNTWEvmP4WAP4fque1VQJiUwXnMkTSO7cQIDAQAB
AoGAQdtrpUXZevWBtIJElkCp+U5krIOUdo8q1sRmT1RjiKCwZgrFkkVC+1Jc2SiO
noaJe89d4D7ybk9V/hpAvNlXrLSc+Gaq8xEOITiiAE1G09Ojc9Q0SFxhW9Sugq/T
dw44QSxA2wJ8zo9nImwKAEAzt6lDOaCQ2qZrZFkSUSYbboECQQDytgjrK9FsrMSF
yz88UCPOo6BLNoXoDgN5SKWEPn+Q3hz+qRy6ka9YDUaxx19C0jiZRAYeg96Zh2MG
CAWWfRCVAkEA52ovBITgWaPYHJcSlIK4rkgpYnD5atLZuajwhnWeBQ0sPhy06CNO
Cp+PIVIYVWtHcmxJk1aOFYsG29G9rg38bQJAMLI/Ndfzy8caIvH1fQdjN8lylsSY
t0dggQwHUXIsrAc0cA/EGNa0BImdXnvu6/w7qNySEbtJhSo5vvMLE/eBxQJATm9y
EkELXban+EDIPmf0OrYguMn779YZj9EP/TL+ZU3qsf6+3nOg7v7X335Y2xLqe4Dy
iyrqK6kcoQL9HHKHHQJAT5jTKawl830Zx85t/j42NNhHsMyXXgtmz4lYyhb/UCik
8vRK7LSjxYvCgnFT+wXT9hOjfEW+AnOKYJTHai4BNw==
-----END RSA PRIVATE KEY-----
"""

OTHER_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDcx31TTh+mcm7v3NtQrkfHL5KgRXv7uDCLI56vULYSp5HtC9F9
Jph2DT8l/XVXj0L5WMPP12VRZkmmgR9LDF5iHXnWE47Dy/6Midz4KIV1Vx7O/LdX
btzq0lYRcaEofZPSfapf7hpNMhl3G5ioUvXp6vbh9EbGLetdXeVeqii53QIDAQAB
AoGBAMiLBJIJIsLEq3SB/01YIacS1XNz6l0KQD4DCv9gpyJmyCy0UYQG7PI+sh/G
DTKN1V49fRBsLYI1Ea2HGG/JOmjhQOxjz/F1jAMbQfeTXhu/JVYlhDgOK3nC+DnF
jmJ2FfqUxr/eE87IzUF5Qm4TVffKwCSaxQ3u3xkbk9+oBkMBAkEA8OVxcTyKmgho
9hk0PHPuFIeWAgKf5015oLUZPPeYYeACiZGUnvP1BdiO9QpZyIPaEiySDb2jv0ZR
kJpHW7qpPQJBAOqfJ3Q+6v/u9pKmjcH8kEtIB8Mtnm5WIs4cLhlChI4xbm1Gawvp
Lly6GSNUvsFVxyaMrqaMQxtKdHg4MtZxHSECQBpVOn1iXNRRrweX4bnqAlCEMcWu
e8RRF8aVhVjAyAuK7TwUieaGTHaDIb1vkDj3ENODw8N0w32ZNjlUZBCG6xECQETP
ms2wKlIXrr+CE69iOJurq4Ml3QJ1Rs32W9rStHfTrZRlA75BjHRrrDW9hBjF5Ju8
xPhZyNC3PIOJz/cuw6ECQQCbfqV4YWiW0j2t/dotJjA0S/QdQYJcUbo/kNUar65v
ZdgAs+Krt4gDkn34BF5009pZf0IBANSPMeqvw4BWr3G4
-----END RSA PRIVATE KEY-----
"""

RSA_PUB = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbZu3/ml//XLdb+n8fMklr3Ckp
BYfIqYFGQzcfDyIBGJUrWZRQgwkQn2P9J8QgVyNSrByFN1DbEJvrY9Lo6kzqy8fl
h9Ws1GKMRfqJZk99/Zae/Wbn9dQqa9EYrMZR3pO5UMmpSRFzZNTWEvmP4WAP4fqu
e1VQJiUwXnMkTSO7cQIDAQAB
-----END PUBLIC KEY-----
"""


class PluginTest(TestCase):

    @staticmethod
    @patch('pulp.client.consumer.config.read_config')
    def load_plugin(mock_read):
        mock_read.return_value = Config()
        plugin = __import__('pulp.agent.gofer.pulpplugin', {}, {}, ['pulpplugin'])
        reload(plugin)
        return plugin

    def setUp(self):
        self.plugin = PluginTest.load_plugin()


class TestAuthentication(PluginTest):

    @patch('__builtin__.open')
    def test_get_key(self, mock_open):
        test_conf = {
            'server': {
                'rsa_pub': '/etc/pki/pulp/consumer/rsa_pub.pem'
            },
            'messaging': {
                'rsa_key': '/etc/pki/pulp/rsa.pem',
            }
        }

        self.plugin.pulp_conf.update(test_conf)

        mock_fp = Mock()
        mock_fp.read = Mock(return_value=RSA_KEY)
        mock_open.return_value = mock_fp

        # test

        key = self.plugin.Authenticator.rsa_key()

        # validation
        mock_open.assert_called_with(test_conf['messaging']['rsa_key'])
        mock_fp.close.assert_called_with()
        self.assertTrue(isinstance(key, RSA.RSA))

    @patch('__builtin__.open')
    def test_get_pub_key(self, mock_open):
        test_conf = {
            'server': {
                'rsa_pub': '/etc/pki/pulp/consumer/rsa_pub.pem'
            },
            'messaging': {
                'rsa_key': '/etc/pki/pulp/rsa.pem',
            }
        }

        self.plugin.pulp_conf.update(test_conf)

        mock_fp = Mock()
        mock_fp.read = Mock(return_value=RSA_PUB)
        mock_open.return_value = mock_fp

        # test

        key = self.plugin.Authenticator.rsa_pub()

        # validation

        mock_open.assert_called_with(test_conf['server']['rsa_pub'])
        mock_fp.close.assert_called_with()

        self.assertTrue(isinstance(key, RSA.RSA))

    @patch('pulp.agent.gofer.pulpplugin.Authenticator.rsa_key')
    def test_signing(self, mock_get):
        message = 'hello'
        key = RSA.load_key_bio(BIO.MemoryBuffer(RSA_KEY))

        mock_key = Mock()
        mock_key.sign = Mock(side_effect=key.sign)
        mock_get.return_value = mock_key

        # test
        auth = self.plugin.Authenticator()
        signature = auth.sign(message)

        #validation

        expected = key.sign(message)

        mock_get.assert_called_with()
        mock_key.sign.assert_called_with(message)
        self.assertEqual(expected, signature)

    @patch('pulp.agent.gofer.pulpplugin.Authenticator.rsa_pub')
    def test_validated(self, mock_get):
        uuid = 'test-uuid'
        message = 'hello'
        key = RSA.load_key_bio(BIO.MemoryBuffer(RSA_KEY))

        mock_get.return_value = RSA.load_pub_key_bio(BIO.MemoryBuffer(RSA_PUB))

        # test

        signature = key.sign(message)
        authenticator = self.plugin.Authenticator()
        authenticator.validate(uuid, message, signature)

    @patch('pulp.agent.gofer.pulpplugin.Authenticator.rsa_pub')
    def test_not_valid(self, mock_get):
        uuid = 'test-uuid'
        message = 'hello'
        key = RSA.load_key_bio(BIO.MemoryBuffer(OTHER_KEY))

        mock_get.return_value = RSA.load_pub_key_bio(BIO.MemoryBuffer(RSA_PUB))

        # test

        signature = key.sign(message)
        authenticator = self.plugin.Authenticator()
        self.assertRaises(ValidationFailed, authenticator.validate, uuid, message, signature)

    @patch('pulp.agent.gofer.pulpplugin.Authenticator.rsa_pub')
    def test_rsa_error_raised(self, mock_get):
        uuid = 'test-uuid'
        message = 'hello'
        key = RSA.load_key_bio(BIO.MemoryBuffer(OTHER_KEY))

        mock_pub = Mock()
        mock_pub.verify = Mock(return_value=False)
        mock_get.return_value = mock_pub

        # test

        signature = key.sign(message)
        authenticator = self.plugin.Authenticator()
        self.assertRaises(ValidationFailed, authenticator.validate, uuid, message, signature)


class TestBundle(PluginTest):

    @patch('pulp.common.bundle.Bundle.cn', return_value=TEST_CN)
    def test_bundle_cn(self, *unused):
        test_conf = {
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        # test
        bundle = self.plugin.ConsumerX509Bundle()
        cn = bundle.cn()

        # validation
        self.assertEqual(bundle.path, CERT_PATH)
        self.assertEqual(cn, TEST_CN)

    @patch('os.path.exists', return_value=True)
    @patch('pulp.common.bundle.Bundle.read', return_value=TEST_BUNDLE)
    def test_invalid_bundle_cn(self, *unused):
        test_conf = {
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        # test
        bundle = self.plugin.ConsumerX509Bundle()
        cn = bundle.cn()

        # validation
        self.assertEqual(bundle.path, CERT_PATH)
        self.assertEqual(cn, None)


class TestBindings(PluginTest):

    @patch('pulp.common.bundle.Bundle.cn', return_value=TEST_CN)
    @patch('pulp.agent.gofer.pulpplugin.Bindings.__init__')
    @patch('pulp.agent.gofer.pulpplugin.PulpConnection')
    def test_pulp_bindings(self, mock_conn, mock_bindings, *unused):
        test_conf = {
            'server': {
                'host': 'test-host',
                'port': '443',
            },
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        # test
        bindings = self.plugin.PulpBindings()

        # validation
        mock_conn.assert_called_with('test-host', 443, cert_filename=CERT_PATH)
        mock_bindings.assert_called_with(bindings, mock_conn())


class TestConduit(PluginTest):

    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    def test_consumer_id(self, mock_bundle):
        mock_bundle().cn = Mock(return_value=TEST_CN)

        # test
        conduit = self.plugin.Conduit()

        # validation
        self.assertEqual(conduit.consumer_id, TEST_CN)

    def test_get_consumer_config(self, *unused):
        test_conf = {
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        # test
        self.plugin.pulp_conf.update(test_conf)
        conduit = self.plugin.Conduit()
        conf = conduit.get_consumer_config()

        # validation
        self.assertEqual(conf, test_conf)

    @patch('gofer.agent.rmi.Context.current')
    def test_update_progress(self, mock_current):
        mock_context = Mock()
        mock_context.progress = Mock()
        mock_current.return_value = mock_context
        conduit = self.plugin.Conduit()
        report = {'a': 1}

        # test
        conduit.update_progress(report)

        # validation
        mock_context.progress.report.assert_called_with()
        self.assertEqual(mock_context.progress.details, report)

    @patch('gofer.agent.rmi.Context.current')
    def test_cancelled(self, mock_current):
        mock_context = Mock()
        mock_context.cancelled = Mock(return_value=True)
        mock_current.return_value = mock_context
        conduit = self.plugin.Conduit()

        # test
        cancelled = conduit.cancelled()

        # validation
        self.assertTrue(cancelled)
        self.assertTrue(mock_context.cancelled.called)

    @patch('gofer.agent.rmi.Context.current')
    def test_cancelled(self, mock_current):
        mock_context = Mock()
        mock_context.cancelled = Mock(return_value=False)
        mock_current.return_value = mock_context
        conduit = self.plugin.Conduit()

        # test
        cancelled = conduit.cancelled()

        # validation
        self.assertFalse(cancelled)
        self.assertTrue(mock_context.cancelled.called)


class TestRegistrationMonitor(PluginTest):

    @patch('pulp.agent.gofer.pulpplugin.PathMonitor.add')
    def test_init(self, mock_add):
        test_conf = {
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        # test
        self.plugin.RegistrationMonitor.init()

        # validation
        mock_add.assert_called_with(CERT_PATH, self.plugin.RegistrationMonitor.changed)

    @patch('pulp.common.bundle.Bundle.cn', return_value=TEST_CN)
    @patch('pulp.agent.gofer.pulpplugin.Plugin.find')
    def test_changed_registered(self, mock_find, *unused):
        test_conf = {
            'server': {
                'host': 'pulp-host',
                'port': '443',
            },
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            },
            'messaging': {
                'host': None,
                'scheme': 'tcp',
                'port': '5672',
                'cacert': 'test-ca',
                'clientcert': None
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        plugin = Mock()
        plugin_cfg = Mock()
        plugin_cfg.messaging = Mock()
        plugin.cfg = Mock(return_value=plugin_cfg)
        mock_find.return_value = plugin

        # test
        self.plugin.RegistrationMonitor.changed(CERT_PATH)

        # validation
        expected_url = 'tcp://pulp-host:5672'
        self.assertEqual(plugin_cfg.messaging.url, expected_url)
        self.assertEqual(plugin_cfg.messaging.cacert, 'test-ca')
        self.assertEqual(plugin_cfg.messaging.clientcert, CERT_PATH)

        mock_find().setuuid.assert_called_with(TEST_CN)

    @patch('pulp.common.bundle.Bundle.cn', return_value=TEST_CN)
    @patch('pulp.agent.gofer.pulpplugin.Plugin.find')
    def test_changed_different_broker_host(self, mock_find, *unused):
        test_conf = {
            'server': {
                'host': 'pulp-host',
                'port': '443',
            },
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            },
            'messaging': {
                'host': 'broker-host',
                'scheme': 'tcp',
                'port': '5672',
                'cacert': 'test-ca',
                'clientcert': None
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        plugin = Mock()
        plugin_cfg = Mock()
        plugin_cfg.messaging = Mock()
        plugin.cfg = Mock(return_value=plugin_cfg)
        mock_find.return_value = plugin

        # test
        self.plugin.RegistrationMonitor.changed(CERT_PATH)

        # validation
        expected_url = 'tcp://broker-host:5672'
        self.assertEqual(plugin_cfg.messaging.url, expected_url)
        self.assertEqual(plugin_cfg.messaging.cacert, 'test-ca')
        self.assertEqual(plugin_cfg.messaging.clientcert, CERT_PATH)

        mock_find().setuuid.assert_called_with(TEST_CN)

    @patch('pulp.agent.gofer.pulpplugin.Plugin.find')
    def test_changed_unregistered(self, mock_find):
        test_conf = {
            'server': {
                'host': 'test-host',
                'port': '443',
            },
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        # test
        self.plugin.RegistrationMonitor.changed(CERT_PATH)

        # validation
        mock_find().setuuid.assert_called_with(None)


class TestSynchronization(PluginTest):

    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    def test_registered(self, mock_bundle):
        mock_bundle().cn = Mock(return_value=TEST_CN)

        # test
        registered = self.plugin.Synchronization.registered()

        # validation
        self.assertTrue(registered)

    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    def test_not_registered(self, mock_bundle):
        mock_bundle().cn = Mock(return_value=None)

        # test
        registered = self.plugin.Synchronization.registered()

        # validation
        self.assertFalse(registered)

    @patch('pulp.agent.gofer.pulpplugin.Synchronization.registered')
    @patch('pulp.agent.gofer.pulpplugin.Profile.send')
    def test_send_profile_when_registered(self, mock_send, mock_registered):
        mock_registered.return_value = True
        # test
        self.plugin.Synchronization.profile()

        # validation
        mock_registered.assert_called_with()
        mock_send.assert_called_with()

    @patch('pulp.agent.gofer.pulpplugin.Synchronization.registered')
    @patch('pulp.agent.gofer.pulpplugin.Profile.send')
    def test_nosend_profile_when_not_registered(self, mock_send, mock_registered):
        mock_registered.return_value = False
        # test
        self.plugin.Synchronization.profile()

        # validation
        mock_registered.assert_called_with()
        self.assertFalse(mock_send.called)


class TestConsumer(PluginTest):

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    def test_unregistered(self, mock_bundle, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().clean.return_value = _report

        # test
        consumer = self.plugin.Consumer()
        report = consumer.unregistered()

        # validation
        mock_bundle().delete.assert_called_with()
        mock_dispatcher().clean.assert_called_with(mock_conduit())
        self.assertEqual(report, _report.dict())

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_bind(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().bind.return_value = _report

        # test
        bindings = [{'A': 1}]
        options = {'B': 2}
        consumer = self.plugin.Consumer()
        report = consumer.bind(bindings, options)

        # validation
        mock_dispatcher().bind.assert_called_with(mock_conduit(), bindings, options)
        self.assertEqual(report, _report.dict())

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_unbind(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().unbind.return_value = _report

        # test
        bindings = [{'A': 1}]
        options = {'B': 2}
        consumer = self.plugin.Consumer()
        report = consumer.unbind(bindings, options)

        # validation
        mock_dispatcher().unbind.assert_called_with(mock_conduit(), bindings, options)
        self.assertEqual(report, _report.dict())


class TestContent(PluginTest):

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_install(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().install.return_value = _report

        # test
        units = [{'A': 1}]
        options = {'B': 2}
        content = self.plugin.Content()
        report = content.install(units, options)

        # validation
        mock_dispatcher().install.assert_called_with(mock_conduit(), units, options)
        self.assertEqual(report, _report.dict())

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_update(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().update.return_value = _report

        # test
        units = [{'A': 10}]
        options = {'B': 20}
        content = self.plugin.Content()
        report = content.update(units, options)

        # validation
        mock_dispatcher().update.assert_called_with(mock_conduit(), units, options)
        self.assertEqual(report, _report.dict())

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_uninstall(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().uninstall.return_value = _report

        # test
        units = [{'A': 100}]
        options = {'B': 200}
        content = self.plugin.Content()
        report = content.uninstall(units, options)

        # validation
        mock_dispatcher().uninstall.assert_called_with(mock_conduit(), units, options)
        self.assertEqual(report, _report.dict())


class TestProfile(PluginTest):

    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    @patch('pulp.agent.gofer.pulpplugin.PulpBindings')
    def test_send(self, mock_bindings, mock_dispatcher, mock_conduit, mock_bundle):
        mock_bundle().cn = Mock(return_value=TEST_CN)

        test_conf = {
            'server': {
                'host': 'test-host',
                'port': '443',
            },
            'filesystem': {
                'id_cert_dir': TEST_ID_CERT_DIR,
                'id_cert_filename': TEST_ID_CERT_FILE
            }
        }
        self.plugin.pulp_conf.update(test_conf)

        _report = Mock()
        _report.details = {
            'AA': {'succeeded': False, 'details': 1234},
            'BB': {'succeeded': True, 'details': 5678}
        }
        _report.dict = Mock(return_value=_report.details)

        mock_dispatcher().profile.return_value = _report

        # test
        profile = self.plugin.Profile()
        report = profile.send()

        # validation
        mock_dispatcher().profile.assert_called_with(mock_conduit())
        mock_bindings().profile.send.assert_called_once_with(TEST_CN, 'BB', 5678)