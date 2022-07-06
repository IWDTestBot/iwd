#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from config import ctx

class Test(unittest.TestCase):

    def validate_connection(self, wd, passphrase):
        psk_agent = PSKAgent(passphrase)
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        network = device.get_ordered_network('ssidSAE')

        self.assertEqual(network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        with self.assertRaises(iwd.FailedEx):
            network.network_object.connect()

        wd.unregister_psk_agent(psk_agent)

    def test_connection_success(self):
        wd = IWD(True)
        self.validate_connection(wd, 'InvalidSecret')

    def test_no_supported_groups(self):
        hostapd = ctx.get_hapd_instance('ssidSAE.conf').cli
        hostapd.set_value('sae_groups', '1')
        hostapd.reload()

        wd = IWD(True)
        self.validate_connection(wd, 'secret123')

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
