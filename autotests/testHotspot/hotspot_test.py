#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
from iwd import IWD
from iwd import IWD_CONFIG_DIR
from iwd import PSKAgent
from iwd import NetworkType
from config import ctx
import testutil

class Test(unittest.TestCase):

    def validate_connection(self, wd, hapd, dgaf_disable=False):
        psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('Hotspot')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()

        if not dgaf_disable:
            testutil.test_ifaces_connected(device.name, hapd.ifname)
        else:
            # This is expected to fail with group traffic
            with self.assertRaises(Exception):
                testutil.test_ifaces_connected(device.name, hapd.ifname, expect_fail=True)

            # Now try again without testing group traffic
            testutil.test_ifaces_connected(device.name, hapd.ifname, group=False)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_hotspot(self):
        hapd = ctx.get_hapd_instance('ssidHotspot.conf').cli
        hapd.set_value('disable_dgaf', '0')
        hapd.reload()

        self.validate_connection(self.wd, hapd)

    def test_dgaf_disabled(self):
        hapd = ctx.get_hapd_instance('ssidHotspot.conf').cli
        hapd.set_value('disable_dgaf', '1')
        hapd.reload()

        self.validate_connection(self.wd, hapd, dgaf_disable=True)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_hotspot('example.conf')
        IWD.copy_to_storage('anqp_enabled.conf', storage_dir=IWD_CONFIG_DIR, name='main.conf')

        cls.wd = IWD(True)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.remove('/tmp/main.conf')

        cls.wd = None

if __name__ == '__main__':
    unittest.main(exit=True)
