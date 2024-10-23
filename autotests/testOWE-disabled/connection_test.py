#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD, Network
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def test_autoconnect_to_open(self):
        IWD.copy_to_storage("transition.open")

        wd = IWD(True)

        devices = wd.list_devices(1)
        device = devices[0]
        device.autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()

        network = Network(device.connected_network)

        self.assertEqual(network.name, "transition")
        self.assertIn(device.address, self.hapd.list_sta())

        device.disconnect()

    def setUp(self):
        self.hapd = HostapdCLI(config="ssidOpen.conf")
        pass

    def tearDown(self):
        IWD.clear_storage()

        self.wd = None

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
