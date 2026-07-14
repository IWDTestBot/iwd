#! /usr/bin/python3

import unittest
import sys

import dbus

sys.path.append('../util')
import iwd
from iwd import IWD
from hwsim import Hwsim
from hostapd import HostapdCLI

BSS_INTERFACE = 'net.connman.iwd.BasicServiceSet'


class Test(unittest.TestCase):
    def _get_rsn(self, device, ssid):
        ordered_network = device.get_ordered_network(ssid, full_scan=True)
        network = ordered_network.network_object
        self.assertEqual(len(network.extended_service_set), 1)

        path = network.extended_service_set[0]
        proxy = self.wd._bus.get_object(iwd.IWD_SERVICE, path)
        properties = dbus.Interface(proxy, iwd.DBUS_PROPERTIES)

        return properties.GetAll(BSS_INTERFACE)['RSN']

    def test_rsn(self):
        device = self.wd.list_devices(1)[0]

        rsn = self._get_rsn(device, 'ssidWPA2')
        self.assertEqual(set(map(str, rsn['KeyMgmt'])), {'wpa-psk'})
        self.assertEqual(set(map(str, rsn['Pairwise'])), {'ccmp'})
        self.assertEqual(str(rsn['Group']), 'ccmp')

        rsn = self._get_rsn(device, 'ssidSAE')
        self.assertEqual(set(map(str, rsn['KeyMgmt'])), {'sae'})
        self.assertEqual(set(map(str, rsn['Pairwise'])), {'ccmp'})
        self.assertEqual(str(rsn['Group']), 'ccmp')

        rsn = self._get_rsn(device, 'ssidTransition')
        self.assertEqual(set(map(str, rsn['KeyMgmt'])),
                         {'wpa-psk', 'sae'})
        self.assertEqual(set(map(str, rsn['Pairwise'])), {'ccmp'})
        self.assertEqual(str(rsn['Group']), 'ccmp')

    def setUp(self):
        self.wd = IWD(True)

    def tearDown(self):
        self.wd.stop()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        Hwsim()
        cls.hostapd = [
            HostapdCLI(config='ssidWPA2.conf'),
            HostapdCLI(config='ssidSAE.conf'),
            HostapdCLI(config='ssidTransition.conf'),
        ]

    @classmethod
    def tearDownClass(cls):
        cls.hostapd = None


if __name__ == '__main__':
    unittest.main(exit=True)
