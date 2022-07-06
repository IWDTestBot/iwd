#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from config import ctx

from time import sleep

class Test(unittest.TestCase):

    def test_connection_success(self):
        hwsim = Hwsim()

        hostapd = ctx.get_hapd_instance('ssidCCMP.conf').cli
        radio = hwsim.get_radio('rad0')

        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidCCMP')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        # Ensure IWD is not scanning. This causes problems with mac80211_hwsim
        # where CMD_FRAME will fail during a scan. This is due to the frame not
        # having the same frequency as the radio (since hwsim is off-channel)
        if device.scanning:
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(device, condition)

        hwsim.spoof_eap_fail(radio, hostapd.frequency, device.address)
        hwsim.spoof_invalid_ptk_1_of_4(radio, hostapd.frequency, device.address)

        with self.assertRaises(TimeoutError):
            condition = 'obj.state == DeviceState.disconnected'
            wd.wait_for_object_condition(device, condition, 4)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
