#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def validate_connection(self, wd):
        device = wd.list_devices(1)[0]

        ordered_network = device.get_ordered_network('TestFT', full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertFalse(self.bss_hostapd[0].list_sta())
        self.assertFalse(self.bss_hostapd[1].list_sta())

        device.connect_bssid(self.bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[1].ifname, device.name, True, True))

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        self.bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[1].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[0].ifname, device.name, True, True))

        self.bss_hostapd[1].deauthenticate(device.address)
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_ft_psk(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[0].set_value('ft_over_ds', '0')
        self.bss_hostapd[0].set_value('ocv', '1')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[1].set_value('ft_over_ds', '0')
        self.bss_hostapd[1].set_value('ocv', '1')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        self.bss_hostapd[2].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[2].set_value('ft_over_ds', '0')
        self.bss_hostapd[2].set_value('ocv', '1')
        self.bss_hostapd[2].reload()
        self.bss_hostapd[2].wait_for_event("AP-ENABLED")

        self.validate_connection(wd)

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('TestFT.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ft-psk-ccmp-1.conf'),
                            HostapdCLI(config='ft-psk-ccmp-2.conf'),
                            HostapdCLI(config='ft-psk-ccmp-3.conf') ]

        cls.bss_hostapd[0].set_address('12:00:00:00:00:01')
        cls.bss_hostapd[1].set_address('12:00:00:00:00:02')
        cls.bss_hostapd[2].set_address('12:00:00:00:00:03')

        # Connect here first, worst candidate
        cls.rule0 = hwsim.rules.create()
        cls.rule0.source = hwsim.get_radio('rad0').addresses[0]
        cls.rule0.bidirectional = True
        cls.rule0.signal = -8500
        cls.rule0.enabled = True

        # Second best candidate, IWD should eventually get here after failing
        # to connect to bss_hostapd[2]
        cls.rule1 = hwsim.rules.create()
        cls.rule1.source = hwsim.get_radio('rad1').addresses[0]
        cls.rule1.bidirectional = True
        cls.rule1.signal = -8000
        cls.rule1.enabled = True

        # Best candidate, IWD should try this first, fail (since auth is
        # dropped), and move onto another candidate.
        cls.rule2 = hwsim.rules.create()
        cls.rule2.source = hwsim.get_radio('rad2').addresses[0]
        cls.rule2.bidirectional = True
        cls.rule2.signal = -2000
        cls.rule2.prefix = 'b0'
        cls.rule2.drop = True
        cls.rule2.enabled = True

        HostapdCLI.group_neighbors(*cls.bss_hostapd)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.rule0.enabled = False
        cls.rule1.enabled = False
        cls.rule2.enabled = False

if __name__ == '__main__':
    unittest.main(exit=True)
