#! /usr/bin/python3

import unittest
import sys, os
import dbus

sys.path.append('../util')
from config import ctx
import iwd
from iwd import IWD, IWDDBusAbstract
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI

#
# Separate client used to test DBus disconnects so we don't bring down the
# entire IWD python library
#
class AffinityClient(IWDDBusAbstract):
    def __init__(self, device_path):
        self._bus = dbus.bus.BusConnection(address_or_type=ctx.dbus_address)
        self._station_if = dbus.Interface(self._bus.get_object(iwd.IWD_SERVICE,
                                      device_path), iwd.IWD_STATION_INTERFACE)

    def set(self):
        self._station_if.SetConnectedBssAffinity(reply_handler=self._success,
                                        error_handler=self._failure)
        self._wait_for_async_op()

    def unset(self):
        self._station_if.UnsetConnectedBssAffinity(reply_handler=self._success,
                                        error_handler=self._failure)
        self._wait_for_async_op()

    def close(self):
        self._bus.close()

class Test(unittest.TestCase):
    def connect(self, device, hapd):
        ordered_network = device.get_ordered_network('TestFT', full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        self.wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.connect_bssid(hapd.bssid)

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(device, condition)

    def test_set_affinity(self):
        device = self.wd.list_devices(1)[0]

        self.connect(device, self.bss_hostapd[0])

        device.set_connected_bss_affinity()

        # IWD should not attempt to roam
        with self.assertRaises(TimeoutError):
            device.wait_for_event("roam-scan-triggered")

        device.unset_connected_bss_affinity()
        device.wait_for_event("roam-scan-triggered")

    def test_roam_below_critical(self):
        device = self.wd.list_devices(1)[0]

        self.connect(device, self.bss_hostapd[0])

        device.set_connected_bss_affinity()

        # IWD should not attempt to roam
        with self.assertRaises(TimeoutError):
            device.wait_for_event("roam-scan-triggered")

        # Lower signal past critical level
        self.bss0_rule.signal = -9000

        device.wait_for_event("roam-scan-triggered")

    def test_affinity_reset_after_roam(self):
        device = self.wd.list_devices(1)[0]

        self.connect(device, self.bss_hostapd[0])

        device.set_connected_bss_affinity()

        # Lower signal past critical level
        self.bss0_rule.signal = -9000

        device.wait_for_event("roam-scan-triggered")
        device.wait_for_event("ft-authenticating")
        device.wait_for_event("associating")
        device.wait_for_event("connected")

        # Affinity should be reset, and IWD should be trying to roam
        device.wait_for_event("roam-scan-triggered")

    def test_error_conditions(self):
        device = self.wd.list_devices(1)[0]

        # Calling set while disconnected should fail
        with self.assertRaises(iwd.NotConnectedEx):
                device.set_connected_bss_affinity()

        # Calling unset prior to a successful set should fail
        with self.assertRaises(iwd.NotConfiguredEx):
                device.unset_connected_bss_affinity()

        self.connect(device, self.bss_hostapd[0])

        device.set_connected_bss_affinity()

        # Multiple calls to set should fail
        with self.assertRaises(iwd.AlreadyExistsEx):
             device.set_connected_bss_affinity()

    def test_affinity_client_disconnect(self):
        device = self.wd.list_devices(1)[0]

        client = AffinityClient(device.device_path)

        self.connect(device, self.bss_hostapd[0])

        client.set()

        with self.assertRaises(TimeoutError):
            device.wait_for_event("roam-scan-triggered")

        client._bus.close()

        device.wait_for_event("roam-scan-triggered")

    def test_affinity_client_reconnect_during_roam(self):
        device = self.wd.list_devices(1)[0]

        client = AffinityClient(device.device_path)

        self.connect(device, self.bss_hostapd[0])

        client.set()

        # Lower signal past critical level
        self.bss0_rule.signal = -9000

        device.wait_for_event("roam-scan-triggered")

        client.close()
        del client
        client = AffinityClient(device.device_path)
        # setting here should get cleared after connecting
        client.set()

        device.wait_for_event("ft-authenticating")
        device.wait_for_event("associating")
        device.wait_for_event("connected")

        # Affinity should be reset, and IWD should be trying to roam
        device.wait_for_event("roam-scan-triggered")

    def test_cleanup_with_connected_client(self):
        device = self.wd.list_devices(1)[0]

        client = AffinityClient(device.device_path)

        self.connect(device, self.bss_hostapd[0])

        client.set()
        self.wd.stop()

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

        self.wd.stop()
        self.wd = None

    def setUp(self):
        self.bss0_rule.signal = -8000
        self.bss1_rule.signal = -8000

        self.wd = IWD(True)

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('TestFT.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ft-psk-ccmp-1.conf'),
                            HostapdCLI(config='ft-psk-ccmp-2.conf') ]

        rad0 = hwsim.get_radio('rad0')
        rad1 = hwsim.get_radio('rad1')

        cls.bss0_rule = hwsim.rules.create()
        cls.bss0_rule.source = rad0.addresses[0]
        cls.bss0_rule.bidirectional = True
        cls.bss0_rule.signal = -8000
        cls.bss0_rule.enabled = True

        cls.bss1_rule = hwsim.rules.create()
        cls.bss1_rule.source = rad1.addresses[0]
        cls.bss1_rule.bidirectional = True
        cls.bss1_rule.signal = -8000
        cls.bss1_rule.enabled = True

        cls.bss_hostapd[0].set_address('12:00:00:00:00:01')
        cls.bss_hostapd[1].set_address('12:00:00:00:00:02')

        HostapdCLI.group_neighbors(*cls.bss_hostapd)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.bss0_rule.remove()
        cls.bss1_rule.remove()

if __name__ == '__main__':
    unittest.main(exit=True)
