#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
from hwsim import Hwsim
import testutil
import os
from configparser import ConfigParser
from dataclasses import dataclass

@dataclass
class KnownFreq:
    uuid: str
    freqs: list

class Test(unittest.TestCase):
    def connect_network(self, wd, device, network, scan=False):
        ordered_network = device.get_ordered_network(network, full_scan=scan)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def read_known_freqs(self):
        ret = {}
        config = ConfigParser()
        config.read('/tmp/iwd/.known_network.freq')
        for s in config.sections():
            ret[os.path.basename(config[s]['name'])] = KnownFreq(s, config[s]['list'].split(' '))

        return ret

    def test_connection_success(self):
        hostapd_psks = [
            HostapdCLI(config="ssidCCMP-2G-1.conf"),
            HostapdCLI(config="ssidCCMP-2G-2.conf"),
            HostapdCLI(config="ssidCCMP-5G.conf"),
        ]

        hwsim = Hwsim()

        rule0 = hwsim.rules.create()
        rule0.source = hostapd_psks[0].bssid
        rule0.signal = -2000
        rule0.enabled = True

        rule1 = hwsim.rules.create()
        rule1.source = hostapd_psks[1].bssid
        rule1.signal = -5000
        rule1.enabled = True

        rule2 = hwsim.rules.create()
        rule2.source = hostapd_psks[2].bssid
        rule2.signal = -7000
        rule2.enabled = True

        wd = IWD(True, '/tmp')

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        #
        # Connect to the PSK network, then Hotspot so IWD creates 2 entries in
        # the known frequency file.
        #
        self.connect_network(wd, device, "ssidCCMP")

        wd.unregister_psk_agent(psk_agent)

        psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        self.connect_network(wd, device, 'Hotspot')

        wd.unregister_psk_agent(psk_agent)

        psk_freqs = None
        psk_uuid = None
        hs20_freqs = None

        freqs = self.read_known_freqs()

        psk_freqs = freqs['ssidCCMP.psk']
        hs20_freqs = freqs['example.conf']

        #
        # Verify the frequencies are what we expect
        #
        self.assertIsNotNone(psk_freqs)
        self.assertIsNotNone(psk_freqs.uuid)
        # Save to compare later
        psk_uuid = psk_freqs.uuid
        self.assertIn('5180', psk_freqs.freqs)
        # First should be the connected network. The other two's order is
        # unknown since its based on whenever the BSS was seen.
        self.assertEqual(psk_freqs.freqs[0], '2412')

        self.assertIsNotNone(hs20_freqs)
        self.assertIsNotNone(hs20_freqs.uuid)
        self.assertIn('2417', hs20_freqs.freqs)

        #
        # Forget all know networks, this should remove all entries in the
        # known frequencies file.
        #
        for n in wd.list_known_networks():
            n.forget()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        # Rank a different BSS higher
        rule0.signal = -7000
        rule1.signal = -2000

        #
        # Reconnect, this should generate a completely new UUID since we
        # previously forgot the network.
        #
        self.connect_network(wd, device, 'ssidCCMP', scan=True)

        wd.unregister_psk_agent(psk_agent)

        #
        # Ensure that a new UUID was created and that we still have the same
        # frequencies listed.
        #
        psk_freqs = None
        psk_uuid2 = None
        hs20_freqs = None

        freqs = self.read_known_freqs()

        psk_freqs = freqs['ssidCCMP.psk']

        self.assertIsNotNone(psk_freqs)
        self.assertIsNotNone(psk_freqs.uuid)
        self.assertNotEqual(psk_uuid2, psk_freqs.uuid)
        self.assertIn('5180', psk_freqs.freqs)
        # The 2417 frequency BSS should be first
        self.assertEqual(psk_freqs.freqs[0], '2417')

        # Rank the 5G BSS highest
        rule0.signal = -7000
        rule1.signal = -7000
        rule2.signal = -2000

        print("CONNECTING AGAGIn")
        self.connect_network(wd, device, 'ssidCCMP', scan=True)

        freqs = self.read_known_freqs()

        psk_freqs = freqs['ssidCCMP.psk']

        # The 5180 frequency BSS should now be first, followed by 2417
        self.assertEqual(psk_freqs.freqs[0], '5180')
        self.assertEqual(psk_freqs.freqs[1], '2417')

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_hotspot('example.conf')
        conf = '[General]\nDisableANQP=0\n'
        os.system('echo "%s" > /tmp/main.conf' % conf)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.remove('/tmp/main.conf')

if __name__ == '__main__':
    unittest.main(exit=True)
