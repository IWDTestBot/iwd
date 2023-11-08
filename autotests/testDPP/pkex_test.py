#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD, SharedCodeAgent
from iwd import DeviceProvisioning
from wpas import Wpas
from hostapd import HostapdCLI
from hwsim import Hwsim
from config import ctx
from time import time
import os

class Test(unittest.TestCase):
    def start_wpas_pkex(self, code, curve=None, **kwargs):
        self.wpas.dpp_bootstrap_gen(type='pkex', curve=curve)
        self.wpas.dpp_pkex_add(code=code, **kwargs)
        if kwargs.get('role', 'configurator') == 'configurator':
            self.wpas.dpp_configurator_create()
            self.wpas.dpp_listen(2437)

    def start_iwd_pkex_configurator(self, device, agent=False):
        self.hapd.reload()
        self.hapd.wait_for_event('AP-ENABLED')

        IWD.copy_to_storage('ssidCCMP.psk')
        device.autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(device, condition)

        if agent:
            self.agent = SharedCodeAgent(codes = {"test": "secret123"})

            device.dpp_pkex_start_configurator(self.agent.path)
        else:
            device.dpp_pkex_configure_enrollee('secret123', identifier="test")

    def test_pkex_iwd_as_enrollee(self):
        self.start_wpas_pkex('secret123', identifier="test")

        self.device[0].dpp_pkex_enroll('secret123', identifier="test")

        self.wpas.wait_for_event("DPP-AUTH-SUCCESS")

    def test_pkex_iwd_as_enrollee_retransmit(self):
        self.rule_reveal_req.enabled = True

        self.start_wpas_pkex('secret123', identifier="test")

        self.device[0].dpp_pkex_enroll('secret123', identifier="test")

        self.wpas.wait_for_event("DPP-AUTH-SUCCESS")

    def test_pkex_unsupported_version(self):
        self.start_wpas_pkex('secret123', identifier="test", version=2)

        now = time()
        self.device[0].dpp_pkex_enroll('secret123', identifier="test")

        condition = "obj.started == False"
        self.wd.wait_for_object_condition(self.device[0]._sc_device_provisioning,
                                            condition, max_wait=125)

        # Check the enrollee stopped after 2 minutes
        elapsed = time() - now
        self.assertLess(elapsed, 125)

    def test_pkex_configurator_timeout(self):
        self.start_iwd_pkex_configurator(self.device[0])

        now = time()

        condition = "obj.started == False"
        self.wd.wait_for_object_condition(self.device[0]._sc_device_provisioning,
                                            condition, max_wait=125)

        # Check the enrollee stopped after 2 minutes
        elapsed = time() - now
        self.assertLess(elapsed, 125)

    def test_pkex_iwd_as_configurator(self):
        self.start_iwd_pkex_configurator(self.device[0])

        self.start_wpas_pkex('secret123', identifier="test", initiator=True,
                                            role='enrollee')

        self.wpas.wait_for_event("DPP-AUTH-SUCCESS")
        self.wpas.wait_for_event("DPP-CONF-RECEIVED")

    def test_pkex_iwd_as_configurator_retransmit(self):
        self.rule_xchg_resp.enabled = True
        self.rule_reveal_resp.enabled = True

        self.start_iwd_pkex_configurator(self.device[0])

        self.start_wpas_pkex('secret123', identifier="test", initiator=True,
                                            role='enrollee')

        self.wpas.wait_for_event("DPP-AUTH-SUCCESS")
        self.wpas.wait_for_event("DPP-CONF-RECEIVED")

    def test_pkex_iwd_as_configurator_bad_group(self):
        self.start_iwd_pkex_configurator(self.device[0])

        self.start_wpas_pkex('secret123', identifier="test", initiator=True,
                                role='enrollee', curve='P-384')

        self.wpas.wait_for_event(f"DPP-RX src={self.device[0].address} freq=2437 type=8")
        self.wpas.wait_for_event("DPP-FAIL")

    def test_pkex_iwd_to_iwd(self):
        self.start_iwd_pkex_configurator(self.device[0])

        self.device[1].dpp_pkex_enroll('secret123', identifier="test")

        self.device[1].autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device[1], condition)

        self.assertTrue(os.path.exists('/tmp/ns0/ssidCCMP.psk'))

        with open('/tmp/ns0/ssidCCMP.psk') as f:
            data = f.read()

        self.assertIn("SendHostname", data)
        self.assertIn("SharedCode=secret123", data)
        self.assertIn("ExactConfig=true", data)

    def test_pkex_configurator_with_agent(self):
        self.start_iwd_pkex_configurator(self.device[0], agent=True)

        self.device[1].dpp_pkex_enroll('secret123', identifier="test")

        self.device[1].autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device[1], condition)

        self.agent = None

    def setUp(self):
        ns0 = ctx.get_namespace('ns0')
        self.wpas = Wpas('wpas.conf')

        self.wd = IWD(True)
        self.wd_ns0 = IWD(True, iwd_storage_dir='/tmp/ns0', namespace=ns0)
        self.device = []
        self.device.append(self.wd.list_devices(1)[0])
        self.device.append(self.wd_ns0.list_devices(1)[0])
        self.hapd = HostapdCLI('hostapd.conf')
        self.hapd.disable()
        self.hwsim = Hwsim()

        self.rule_xchg_resp = self.hwsim.rules.create()
        self.rule_xchg_resp.prefix = 'd0'
        self.rule_xchg_resp.match_offset = 24
        self.rule_xchg_resp.match = '04 09 50 6f 9a 1a 01 08'
        self.rule_xchg_resp.match_times = 1
        self.rule_xchg_resp.drop = True

        self.rule_reveal_resp = self.hwsim.rules.create()
        self.rule_reveal_resp.prefix = 'd0'
        self.rule_reveal_resp.match_offset = 24
        self.rule_reveal_resp.match = '04 09 50 6f 9a 1a 01 0a'
        self.rule_reveal_resp.match_times = 1
        self.rule_reveal_resp.drop = True

        self.rule_reveal_req = self.hwsim.rules.create()
        self.rule_reveal_req.prefix = 'd0'
        self.rule_reveal_req.match_offset = 24
        self.rule_reveal_req.match = '04 09 50 6f 9a 1a 01 09'
        self.rule_reveal_req.match_times = 1
        self.rule_reveal_req.drop = True

    def tearDown(self):
        # Tests end in various states, don't fail when tearing down.
        try:
            self.device[0].disconnect()
            self.device[0].dpp_pkex_stop()
            self.device[1].disconnect()
            self.device[1].dpp_pkex_stop()
        except:
            pass

        self.wpas.dpp_configurator_remove()
        self.wpas.clean_up()

        self.wd = None
        self.wd_ns0 = None
        self.device = None
        self.wpas = None
        self.hapd = None
        self.rule_xchg_resp = None
        IWD.clear_storage()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)