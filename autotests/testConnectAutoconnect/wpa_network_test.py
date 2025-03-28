#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import validation
from validation import TestConnectAutoConnect
from iwd import IWD

class TestWpaNetwork(unittest.TestCase):
    '''
    The below test cases exercise the following connection scenarios:

    Network config is
    present at start time:  Connect:  AutoConnect:  Result:
    --------------------------------------------------------------------------
    False                   True                    Connection succeeds
    True                              True          Connection succeeds
    '''

    def test_wpa(self):
        tca = TestConnectAutoConnect()
        tca.validate('ssidWPA', False, None, True)
        tca.validate('ssidWPA', True, None, True)

        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
