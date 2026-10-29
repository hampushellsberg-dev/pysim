#!/usr/bin/env python3

# (C) 2026 by Hampus Hellsberg <hampushellsberg@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
from osmocom.utils import h2b

import pySim.esim.rsp as rsp

SKI_V2 = '11' * 20
SKI_V3 = '22' * 20

def tlv(tag: str, value_hex: str) -> str:
    """Hex of a DER TLV (length below 256), for building the test vectors by hand."""
    length = len(value_hex) // 2
    assert length < 0x100
    if length < 0x80:
        return tag + '%02x' % length + value_hex
    return tag + '81%02x' % length + value_hex

# EUICCInfo1 as an SGP.22 v3.1 eUICC returns it (SGP.22 v3.1 Annex H)
EUICC_INFO1_V3 = tlv('bf20',
    tlv('82', '030100') +                       # lowestSvn [2] (svn in v2)
    tlv('a9', tlv('04', SKI_V2)) +              # euiccCiPKIdListForVerification [9]
    tlv('aa', tlv('04', SKI_V2)) +              # euiccCiPKIdListForSigning [10]
    tlv('b1', tlv('04', SKI_V3)) +              # euiccCiPKIdListForSigningV3 [17]
    tlv('88', '05900020') +                     # euiccRspCapability [8]: bits 0, 3, 18
    tlv('93', '030100'))                        # highestSvn [19]

EUICC_INFO1_V2 = tlv('bf20',
    tlv('82', '020500') +
    tlv('a9', tlv('04', SKI_V2)) +
    tlv('aa', tlv('04', SKI_V2)))

EUICC_INFO2_V3 = tlv('bf22',
    tlv('81', '030301') +                       # profileVersion [1]
    tlv('82', '030100') +                       # svn [2]
    tlv('83', '010203') +                       # euiccFirmwareVer [3]
    tlv('84', '0103') +                         # extCardResource [4]
    tlv('85', '0780') +                         # uiccCapability [5]
    tlv('88', '0490') +                         # rspCapability [8]: bits 0, 3
    tlv('a9', tlv('04', SKI_V2)) +              # euiccCiPKIdListForVerification [9]
    tlv('aa', tlv('04', SKI_V2)) +              # euiccCiPKIdListForSigning [10]
    tlv('04', '010000') +                       # ppVersion
    tlv('0c', '') +                             # sasAcreditationNumber
    tlv('8d', '0640') +                         # treProperties [13]: isIntegrated
    tlv('8e', '544553542d545245') +             # treProductReference [14]
    tlv('af', tlv('04', '020300')) +            # additionalProfilePackageVersions [15]
    tlv('90', '00') +                           # lpaMode [16]: lpad
    tlv('b1', tlv('04', SKI_V3)) +              # euiccCiPKIdListForSigningV3 [17]
    tlv('92', 'cafe') +                         # additionalEuiccInfo [18]
    tlv('93', '030100') +                       # highestSvn [19]
    tlv('b4', ''))                              # iotSpecificInfo [20]


class TestEuiccInfoV3Members(unittest.TestCase):
    """EUICCInfo1/2 are read before the SGP.22 version of the eUICC is known, so the
    v2 module has to decode the v3 members instead of dropping them."""

    def test_euicc_info1_v3_members(self):
        dec = rsp.asn1.decode('EUICCInfo1', h2b(EUICC_INFO1_V3))
        self.assertEqual(dec['svn'], h2b('030100'))
        self.assertEqual(dec['euiccCiPKIdListForSigningV3'], [h2b(SKI_V3)])
        self.assertEqual(dec['euiccRspCapability'], (h2b('900020'), 19))
        self.assertEqual(dec['highestSvn'], h2b('030100'))
        self.assertEqual(rsp.asn1.encode('EUICCInfo1', dec), h2b(EUICC_INFO1_V3))

    def test_euicc_info1_v2_encoding_unchanged(self):
        dec = rsp.asn1.decode('EUICCInfo1', h2b(EUICC_INFO1_V2))
        self.assertEqual(set(dec.keys()),
                         {'svn', 'euiccCiPKIdListForVerification', 'euiccCiPKIdListForSigning'})
        self.assertEqual(rsp.asn1.encode('EUICCInfo1', dec), h2b(EUICC_INFO1_V2))

    def test_euicc_info2_v3_members(self):
        dec = rsp.asn1.decode('EUICCInfo2', h2b(EUICC_INFO2_V3))
        self.assertEqual(dec['treProperties'], (h2b('40'), 2))
        self.assertEqual(dec['treProductReference'], 'TEST-TRE')
        self.assertEqual(dec['additionalProfilePackageVersions'], [h2b('020300')])
        self.assertEqual(dec['lpaMode'], 0)    # lpad
        self.assertEqual(dec['euiccCiPKIdListForSigningV3'], [h2b(SKI_V3)])
        self.assertEqual(dec['additionalEuiccInfo'], h2b('cafe'))
        self.assertEqual(dec['highestSvn'], h2b('030100'))
        self.assertEqual(dec['iotSpecificInfo'], {})
        self.assertEqual(rsp.asn1.encode('EUICCInfo2', dec), h2b(EUICC_INFO2_V3))


if __name__ == "__main__":
    unittest.main()
