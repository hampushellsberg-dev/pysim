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
import asn1tools
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


TID = h2b('0102030405060708')
SIG = h2b('00' * 64)
ICCID = h2b('98880221436587092143')
NOTIF_METADATA = {'seqNumber': 1, 'profileManagementOperation': (h2b('40'), 2),
                  'notificationAddress': 'smdp.example.com', 'iccid': ICCID}

# The BF-tagged types SGP.22 v3.1 added: ES10 (sections 5.7.3, 5.7.23-5.7.29), ES9+ (5.6.6,
# 5.6.7), ES11 (5.8.3) and DeleteNotificationForDc of AuthenticateClientRequest (5.6.3)
TYPES_V3 = [
    ('EuiccConfiguredDataRequest', 'bf3c', {}),
    ('EuiccConfiguredDataResponse', 'bf3c', {
        'defaultDpAddress': 'smdp.example.com', 'rootDsAddress': 'smds.example.com',
        'allowedCiPKId': h2b(SKI_V3), 'ciList': [{'ciPKId': h2b(SKI_V3), 'ciName': 'Test CI'}]}),
    ('LoadRpmPackageRequest', 'bf44', {
        'smdpSigned3': {'transactionId': TID,
                        'rpmPackage': [{'rpmCommandDetails': ('enable', {'iccid': ICCID})}]},
        'smdpSignature3': SIG, 'targetEsimPort': 1}),
    ('LoadRpmPackageResult', 'bf44', ('loadRpmPackageResultNotSigned', {
        'transactionId': TID, 'loadRpmPackageErrorCodeNotSigned': 4})),
    ('VerifySmdsResponseRequest', 'bf45', {
        'smdsSigned2': {'transactionId': TID, 'requestSpecificData': ('pushServiceRegistrationResult', {})},
        'smdsSignature2': SIG}),
    ('VerifySmdsResponseResponse', 'bf45', ('verifySmdsResponseOk', None)),
    ('CheckEventRequest', 'bf46', {'ecId': bytes(range(16)), 'smdsAddress': 'smds.example.com'}),
    ('CheckEventResponse', 'bf46', ('checkEventOk', {'isPendingEvent': True})),
    ('AlertData', 'bf4a', ('pendingOperationAlert', ('defaultSmdp', None))),
    ('VerifyDeviceChangeRequest', 'bf4b', {
        'smdpSigned5': {'transactionId': TID, 'deviceChangeResponse': ('deviceChangeData', {
            'iccid': ICCID, 'activationCodeForDc': '1$smdp.example.com$ABC'})},
        'smdpSignature5': SIG}),
    ('VerifyDeviceChangeResponse', 'bf4b', ('verifyDeviceChangeError', 8)),
    ('ConfirmDeviceChangeRequest', 'bf4c', {
        'transactionId': TID, 'prepareDeviceChangeResponse': ('prepareDeviceChangeResponseError', {
            'transactionId': TID, 'downloadErrorCode': 127})}),
    ('ConfirmDeviceChangeResponse', 'bf4c', ('confirmDeviceChangeError', 3)),
    ('PrepareDeviceChangeRequest', 'bf4d', {
        'smdpSigned4': {'transactionId': TID, 'ccRequiredFlag': False}, 'smdpSignature4': SIG}),
    ('PrepareDeviceChangeResponse', 'bf4d', ('prepareDeviceChangeResponseError', {
        'transactionId': TID, 'downloadErrorCode': 127})),
    ('VerifySmdpResponseRequest', 'bf60', {
        'smdpSigned6': {'transactionId': TID, 'requestSpecificData': ('retryData', {
            'retryDelay': 5, 'dcSessionId': h2b('01')})},
        'smdpSignature6': SIG}),
    ('VerifySmdpResponseResponse', 'bf60', ('verifySmdpResponseOk', None)),
    ('CheckProgressRequest', 'bf61', {'dcSessionId': h2b('0102')}),
    ('CheckProgressResponse', 'bf61', ('checkProgressOk', {'retryDelay': 10})),
    ('VerifyProfileRecoveryRequest', 'bf62', {
        'smdpSigned4': {'transactionId': TID, 'ccRequiredFlag': True,
                        'activationCodeForProfileRecovery': '1$smdp.example.com$XYZ'},
        'smdpSignature4': SIG}),
    ('VerifyProfileRecoveryResponse', 'bf62', ('verifyProfileRecoveryOk', None)),
    ('DeleteNotificationForDc', 'bf63', {
        'notificationMetadata': NOTIF_METADATA, 'euiccNotificationSignature': SIG}),
]


class TestRspV3Module(unittest.TestCase):
    """The SGP.22 v3.1 module next to the v2 one."""

    def test_compiled_once(self):
        self.assertIs(rsp.asn1_v3(), rsp.asn1_v3())

    def test_bf_tagged_v3_types(self):
        for type_name, tag, value in TYPES_V3:
            with self.subTest(type_name):
                self.assertNotIn(type_name, rsp.asn1.types)
                enc = rsp.asn1_v3().encode(type_name, value)
                self.assertEqual(enc[:2], h2b(tag))
                self.assertEqual(rsp.asn1_v3().decode(type_name, enc), value)

    def test_v3_member_names(self):
        dec_v2 = rsp.asn1.decode('EUICCInfo1', h2b(EUICC_INFO1_V3))
        dec_v3 = rsp.asn1_v3().decode('EUICCInfo1', h2b(EUICC_INFO1_V3))
        self.assertEqual(dec_v2['svn'], dec_v3['lowestSvn'])
        self.assertEqual(dec_v3['highestSvn'], h2b('030100'))
        self.assertEqual(rsp.asn1_v3().encode('EUICCInfo1', dec_v3), h2b(EUICC_INFO1_V3))

    def test_device_capabilities_tag_88_differs(self):
        # same bytes, different member: the reason v3.1 is not merged into the v2 module
        enc = h2b('30058803020000')
        self.assertEqual(rsp.asn1.decode('DeviceCapabilities', enc),
                         {'rspRpmSupportedVersion': h2b('020000')})
        self.assertEqual(rsp.asn1_v3().decode('DeviceCapabilities', enc),
                         {'nrEpcSupportedRelease': h2b('020000')})

    def test_smdp_oid_mandatory_in_v3(self):
        pir = {'transactionId': TID, 'notificationMetadata': NOTIF_METADATA,
               'finalResult': ('errorResult', {'bppCommandId': 1, 'errorReason': 1})}
        enc = rsp.asn1.encode('ProfileInstallationResultData', pir)
        self.assertEqual(rsp.asn1.decode('ProfileInstallationResultData', enc)['transactionId'], TID)
        with self.assertRaises(asn1tools.DecodeError):
            rsp.asn1_v3().decode('ProfileInstallationResultData', enc)
        pir['smdpOid'] = '1.2.3.4'
        enc = rsp.asn1.encode('ProfileInstallationResultData', pir)
        self.assertEqual(rsp.asn1_v3().decode('ProfileInstallationResultData', enc)['smdpOid'],
                         '1.2.3.4')

    def test_unchanged_encodings_match(self):
        server_signed1 = {'transactionId': TID, 'euiccChallenge': bytes(16),
                          'serverAddress': 'smdp.example.com', 'serverChallenge': bytes(range(16))}
        ctx = {'matchingId': 'ABC', 'deviceInfo': {'tac': h2b('35230145'), 'deviceCapabilities': {}}}
        for type_name, value in (('ServerSigned1', server_signed1),
                                 ('CtxParamsForCommonAuthentication', ctx)):
            with self.subTest(type_name):
                self.assertEqual(rsp.asn1.encode(type_name, value), rsp.asn1_v3().encode(type_name, value))
        # operationType [2] DEFAULT {profileDownload}: absent on the wire, filled in on decode
        dec = rsp.asn1_v3().decode('CtxParamsForCommonAuthentication',
                                   rsp.asn1.encode('CtxParamsForCommonAuthentication', ctx))
        self.assertEqual(dec['operationType'], (h2b('80'), 1))


class TestOperatorIdName(unittest.TestCase):
    """SGP.22 v3.1 and the SGP.32 v1.3 module, which imports it from RSPDefinitions, spell
    the type OperatorId; the v2 module calls it OperatorID."""

    OWNER = {'mccMnc': h2b('00f110'), 'gid1': h2b('01')}

    def test_alias_encodes_like_operator_id(self):
        enc = rsp.asn1.encode('OperatorId', self.OWNER)
        self.assertEqual(enc, rsp.asn1.encode('OperatorID', self.OWNER))
        self.assertEqual(rsp.asn1.decode('OperatorId', enc), self.OWNER)

    def test_importable_under_the_v3_name(self):
        from importlib import resources
        rsp_dir = resources.files('pySim.esim').joinpath('asn1').joinpath('rsp')
        rsp_txt = '\n'.join(i.read_text() for i in rsp_dir.iterdir() if i.name.endswith('.asn'))
        importer = """Importer DEFINITIONS AUTOMATIC TAGS ::= BEGIN
IMPORTS OperatorId FROM RSPDefinitions {joint-iso-itu-t(2) international-organizations(23) gsma(146) rsp(1) asn1modules(1) sgp22v2(2)};
Owner ::= SEQUENCE { profileOwner [23] OperatorId }
END
"""
        spec = asn1tools.compile_string(rsp_txt + '\n' + importer, codec='der')
        enc = spec.encode('Owner', {'profileOwner': self.OWNER})
        self.assertEqual(enc[2:], h2b('b7') + rsp.asn1.encode('OperatorID', self.OWNER)[1:])


if __name__ == "__main__":
    unittest.main()
