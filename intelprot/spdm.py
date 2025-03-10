#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    :platform: Linux, Windows
    :synopsis: spdm module is for all functions related to SPDM message operations for attestation

    This module is used for CPLD device attestation validation.

    Author: scott.huang@intel.com

"""
import struct, secrets, hashlib
from array import array
import ecdsa
from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der
import fileinput
import logging
logger = logging.getLogger(__name__)

dict_spdm_req_1p0 = { \
    'GET_DIGESTS'           : 0x81,
    'GET_CERTIFICATE'       : 0x82,
    'CHALLENGE'             : 0x83,
    'GET_VERSION'           : 0x84,
    'GET_MEASUREMENTS'      : 0xE0,
    'GET_CAPABILITIES'      : 0xE1,
    'NEGOTIATE_ALGORITHMS'  : 0xE3,
    'VENDOR_DEFINED_REQUEST': 0xFE,
    'RESPOND_IF_READY'      : 0xFF}

#define message for spdm responder
dict_spdm_res_1p0 = { \
    'DIGESTS'                : 0x01,
    'CERTIFICATE'            : 0x02,
    'CHALLENGE_AUTH'         : 0x03,
    'VERSION'                : 0x04,
    'MEASUREMENTS'           : 0x60,
    'CAPABILITIES'           : 0x61,
    'ALGORITHMS'             : 0x63,
    'VENDOR_DEFINED_RESPONSE': 0x7E,
    'ERROR'                  : 0x7F}

dict_spdm_1p0 = {**dict_spdm_req_1p0, **dict_spdm_res_1p0}

def get_codestr(spdm_code):
    for k in dict_spdm_1p0:
        if dict_spdm_1p0[k] == spdm_code:
            return k

OpenSPDM_Start_Cmd     = [0x00, 0x00, 0xde, 0xad]
OpenSPDM_Stop_Cmd      = [0x00, 0x00, 0xff, 0xfe]
OpenSPDM_Transmit_Cmd  = [0x00, 0x00, 0x00, 0x01]
OpenSPDM_Transmit_Type = [0x00, 0x00, 0x00, 0x01]
Client_Hello = b'Client Hello!\x00'
Server_Hello = b'Server Hello!\x00'

dict_Get_Version = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1}}
dict_Get_Version_fmt = '<BBBB'

dict_Version = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'Rsvd'         : {'size': 1},
    'VerNumEntCnt' : {'size': 1},
    'VerNumEnt1_n' : {'size': 2}
}
dict_Version_fmt = '<BBBBBBH'

dict_Get_Capabilities = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1}
}
dict_Get_Capabilities_fmt = '<BBBB'


dict_Capabilities = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'Rsvd'         : {'size': 1},
    'CTExponent'   : {'size': 1},
    'Rsvd2'        : {'size': 2},
    'Flags'        : {'size': 4}
}
dict_Capabilities_fmt = '<BBBBBBHI'

dict_Get_Digests = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1}
}
dict_Get_Digests_fmt = '<BBBB'

dict_Digests = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'Digest0'      : {'size': 48},
    'Digest1'      : {'size': 48},
    'Digest2'      : {'size': 48}
}
dict_Digests_fmt = '<BBBB48s'

def dec_Digests(input_data):
    """
    decode Digests Message
    """
    dict_Digests['SPDMVersion']['value'] = input_data[0]
    dict_Digests['ReqResCode']['value']  = input_data[1]
    dict_Digests['Param1']['value']      = input_data[2]
    dict_Digests['Param2']['value']      = input_data[3]
    for i in range(0, 3):
        dict_Digests['Digest{}'.format(i)]['value'] = ''
    print("digest number:", int((len(input_data)-4)/48))
    for i in range(0, int((len(input_data)-4)/48)):
        dict_Digests['Digest{}'.format(i)]['value']  = int.from_bytes(input_data[4+48*i:4+48*(i+1)], 'little')
    show_dict(dict_Digests)

dict_Get_Certificate = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'Offset'       : {'size': 2},
    'Length'       : {'size': 2}
}
dict_Get_Certificate_fmt = '<BBBBHH'

dict_Certificate = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'PortionLen'   : {'size': 2},
    'RemainderLen' : {'size': 2},
    'CertChain'    : {'size': 0},
}
dict_Certificate_fmt = '<BBBBHH'

def show_dict(dict, perline=48):
    """ display dictionary variable with selected bytes per line

    :param dict: dictionary variable to display or list in log
    :param perline: items per line, optional, default is 48

    """
    for k in dict:
        val = dict[k]['value']
        if k == 'ReqResCode':
            logger.info('{:15s} : 0x{:02x} -- {}'.format(k, val, get_codestr(val)))
        elif isinstance(val, int):
            logger.info('{:15s} : 0x{:x}'.format(k, val))
        elif isinstance(val, (bytes, bytearray)):
            if len(val) <= 32:
                logger.info('{:15s} : {}'.format(k, val.hex()))
            else:
                logger.info('{:15s} : {}'.format(k, val[0:perline].hex()))
                for i in range(perline, len(val), perline):
                    logger.info('{:15s} : {}'.format(' ', val[i:i+perline].hex()))


def dec_Certificate(input_data):
    """ decode and show dict_Certificate message """
    dict_Certificate['SPDMVersion']['value'] = input_data[0]
    dict_Certificate['ReqResCode']['value']  = input_data[1]
    dict_Certificate['Param1']['value']      = input_data[2]
    dict_Certificate['Param2']['value']      = input_data[3]
    dict_Certificate['PortionLen']['value']  = int.from_bytes(input_data[4:6], 'little')
    dict_Certificate['RemainderLen']['value']= int.from_bytes(input_data[6:8], 'little')
    dict_Certificate['CertChain']['size']  = dict_Certificate['PortionLen']['value']
    dict_Certificate['CertChain']['value'] = input_data[struct.calcsize(dict_Certificate_fmt):]
    show_dict(dict_Certificate)


def dec_spdm_message(input_data, dict, fmt):
    """ decode SPDM message

    :param input_data: input data
    :param dict: dictionary variable representing of the message
    :param fmt: format if log or display

    """
    lst = struct.unpack(fmt, input_data[0:struct.calcsize(fmt)])
    i = 0
    for k in dict:
        dict[k]['value'] = lst[i]
        i += 1
    show_dict(dict)


dict_NegotiateAlgo = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'Length'       : {'size': 2},
    'MeasSpec'     : {'size': 1},
    'Rsvd1'        : {'size': 1},
    'BaseAsymAlgo' : {'size': 4},
    'BaseHashAlgo' : {'size': 4},
    'Rsvd2'        : {'size': 12},
    'ExtAsymCount' : {'size': 1},
    'ExtHashCount' : {'size': 1},
    'Rsvd3'        : {'size': 2}}
dict_NegotiateAlgo_fmt = '<BBBBHBBII12sBBH'
dict_BaseAsymAlgo = { \
    'TPM_ALG_RSASSA_2048'         :0x1,
    'TPM_ALG_RSAPSS_2048'         :0x2,
    'TPM_ALG_RSASSA_3072'         :0x4,
    'TPM_ALG_RSAPSS_3072'         :0x8,
    'TPM_ALG_ECDSA_ECC_NIST_P256' :0x10,
    'TPM_ALG_RSASSA_4096'         :0x20,
    'TPM_ALG_RSAPSS_4096'         :0x40,
    'TPM_ALG_ECDSA_ECC_NIST_P384' :0x80,
    'TPM_ALG_ECDSA_ECC_NIST_P521' :0x100}
dict_BaseHashAlgo = { \
    'TPM_ALG_SHA_256' :0x01,
    'TPM_ALG_SHA_384' :0x02,
    'TPM_ALG_SHA_512' :0x04,
    'TPM_ALG_SHA3_256':0x08,
    'TPM_ALG_SHA3_384':0x10,
    'TPM_ALG_SHA3_512':0x20}
dict_MeasHashAlgo = { \
    'Raw Bit Stream Only' :0x01,
    'TPM_ALG_SHA_256'     :0x02,
    'TPM_ALG_SHA_384'     :0x04,
    'TPM_ALG_SHA_512'     :0x08,
    'TPM_ALG_SHA3_256'    :0x10,
    'TPM_ALG_SHA3_384'    :0x20,
    'TPM_ALG_SHA3_512'    :0x40}

def map_dict_val(dict, val):
    lst = ''
    for k in dict:
        if dict[k] & val == dict[k]:
            if lst == '': lst=lst+k
            else: lst = lst+' | '+k
    return lst

dict_Algorithm = {
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'Length'       : {'size': 2},
    'MeasSpec'     : {'size': 1},
    'Rsvd1'        : {'size': 1},
    'MeasHashAlgo' : {'size': 4},
    'BaseAsymSel'  : {'size': 4},
    'BaseHashSel'  : {'size': 4},
    'Rsvd2'        : {'size': 12},
    'ExtAsymCount' : {'size': 1},
    'ExtHashSelCnt': {'size': 1},
    'Rsvd3'        : {'size': 2}}
dict_Algorithm_fmt = '<BBBBHBBIII12sBBH'

def dec_Neogotiate_Algo(input_data):
    """ decode NEGOTIAGE_ALGORITH message """
    fmt = dict_NegotiateAlgo_fmt
    lst = struct.unpack(fmt, input_data[0:struct.calcsize(fmt)])
    i = 0
    for k in dict_NegotiateAlgo:
        dict_NegotiateAlgo[k]['value'] = lst[i]
        i += 1

    #show_dict(dict_NegotiateAlgo)
    for k in dict_NegotiateAlgo:
        val = dict_NegotiateAlgo[k]['value']
        if k == 'BaseAsymAlgo':
            #print(val)
            lst = map_dict_val(dict_BaseAsymAlgo, val)
            logger.info('{:15s} : 0x{:08x} -- {}'.format(k, val, lst))
        elif k == 'BaseHashAlgo':
            #print(val)
            lst = map_dict_val(dict_BaseHashAlgo, val)
            logger.info('{:15s} : 0x{:08x} -- {}'.format(k, val, lst))
        elif k == 'ReqResCode':
            logger.info('{:15s} : 0x{:02x} -- {}'.format(k, val, get_codestr(val)))
        elif isinstance(val, int): logger.info('{:15s} : 0x{:x}'.format(k, val))
        else: logger.info('{:15s} : {}'.format(k, val.hex()))

def dec_Algorithm(input_data):
    """ decode ALGORITHM message """
    fmt = dict_Algorithm_fmt
    lst = struct.unpack(fmt, input_data[0:struct.calcsize(fmt)])
    i = 0
    for k in dict_Algorithm:
        dict_Algorithm[k]['value'] = lst[i]
        i += 1
    #show_dict
    for k in dict_Algorithm:
        val = dict_Algorithm[k]['value']
        if k == 'MeasHashAlgo':
            #print(val) MeasHashAlgo
            lst = map_dict_val(dict_MeasHashAlgo, val)
            logger.info('{:15s} : 0x{:08x} -- {}'.format(k, val, lst))
        elif k == 'BaseAsymSel':
            #print(val)
            lst = map_dict_val(dict_BaseAsymAlgo, val)
            logger.info('{:15s} : 0x{:08x} -- {}'.format(k, val, lst))
        elif k == 'ReqResCode':
            logger.info('{:15s} : 0x{:02x} -- {}'.format(k, val, get_codestr(val)))
        elif isinstance(val, int): logger.info('{:15s} : 0x{:x}'.format(k, val))
        else: logger.info('{:15s} : {}'.format(k, val.hex()))

# end of NEGOTIATE_ALGORITHM, ALGORITHM
dict_Challenge = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'nonce'        : {'size': 32}}
dict_Challenge_fmt = '<BBBB32s'

dict_Challenge_Auth = {
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'CertChainHash': {'size': 48},
    'nonce'        : {'size': 32},
    'MeasSumHash'  : {'size': 48},
    'OpaqueLen'    : {'size': 2},
    'Signature'    : {'size': 96}
}
dict_Challenge_Auth_fmt = '<BBBB48s32s48sH96s'

dict_Get_Measurements = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'nonce'        : {'size': 32}}
dict_Get_Measurements_fmt = '<BBBB32s'

dict_Measurements = { \
    'SPDMVersion'  : {'size': 1},
    'ReqResCode'   : {'size': 1},
    'Param1'       : {'size': 1},
    'Param2'       : {'size': 1},
    'NumOfBlocks'  : {'size': 1},
    'MeasRecordLen': {'size': 3},
    'MeasRecord'   : {'size': 0},
    'Nonce'        : {'size': 32},
    'OpaqueLen'    : {'size': 2},
    'OpaqueData'   : {'size': 0},
    'Signature'    : {'size': 96}}

def dec_Get_Measurements(input_data):
    dict_Get_Measurements['SPDMVersion']['value']=input_data[0]
    dict_Get_Measurements['ReqResCode']['value']=input_data[1]
    dict_Get_Measurements['Param1']['value']=input_data[2]
    dict_Get_Measurements['Param2']['value']=input_data[3]
    dict_Get_Measurements['nonce']['value'] = None
    if len(input_data) == 36:
        dict_Get_Measurements['nonce']['value'] = input_data[4:]
    show_dict(dict_Get_Measurements)


def dec_Measurements(input_data):
    dict_Measurements['SPDMVersion']['value'] = input_data[0]
    dict_Measurements['ReqResCode']['value']  = input_data[1]
    dict_Measurements['Param1']['value']      = input_data[2]
    dict_Measurements['Param2']['value']      = input_data[3]
    dict_Measurements['NumOfBlocks']['value'] = input_data[4]
    MeasRecordLen = int.from_bytes(input_data[5:8], 'little')
    dict_Measurements['MeasRecordLen']['value']= MeasRecordLen
    dict_Measurements['MeasRecord']['size']    = MeasRecordLen
    dict_Measurements['MeasRecord']['value']   = input_data[8:8+MeasRecordLen]
    dict_Measurements['Nonce']['value']        = input_data[8+MeasRecordLen:40+MeasRecordLen]
    OpaqueLen = int.from_bytes(input_data[40+MeasRecordLen:42+MeasRecordLen], 'little')
    dict_Measurements['OpaqueLen']['value']    = OpaqueLen
    dict_Measurements['OpaqueData']['size']    = OpaqueLen
    if OpaqueLen == 0x0:
        dict_Measurements['OpaqueData']['value'] = b''
    else:
        dict_Measurements['OpaqueData']['value'] = input_data[42+MeasRecordLen:42+MeasRecordLen+OpaqueLen]
    dict_Measurements['Signature']['value']    = input_data[42+MeasRecordLen+OpaqueLen:]
    show_dict(dict_Measurements)

def start_hello():
    lst = OpenSPDM_Start_Cmd + OpenSPDM_Transmit_Type + \
          list(struct.pack('>I', len(Client_Hello))) +\
          list(Client_Hello)
    return array('B', lst).tobytes()

def server_hello():
    lst = OpenSPDM_Start_Cmd + OpenSPDM_Transmit_Type + \
          list(struct.pack('>I', len(Server_Hello))) +\
          list(Server_Hello)
    return array('B', lst).tobytes()

def stop_msg():
    lst = OpenSPDM_Stop_Cmd + OpenSPDM_Transmit_Type + \
          [0, 0, 0, 0]
    return array('B', lst).tobytes()

def get_openspdm_data(lst_data):
    buffer_size = list(struct.pack('>I', len(lst_data)))
    lst= OpenSPDM_Transmit_Cmd + OpenSPDM_Transmit_Type+ \
         buffer_size + lst_data
    return array('B', lst).tobytes()

def msg_get_certificate(offset, length, ver=0x10, slot_num=0):
    lst_data=[0x05, 0x10, 0x82, slot_num, 0x00]+\
             list(struct.pack('<H', offset))+\
             list(struct.pack('<H', length))
    return lst_data

def msg_negotiate_algorithms(length, MeaSpec, BaseAsymAlgo, BaseHashAlgo):
    lst_data =[0x05, 0x10, 0xE3, 0x00, 0x00]+\
              list(struct.pack('<H', length))+[MeaSpec]+list(bytes(1))+\
              list(struct.pack('<I', BaseAsymAlgo))+\
              list(struct.pack('<I', BaseHashAlgo))+list(bytes(16))
    return lst_data

def msg_challenge(param1, param2):
    lst_data = [0x05, 0x10, 0x83, param1, param2] + list(secrets.token_bytes(32))
    return lst_data

def msg_get_mesurement(param1, param2, add_nonce=False):
    lst_data = [0x05, 0x10, 0xE0, param1, param2]
    if add_nonce:
        lst_data = [0x05, 0x10, 0xE0, param1, param2]+list(secrets.token_bytes(32))
    return lst_data

def get_lst_data(msg, param1=0, param2=0):
    msgcode = dict_spdm_req_1p0[msg]
    return [0x05, 0x10, msgcode, param1, param2]


class egs_spdm(object):
    """ class for egs_spdm

    :param input_data: input data

    """
    def __init__(self, input_data):
        self._data= input_data  # input data
        self._messageCode = None

    def decode_message(self):
        reqRescode = self._data[1]
        for k in dict_spdm_1p0:
            if dict_spdm_1p0[k] == reqRescode:
                self._messageCode = k

        k = self._messageCode
        if k == 'GET_VERSION':
            dec_spdm_message(self._data, dict_Get_Version, dict_Get_Version_fmt)
        if k == 'VERSION':
            dec_spdm_message(self._data, dict_Version, dict_Version_fmt)
        if k == 'GET_CAPABILITIES':
            dec_spdm_message(self._data, dict_Get_Capabilities, dict_Get_Capabilities_fmt)
        if k == 'CAPABILITIES':
            dec_spdm_message(self._data, dict_Capabilities, dict_Capabilities_fmt)
        if k == 'GET_DIGESTS':
            dec_spdm_message(self._data, dict_Get_Digests, dict_Get_Digests_fmt)
        if k == 'DIGESTS':
            dec_Digests(self._data)
        if k == 'NEGOTIATE_ALGORITHMS':
            dec_Neogotiate_Algo(self._data)
        if k == 'ALGORITHMS':
            dec_Algorithm(self._data)
        if k == 'GET_CERTIFICATE':
            dec_spdm_message(self._data, dict_Get_Certificate, dict_Get_Certificate_fmt)
        if k == 'CERTIFICATE':
            dec_Certificate(self._data)
            #dec_spdm_message(self._data, dict_Certificate, dict_Certificate_fmt)
        if k == 'CHALLENGE':
            dec_spdm_message(self._data, dict_Challenge, dict_Challenge_fmt)
        if k == 'CHALLENGE_AUTH':
            #dec_spdm_message(self._data, dict_Challenge_Auth, dict_Challenge_Auth_fmt)
            logger.info("-- CHALLENGE_AUTH Data: {}".format(self._data))
        if k == 'GET_MEASUREMENTS':
            #dec_spdm_message(self._data, dict_Get_Measurements, dict_Get_Measurements_fmt)
            dec_Get_Measurements(self._data)
        if k == 'MEASUREMENTS':
            dec_Measurements(self._data)


class SPDM_REQUESTER(object):
    """
      class for SPDM requester operation

    :param dict_spdm_msg: dictionary of SPDM message

    """
    def __init__(self, dict_spdm_msg):
        """ constructor
        """
        self.dict_spdm_msg = dict_spdm_msg
        self.calc()
        self.res_pubkey = None

    def set_responder_pubkey(self, res_pubkey_pem):
        """ set responder public key

        :param res_pubkey_pem: responder public key in PEM format

        """
        self.res_pubkey = res_pubkey_pem

    def calc(self):
        """ do calculation of the message
        """
        self.A = self.dict_spdm_msg['0x84'][0] + self.dict_spdm_msg['0x04'][0] + \
                 self.dict_spdm_msg['0xE1'][0] + self.dict_spdm_msg['0x61'][0] + \
                 self.dict_spdm_msg['0xE3'][0] + self.dict_spdm_msg['0x63'][0]

        self.B =b''
        for (getd, d) in zip(self.dict_spdm_msg['0x81'], self.dict_spdm_msg['0x01']):
            #print('getd={}, d={}'.format(getd, d))
            self.B += getd + d
        for (getc, c) in zip(self.dict_spdm_msg['0x82'], self.dict_spdm_msg['0x02']):
            #print('getc={}, c={}'.format(getc, c))
            self.B += getc + c

        self.C = self.dict_spdm_msg['0x83'][0] + self.dict_spdm_msg['0x03'][0][:-96]

        self.M2 = self.A + self.B + self.C
        self.m2hash_hex = hashlib.sha384(self.M2).hexdigest()
        self.M2Hash = bytearray.fromhex(self.m2hash_hex)

        self.L2 = b''  # concatenate all GET_M/M spdm bytes
        for (getm, m) in zip(self.dict_spdm_msg['0xE0'], self.dict_spdm_msg['0x60']):
            self.L2 += getm + m
        # exclude signature bytes in last measurement
        self.L2 = self.L2[:-96]
        self.L2hash_hex = hashlib.sha384(self.L2).hexdigest()
        self.L2Hash = bytearray.fromhex(self.L2hash_hex)

    def verify_M2(self):
        """ verify CHALLENGE_AUTH using responder public key

         Before run verification function, please use set_responder_pubkey()
         method to set the responder public key.

        """
        logger.info('-- Verify M2hash')
        logger.info('M2 hash: {}'.format(self.m2hash_hex))
        self.VK = self.res_pubkey  #r'C:\shuang4\Work\openspdm-master\Build\DEBUG_VS2019\X64\EcP384\end_res_public_key.pem'
        bdata = self.dict_spdm_msg['0x03'][0]
        l= len(bdata)
        self.signature_R = bdata[l-96:l-48]
        self.signature_S = bdata[l-48:l]
        logger.info('-- signature: R: {}, S: {}'.format(self.signature_R.hex(), self.signature_S.hex()))
        R, S = self.signature_R, self.signature_S
        with open(self.VK) as f:
            vk = VerifyingKey.from_pem(f.read())
        r, s = int.from_bytes(R, byteorder='big'), int.from_bytes(S, byteorder='big')
        order = ecdsa.NIST384p.generator.order()
        signature = sigencode_der(r, s, order)

        try:
            assert vk.verify(signature, self.M2, hashlib.sha384, sigdecode=sigdecode_der)
        except:
            logger.info('-- Verification M2 Failed')
            raise
            return False
        logger.info('-- Verification M2 PASS !')
        return True

    def verify_L2(self):
        """ verify MESSAGES.SIGNATURE
        """
        logger.info('-- Verify L2')
        logger.info('L2 hash: {}'.format(self.L2hash_hex))
        self.VK = self.res_pubkey  #r'C:\shuang4\Work\openspdm-master\Build\DEBUG_VS2019\X64\EcP384\end_res_public_key.pem'
        bdata = self.dict_spdm_msg['0x60'][-1]  # get the last MEASUREMENT message
        l= len(bdata)
        self.m_sig_R = bdata[l-96:l-48]
        self.m_sig_S = bdata[l-48:l]
        logger.info('-- Measurement Signature: \n R: {} \n S: {}'.format(self.m_sig_R.hex(), self.m_sig_S.hex()))
        R, S = self.m_sig_R, self.m_sig_S
        with open(self.VK) as f:
            vk = VerifyingKey.from_pem(f.read())
        r, s = int.from_bytes(R, byteorder='big'), int.from_bytes(S, byteorder='big')
        order = ecdsa.NIST384p.generator.order()
        signature = sigencode_der(r, s, order)
        try:
            assert vk.verify(signature, self.L2, hashlib.sha384, sigdecode=sigdecode_der)
        except:
            logger.info('-- Verification L2 Failed :(')
            raise
            return False
        logger.info('-- Verification L2 PASS !:)')
        return True


    def show(self):
        """ display requester spdm message

        """
        logger.info('-- show spdm requester message:')
        logger.info("--A: {}".format(self.A.hex()))
        logger.info("--B: {}".format(self.B.hex()))
        logger.info("--C: {}".format(self.C.hex()))
        logger.info("--M2:{}".format(self.M2.hex()))
        logger.info('M2 hash: {}'.format(self.m2hash_hex))
        logger.info("--L2:{}".format(self.L2.hex()))
        logger.info('L2 hash: {}'.format(self.L2hash_hex))

        for k in self.dict_spdm_msg:
            logger.info('{}-{:25s} : {}'.format(k, get_codestr(int(k, 16)), self.dict_spdm_msg[k]))


class SPDM_RESPONDER(object):
    """ Class for SPDM responder operation

    :param dict_spdm_msg: dictionary of SPDM message

    """
    def __init__(self, dict_spdm_msg):
        """ constructor """
        self.dict_spdm_msg = dict_spdm_msg
        self.calc()

    def calc(self):
        """ do calculation """
        self.A = self.dict_spdm_msg['0x84'] + self.dict_spdm_msg['0x04'] + \
                 self.dict_spdm_msg['0xE1'] + self.dict_spdm_msg['0x61'] + \
                 self.dict_spdm_msg['0xE3'] + self.dict_spdm_msg['0x63']
        self.B = self.dict_spdm_msg['0x81'] + self.dict_spdm_msg['0x01'] + \
                 self.dict_spdm_msg['0x82'] + self.dict_spdm_msg['0x02']
        self.C = self.dict_spdm_msg['0x83'] + self.dict_spdm_msg['0x03'][:-96]
        self.M1 = self.A + self.B + self.C
        self.m1hash_hex = hashlib.sha384(self.M1).hexdigest()
        self.M1Hash = bytearray.fromhex(self.m1hash_hex)
        self.L1 = self.dict_spdm_msg['0xE0'] + self.dict_spdm_msg['0x60']


    def show(self):
        """ show responder spdm message """
        logger.info('-- show spdm responder message:')
        logger.info("--A: {}".format(self.A.hex()))
        logger.info("--B: {}".format(self.B.hex()))
        logger.info("--C: {}".format(self.C.hex()))
        logger.info("--M1:{}".format(self.M1.hex()))
        logger.info('M1 hash: {}'.format(self.m1hash_hex))

        for k in self.dict_spdm_msg:
            logger.info('{}-{:25s} : {}'.format(k, get_codestr(int(k, 16)), self.dict_spdm_msg[k]))

