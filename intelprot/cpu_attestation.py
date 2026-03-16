#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    :platform: Unix, Windows
    :synopsis: Parse PFR PFM, display and customize PFM.

    This module is for CPU attestation in BHS and OKS platform
    It supports SPDM protocol verification for Customized PRoT implementation of Xeon 6 and 7 CPU attestation

    Author: scott.huang@intel.com

    SO far, it includes SPDM 1.0 support for BHS CPU attestation, classes:

    * PARSE_SPDM_BHS
    * Cert
    * GNR_Certificate_Chain
    * BHS_CPU_Attestation

    Command line
    *****************************

    help-menu::

        >python -m intelprot.cpu_attestation -h
        >python -m intelprot.cpu_attestation -p {platform} -i {input_file} -v -l {log_file}


    input_file::

        SPDM data binary file or hex string SPDM data separated with blank spaces or line breaks

"""
from __future__ import print_function
from __future__ import division

__author__ = "Scott Huang (scott.huang@intel.com)"

import struct, hashlib, struct, os, sys, string, re, shutil
import pathlib
import argparse
import pathlib, subprocess
from collections import OrderedDict
import datetime

import pathlib, subprocess
import ecdsa
from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der
from binaryornot.check import is_binary
from intelprot import utility 

import logging
logger = logging.getLogger(__name__)

# BHS CPU attestation SPDM code
dict_bhs_spdm_code = { \
    '0x84':'GET_VERSION',
    '0x04':'VERSION',
    '0xE1':'GET_CAPABILITIES',
    '0x61':'CAPABILITIES',
    '0xE3':'NEGOTIATE_ALGORITHMS',
    '0x63':'ALGORITHMS',
    '0x81':'GET_DIGESTS',
    '0x01':'DIGESTS',
    '0x82':'GET_CERTIFICATE',
    '0x02':'CERTIFICATE',
    '0x83':'CHALLENGE',
    '0x03':'CHALLENGE_AUTH',
    '0xE0':'GET_MEASUREMENTS',
    '0x60':'MEASUREMENTS',
}

class ConfigDict(OrderedDict):
    """ define an ordered dictionary """
    def __missing__(self, key):
        val = self[key] = ConfigDict()
        return val


def delete_subfolders_by_name(parent_folder, folder_name_to_delete):
    """
    Deletes all subfolders with a specific name inclusing substr within a given parent folder.

    Args:
        parent_folder (str): The path to the parent folder to search within.
        folder_name_to_delete (str): The name of the subfolders to delete.
    """
    if not os.path.isdir(parent_folder):
        print(f"Error: Parent folder '{parent_folder}' does not exist.")
        return

    for root, dirs, files in os.walk(parent_folder):
        for dir_name in dirs:
            #if dir_name == folder_name_to_delete:
            if folder_name_to_delete in dir_name:
                folder_path = os.path.join(root, dir_name)
                try:
                    shutil.rmtree(folder_path)
                    print(f"Deleted folder: {folder_path}")
                except OSError as e:
                    print(f"Error deleting folder {folder_path}: {e}")

#-------------------------
class BHS_CPU_SPDM_PARSER(object):
    """
     parse SPDM transaction data collected from BHS CPU attestation

    :param spdm_transaction_file : all spdm transaction data in a file, it is either binary file or a text file with hexstr separated with line or space

      data format: <SPDM-version, 10> <code> <data> ... all in hex string without prefix '0x'
      example: 10 84 00 00
               10 04 00 00 00 01 00 10

     Text file format: data can be separated with space, or line break. Those will be filter out in processing.
     Binary file format: *.bin file with <spdm-version><code><data...> with one spdm-requester message followed by one spdm-responder message

    :return:
    dictionary format with all message for continue processing

    """
    bhs_spdm10_code_parse_func = {
    '84':'parse_get_version', \
    '04':'parse_version', \
    'E1':'parse_get_capabilities',  \
    '61':'parse_capabilities',  \
    'E3':'parse_negotiate_algorithms', \
    '63':'parse_algorithms',  \
    '81':'parse_get_digests',  \
    '01':'parse_digests',  \
    '82':'parse_get_certificate', \
    '02':'parse_certificate', \
    '83':'parse_challenge', \
    '03':'parse_challenge_auth',  \
    'E0':'parse_get_measurements',  \
    '60':'parse_measurements'
    }

    def __init__(self, spdm_transaction_file):
        self.lst_dict_spdm = [] # define an empty list of spdm dictionary
        self.dict_spdm = ConfigDict()  # define a dictionary format
        self.spdm_file_raw = spdm_transaction_file
        self.cert_chain = bytes()
        self.lst_meas_index   = []
        self.lst_measurements = []
        if not os.path.exists(self.spdm_file_raw):
            logger.error("-- File {} does not exists, check file name and path !".format(spdm_transaction_file))
            sys.exit(1)

        if is_binary(self.spdm_file_raw):
            self.spdm_file_binary = self.spdm_file_raw
        elif self.is_hexstr_text():
            self.hex2bin_file()
        else:
            logger.error("-- Wrong data format in file {}".format(self.spdm_file_raw))
            sys.exit(1)

    def is_hexstr_text(self):
        with open(self.spdm_file_raw, 'r') as f:
            content = f.read()
        # Regular expression to match only hex characters (0-9, a-f, A-F), spaces, and line breaks
        # The pattern '^[\da-fA-F\s\n\r]*$' ensures that the entire string consists only of these characters.
        # \d matches digits (0-9), a-fA-F matches hex letters,
        # \s matches any whitespace character (including space, tab, newline, etc.)
        # \n\r specifically include newline and carriage return
        # * means zero or more occurrences
        # ^ and $ anchor the match to the beginning and end of the string
        if re.fullmatch(r'^[\da-fA-F\s\n\r]*$', content):
            return True

    def hex2bin_file(self):
        """ convert to standard binary file format for processing """
        with open(self.spdm_file_raw, 'r', encoding='utf-8') as f_in:
            content = f_in.read()
        cleaned_content = re.sub(r'\s+', '', content)
        self.spdm_file_binary = 'hex2bin_spdm_file.bin'
        with open(self.spdm_file_binary, 'wb') as f_out:
            f_out.write(bytes.fromhex(cleaned_content))

    def parse_get_version(self):
        """ process GET_VERSION
            '0x84':'GET_VERSION' \
        """
        logger.info("-- parse GET_VERSION ")
        self.dict_spdm['code']= '84'
        self.dict_spdm['data'] = self.bdata_remainder[2:4].hex()
        self.bdata_remainder = self.bdata_remainder[4:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        #print(self.lst_dict_spdm)

    def parse_version(self):
        """ process VERSION
            '0x04':'VERSION' \
        """
        logger.info("-- parse VERSION ")
        self.dict_spdm['code']= '04'
        self.dict_spdm['data'] = self.bdata_remainder[2:6+2].hex()
        self.bdata_remainder = self.bdata_remainder[(6+2):]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        #print(self.lst_dict_spdm)

    def parse_get_capabilities(self):
        """ process GET_CAPABILITIES
            '0xE1':'GET_CAPABILITIES' \
        """
        logger.info("-- parse GET_CAPABILITIES ")
        self.dict_spdm['code']= 'E1'
        self.dict_spdm['data'] = self.bdata_remainder[2:2+2].hex()
        self.bdata_remainder = self.bdata_remainder[2+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        #print(self.lst_dict_spdm)

    def parse_capabilities(self):
        """ process CAPABILITIES
            '0x61':'CAPABILITIES' \
        """
        logger.info("-- parse CAPABILITIES ")
        self.dict_spdm['code']= '61'
        self.dict_spdm['data'] = self.bdata_remainder[2:10+2].hex()
        self.bdata_remainder = self.bdata_remainder[10+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        #print(self.lst_dict_spdm)

    def parse_negotiate_algorithms(self):
        """ process negotiate_algorithms
            '0x81':'NEOGOTIATE_ALGORITHMS' \
        """
        self.dict_spdm['code']= 'E3'
        self.dict_spdm['data'] = self.bdata_remainder[2:30+2].hex()
        self.bdata_remainder = self.bdata_remainder[30+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        #print(self.lst_dict_spdm)

    def parse_algorithms(self):
        """ process algorithms
            '0x63':'ALGORITHMS' \
        """
        self.dict_spdm['code']= '63'
        self.dict_spdm['data'] = self.bdata_remainder[2:34+2].hex()
        self.bdata_remainder = self.bdata_remainder[34+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        #print(self.lst_dict_spdm)

    def parse_get_digests(self):
        """ process get digest
            '0x81':'GET_DIGEST' \
        """
        self.dict_spdm['code']= '81'
        self.dict_spdm['data'] = self.bdata_remainder[2:2+2].hex()
        self.bdata_remainder = self.bdata_remainder[2+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        #print(self.lst_dict_spdm)

    def parse_digests(self):
        """ process digest
            '0x01':'DIGESTS' \
        """
        self.dict_spdm['code']= '01'
        self.dict_spdm['data'] = self.bdata_remainder[2:50+2].hex()
        self.bdata_remainder = self.bdata_remainder[50+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        #print(self.lst_dict_spdm)

    def parse_get_certificate(self):
        """ process get certificate
        '0x82':'GET_CERTIFICATE', 'p1:p2:offset:length', '<BBHH'),
        """
        logger.info("-- processs get_certificate" )
        self.dict_spdm['code']= '82'
        lst_k = ('p1', 'p2', 'offset', 'length')
        lst_v = struct.unpack('<BBHH', self.bdata_remainder[2:6+2])
        for (k, v) in zip(lst_k, lst_v):
            self.dict_spdm[k] = v
        self.bdata_remainder = self.bdata_remainder[6+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()

    def parse_certificate(self):
        """ process certificate msg data

            '0x02':'CERTIFICATE', 'p1:p2:portion_len:remainder_len:cert_chain', '<BBHH{}'), \
        """
        logger.info("-- processs certificate" )
        self.dict_spdm['code']= '02'
        lst_k = ('p1', 'p2', 'portion_len', 'remainder_len')
        lst_v = (p1, p2, portion_len, remainder_len) = struct.unpack('<BBHH', self.bdata_remainder[2:6+2])
        for (k, v) in zip(lst_k, lst_v):
            self.dict_spdm[k] = v
        #logger.info('--portion_len = {}, remainder_len = {}'.format(portion_len, remainder_len))
        self.dict_spdm['cert_chain'] = struct.unpack('<{}s'.format(portion_len), self.bdata_remainder[6+2:(6+2+portion_len)])[0]

        self.cert_chain += self.dict_spdm['cert_chain'] # add up all certificate chain bytes

        self.bdata_remainder = self.bdata_remainder[(6+2+portion_len):]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()
        self.cert_remainder_len = remainder_len


    def parse_challenge(self):
        """ process challenge
            '0x83':'CHALLENGE', 'p1:p2:nonce', '<BB32s'), \
        """
        logger.info("-- processs parse_challenge" )
        self.dict_spdm['code']= '83'
        self.dict_spdm['data'] = self.bdata_remainder[2:34+2].hex()

        # 00 ff df3c2e86bff7feaf,6db5f97e76fff7d2,f96baf7adbe7eeeb,2fbbf757ddf7fe97
        lst_k = ('p1', 'p2', 'nonce')
        lst_v = (p1, p2, nonce) = struct.unpack('<BB32s', self.bdata_remainder[2:34+2])
        for (k, v) in zip(lst_k, lst_v):
            self.dict_spdm[k] = v

        self.bdata_remainder = self.bdata_remainder[34+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()


    def parse_challenge_auth(self):
        """ process challenge authentication
            '0x03':'CHALLENGE_AUTH', 'p1:p2:CertChainHash:Nonce:MeasSumHash:OpaqueLen:Signature', '<BB48s32sH96s'), \
        """
        self.dict_spdm['code']= '03'
        logger.info("-- processs parse_challenge_auth" )
        lst_k = ('p1', 'p2', 'cert_chain_hash', 'nonce', 'measSumhash', 'opaque_len', 'signature')
        lst_v = (p1, p2, cert_chain_hash, nonce, measSumhash, opaque_len, signature) = struct.unpack('<BB48s32s48sH96s', self.bdata_remainder[2:2+struct.calcsize('<BB48s32s48sH96s')])
        for (k, v) in zip(lst_k, lst_v):
            self.dict_spdm[k] = v
        self.bdata_remainder=self.bdata_remainder[2+struct.calcsize('<BB48s32s48sH96s'):]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.dict_spdm = ConfigDict()


    def parse_get_measurements(self):
        """ process challenge authentocation
        '0xE0':'GET_MEASUREMENTS', 'p1:p2:nonce', '<BB32s'), \
        """
        if len(self.bdata_remainder) == 0:
            logger.info('-- no more data to process get_measurements')
            return
        self.dict_spdm['code'] = 'E0'
        logger.info("-- processs get_measurement")
        lst_k = ('p1', 'p2', 'nonce')
        # 01,08, 5103c0005b65d6fd,1a8d110036b74a01,972251e010506b47,0110308a5b75dc15
        lst_v = (p1, p2, nonce) = struct.unpack('<BB32s', self.bdata_remainder[2:34+2])
        for (k, v) in zip(lst_k, lst_v):
            self.dict_spdm[k] = v
        self.dict_spdm['data'] = self.bdata_remainder[2:34+2].hex()
        self.bdata_remainder = self.bdata_remainder[34+2:]
        self.lst_dict_spdm.append(self.dict_spdm)
        self.lst_meas_index.append(self.dict_spdm['p2'])
        self.dict_spdm = ConfigDict()

    def parse_measurements(self):
        """ process challenge authentocation
          '0x60':'MEASUREMENTS', 'p1:p2:NumBlocks:MeasRecordLen:MeasRecord:Nonce:OpaqueLen:Signature', '<BBB3s{}32sH:96s')
        """
        logger.info("-- parse MEASUREMENTS ")
        if len(self.bdata_remainder) == 0:
            logger.info('-- no more data to process get_measurements')
            return
        self.dict_spdm['code']= '60'
        #print(self.bdata_remainder.hex())
        (p1, p2, num_blocks, meas_rec_len) = struct.unpack('<BBB3s', self.bdata_remainder[2:6+2])
        if (p1==0x8) and (p2==0x0) and (num_blocks==0x0) and (meas_rec_len.hex()=='000000'):
            meas_record_len = 0
            meas_record = None
            self.total_num_meas = p1
            (nonce, opaque_len, signature) = struct.unpack('<32sH96s', self.bdata_remainder[6+2:(6+2+32+2+96)])
        if (p1==0x0) and (p2==0x0) and (num_blocks==0x1):
            meas_record_len = struct.unpack('<I', meas_rec_len+b'\x00')[0]
            (meas_record, nonce, opaque_len, signature) = struct.unpack('<{}s32sH96s'.format(meas_record_len), self.bdata_remainder[6+2:(6+2+meas_record_len+32+2+96)])

        self.bdata_remainder = self.bdata_remainder[(6+2+meas_record_len+32+2+96):]
        lst_k = ['p1', 'p2', 'num_blocks', 'meas_record_len', 'meas_record', 'nouce', 'opaque_len', 'signature']
        lst_v = [p1, p2, num_blocks, meas_record_len, meas_record, nonce, opaque_len, signature]
        for (k, v) in zip(lst_k, lst_v):
            self.dict_spdm[k] = v
        self.lst_dict_spdm.append(self.dict_spdm)
        self.lst_measurements.append(self.dict_spdm['meas_record'])
        self.num_meas += 1
        self.dict_spdm = ConfigDict()


    def process_spdm_protocol_msg(self):
        """ process spdm 10 protocol message until done or observe error """
        lst_code_1 = ['84', '04', 'e1', '61', 'e3', '63', '81', '01', '82', '02']
        lst_repeat_code_1 = ['82', '02']
        lst_code_2 = ['83', '03', 'e0', '60']
        lst_repeat_code_2 = ['e0', '60']
        self.cert_remainder_len = None
        self.num_meas = 0
        for c in lst_code_1:
            self.bdata_remainder[0:1].hex()=='10'+c
            parse_func = getattr(self, self.bhs_spdm10_code_parse_func[c.upper()])
            #print('parse_func = {}'.format(parse_func))
            try:
                parse_func()
            except Exception as e:
                logger.error("-- process CODE:{} Failed !".format(c))
                print(e)
                #sys.exit(1)

        while (self.cert_remainder_len != None) and (self.cert_remainder_len > 0):
            for c in lst_repeat_code_1:
                self.bdata_remainder[0:1].hex()=='10'+c
                parse_func = getattr(self, self.bhs_spdm10_code_parse_func[c.upper()])
                try:
                    parse_func()
                except Exception as e:
                    logger.error("-- process CODE:{} Failed !".format(c))
                    print(e)
                    #sys.exit(1)

        for c in lst_code_2:
            self.bdata_remainder[0:1].hex()=='10'+c
            parse_func = getattr(self, self.bhs_spdm10_code_parse_func[c.upper()])
            #print('parse_func = {}'.format(parse_func))
            try:
                parse_func()
            except Exception as e:
                logger.error("-- process CODE:{} Failed, check your data !".format(c))
                print(e)
                #sys.exit(1)

        logger.info("---- Total number of measurements: {}".format(self.total_num_meas) )
        while len(self.bdata_remainder)>0:
            for c in lst_repeat_code_2:
                self.bdata_remainder[0:1].hex()=='10'+c
                parse_func = getattr(self, self.bhs_spdm10_code_parse_func[c.upper()])
                try:
                    parse_func()
                except Exception as e:
                    logger.error("-- process CODE:{} Failed !".format(c))
                    print(e)
                    #sys.exit(1)


    def process_binary_file(self):
        """ process spdm data transaction on binary file format
            file: self.spdm_file_binary
            data format must be <spdm_version>, <code>, <data>,... one requester message followed with one responder message
            save data to self.dict_spdm
        """
        with open(self.spdm_file_binary, 'rb') as f:
            self.bdata = f.read()
        self.bdata_remainder = self.bdata
        if self.bdata[0:2] != bytes.fromhex('1084'):
            logger.error("-- wrong data: expect start with '10 84' ...")
            sys.exit(1)
        self.process_spdm_protocol_msg()


    def show_spdm_msg(self):
        """ show self.lst_dict_spdm """
        for d in self.lst_dict_spdm:
            logger.info(d)
            logger.info('----')


    def verify_M2(self):
        """ verify M2 """
        pass

    def verify_root_ca_hash(self):
        """ verify RootCA hash """
        rootca = os.path.join(os.path.dirname(__file__), 'rootca', 'DICE_RootCA.cer')
        hash_data = utility.get_hash384(rootca)
        if hash_data == self.cert_chain[4:52].hex(): 
            print('-- rootca certificate hash384 verificaton : PASS')
        
    def verify_cert_chain(self):
        """ verify certificate chain """
        self.cc_total_len=struct.unpack('<I', self.cert_chain[0:4])[0]
        self.cc_rootca_hash=self.cert_chain[4:52].hex()
        self.cc_data = self.cert_chain[52:]
        self.cc_obj = GNR_Certificate_Chain(self.cc_data)
        self.cc_obj.verify_cert_chain()
        self.cc_obj.show_certificates()


    def verify_protocol(self):
        """ verify certificate """
        """
        self.verify_obj = CPU_SPDM_10(self.lst_dict_spdm)
        self.verify_obj.get_certificate()
        self.verify_obj.get_all_cpu_measurements()
        self.verify_obj.verify_certificate_chain()
        self.verify_obj.verify_measurement()

        self.verify_obj.show_certificates()
        self.verify_obj.show_measurement()
        """


#--------------------------

class PARSE_SPDM_BHS(object):
    """ parse SPDM transaction data collected from BHS CPU attestation

    :param spdm_transaction_file : all spdm transaction data in a file, it is either binary file or a text file with hexstr separated with line or space

    """
    lst_code_size = (('0x84', 4),  ('0x04',  8), \
                     ('0xE1', 4),  ('0x61', 12), \
                     ('0xE3', 32), ('0x63', 36), \
                     ('0x81', 4),  ('0x01', 52), \
                     ('0x82', 8) )

    def __init__(self, spdm_transaction_file):
        self.dict_spdm = ConfigDict()
        self.dict_spdm = { k:[] for k in dict_bhs_spdm_code}

        # process input file, either binary or hex string text file
        self.process_file(spdm_transaction_file)

        curpos=0   # current position
        for (k, s) in self.lst_code_size:
            #pattern=b'\x10'+bytes.fromhex(k[2:])
            self.dict_spdm[k].append(self.bdata[curpos:curpos+s])
            curpos += s

        with open('cpu1_spdm_transaction.bin', 'wb') as f:
            f.write(self.bdata)

        print(self.dict_spdm)
        """
        print(self.dict_spdm['0x84'][0].hex())
        print(self.dict_spdm['0x04'][0].hex())
        print(self.dict_spdm['0xE1'][0].hex())
        print(self.dict_spdm['0x61'][0].hex())
        print(self.dict_spdm['0xE3'][0].hex())
        print(self.dict_spdm['0x63'][0].hex())
        """
        self.cert_pos = curpos
        self.get_cert_size = struct.unpack('<H', self.bdata[(curpos-2):(curpos)])[0]
        #print('-- curpos = {}'.format(curpos))
        #print('-- self.bdata[(curpos-2):(curpos)]={},\n -- get_cert_size=0x{:x}'.format(self.bdata[(curpos-2):(curpos)].hex(), self.get_cert_size))

        self.total_len_certchain = struct.unpack('<H', self.bdata[(curpos+8):(curpos+8+2)])[0]
        self.root_hash   = self.bdata[(curpos+12):(curpos+12+48)]
        self.len_cert   = self.get_cert_size+8
        self.cert_chain = self.bdata[(curpos+8+4+48):(curpos+self.get_cert_size+8)]
        self.dict_spdm['0x02'].append(self.bdata[curpos:(curpos + self.len_cert)])
        curpos += 8 + self.get_cert_size

        #print('-- get_cert_size=0x{:x}'.format(self.get_cert_size))

        while True:
            self.dict_spdm['0x82'].append(self.bdata[curpos:(curpos + 8)])
            curpos += 8
            self.dict_spdm['0x02'].append(self.bdata[curpos:(curpos + 8+ self.get_cert_size)])
            self.cert_chain += self.bdata[(curpos+8):(curpos +8+self.get_cert_size)]

            #print(self.bdata.hex())
            #print('curpos = {}'.format(curpos))

            remainder_len = struct.unpack('<H', self.bdata[(curpos+6):(curpos + 8)])[0]

            curpos += 8 + self.get_cert_size
            if remainder_len <= self.get_cert_size: break

        self.dict_spdm['0x82'].append(self.bdata[curpos:(curpos + 8)])
        curpos += 8
        self.dict_spdm['0x02'].append(self.bdata[curpos:(curpos + 8 + remainder_len)])
        self.cert_chain += self.bdata[(curpos+8):(curpos+8+remainder_len)]
        curpos += 8 + remainder_len
        self.dict_spdm['0x83'].append(self.bdata[curpos:(curpos + 36)])
        curpos += 36
        #print('-- curpos: 0x{:x}'.format(curpos))
        self.opaquelen = struct.unpack('<H', self.bdata[(curpos+132):(curpos + 134)])[0]
        self.dict_spdm['0x03'].append(self.bdata[curpos:(curpos + 134+self.opaquelen+96)])
        curpos += 134+self.opaquelen+96
        #print('-- curpos: 0x{:x}'.format(curpos))
        self.chal_auth_sig_r = self.bdata[curpos-96:(curpos-48)]
        self.chal_auth_sig_s = self.bdata[curpos-48:(curpos)]

        self.save_cert_chain()


    def save_cert_chain(self):
        """ """
        self.cert_chain_der = 'cert_chain.crt'
        with open(self.cert_chain_der, 'wb') as f:
            f.write(self.cert_chain)

    def process_file(self, spdm_transaction_file):
        """ process a hex text file

        remove all line breaks and spaces combine spdm data bytes as hex string, then convert to bytes
        :param spdm_transaction_file: spdm data in binary format or in hex string separated with spaces or linebreaks

        """
        logging.getLogger().setLevel(logging.INFO)
        if is_binary(spdm_transaction_file):
            with open(spdm_transaction_file, 'rb') as f:
                self.bdata=f.read()
        else:
            # process hexstr text file separate with bytes, remove all line break and blank space
            with open(spdm_transaction_file, 'r') as f:
                hexdata = f.read()
            clean_hexdata = hexdata.replace(" ", "").replace("\n", "")
            self.bdata = bytes.fromhex(clean_hexdata)
        logging.getLogger().setLevel(logging.DEBUG)


class Cert():
    """ Certificate Class """
    def __init__(self, subject, issuer, content, expiry=None, position = 0, missing=False):
        self.subject = subject
        self.issuer = issuer
        self.content = content
        self.expiry = expiry
        self.children = []
        self.position = position
        self.missing = missing

    def add_child(self, child):
        self.children.append(child)


class GNR_Certificate_Chain():
    """ BHS CPU Certificate Chain

    :param cert_chain_input: certificate chain in multiple format
       a) bytes format
       b) hexstr format which can be converted to bytes
       d) pem format
    """
    lst_cert_name = ['dice_root', 'sc1', 'gnr', 'gnr_manuf', 'idevid', 'alias', 'alias_spdm']

    def __init__(self, cert_chain_input):
        """ constructor """
        self.lst_certs_fn= ['{:03d}_'.format(self.lst_cert_name.index(c)+1) + c +'.pem' for c in self.lst_cert_name]
        logging.getLogger().setLevel(logging.INFO)

        format_data = "%y%m%d-%H%M%S"
        current_datetime = datetime.datetime.now()
        ts=current_datetime.strftime(format_data)

        if isinstance(cert_chain_input, bytes):
            self.cc_path   = os.getcwd()
            self.cc_chain_path = os.path.join(self.cc_path, 'save_certchain_{}'.format(ts))
            # clean up previous saved folder, only keep latest one in folder
            delete_subfolders_by_name(self.cc_path, 'save_certchain_')

            pathlib.Path(self.cc_chain_path).mkdir(parents=True, exist_ok=True)
            self.fn_cert_chain_der = os.path.join(self.cc_chain_path, 'temp_cert_chain.der')
            with open(self.fn_cert_chain_der, 'wb') as f:
                f.write(cert_chain_input)
        elif isinstance(cert_chain_input, str) and (not re.search(r"[^a-fA-F0-9]", cert_chain_input)):
            self.cc_path   = os.getcwd()
            self.cc_chain_path = os.path.join(self.cc_path, 'save_certchain_{}'.format(ts))
            # clean up previous saved folder, only keep latest one in folder
            delete_subfolders_by_name(self.cc_path, 'save_certchain_')

            pathlib.Path(self.cc_chain_path).mkdir(parents=True, exist_ok=True)
            self.fn_cert_chain_der = os.path.join(self.cc_chain_path, 'temp_cert_chain.der')
            with open(self.fn_cert_chain_der, 'wb') as f:
                f.write(bytes.fromhex(cert_chain_input))
        elif os.path.splitext(cert_chain_input)[-1] == '.pem': # PEM format Cert Chain file, direct process the pem file
            self.fn_cert_chain_pem = cert_chain_input
            self.cc_path   = os.path.dirname(self.fn_cert_chain_pem)
            self.cc_chain_path = os.path.join(self.cc_path, 'save_certchain_{}'.format(ts))
            # clean up previous saved folder, only keep latest one in folder
            delete_subfolders_by_name(self.cc_path, 'save_certchain_')

            pathlib.Path(self.cc_chain_path).mkdir(parents=True, exist_ok=True)
            print(self.fn_cert_chain_pem)
            self.extract_certs_from_pem()
            return
        else: # looger error message for non-supported format of input in constructor
            logger.error('-- non-supported format: must be bin file, bytes, or pem file !')
            return

        self.fn_cert_chain_pem = os.path.splitext(self.fn_cert_chain_der)[0]+'.pem'
        convert_cmd = "openssl storeutl -certs {a} > {b}".format(a= self.fn_cert_chain_der, b=self.fn_cert_chain_pem)
        try:
            result = subprocess.run(convert_cmd, shell=True, check=True, capture_output=True, text=True)
            logger.debug("Command executed successfully:")
            #print(result.stdout)
            #return result
        except subprocess.CalledProcessError as e:
            logger.debug(f"Command failed with exit code {e.returncode}:")
            print(e.stderr)
            return e
        except FileNotFoundError as e:
            logger.debug(f"File not found: {e.filename}, please install it")
            return e
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            return e
        logging.getLogger().setLevel(logging.DEBUG)
        print(self.fn_cert_chain_pem)
        self.extract_certs_from_pem()


    def extract_certs_from_pem(self):
        """ extract certs to a list as strings """
        self.total_certs = 0
        self.lst_certs = []
        with open(self.fn_cert_chain_pem) as whole_cert:
            cert_started = False
            content = ''
            for line in whole_cert:
                if '-----BEGIN CERTIFICATE-----' in line:
                    if not cert_started:
                        content += line
                        cert_started = True
                    else:
                        print('Error, start cert found but already started')
                        sys.exit(1)
                elif '-----END CERTIFICATE-----' in line:
                    if cert_started:
                        content += line
                        self.lst_certs.append(content)
                        self.total_certs += 1
                        content = ''
                        cert_started = False
                    else:
                        print('Error, cert end found without start')
                        sys.exit(1)
                elif cert_started:
                        content += line
            if cert_started:
                print('The file is corrupted')
                sys.exit(1)

        self.save_certs_pem()

    def save_certs_pem(self):
        """ save certificate chain as individual pem file for verification """
        for (cert_fn, cert_pem) in zip(self.lst_certs_fn, self.lst_certs):
            with open(os.path.join(self.cc_chain_path, cert_fn), 'w') as f:
                f.write(cert_pem)

    def verify_cert_chain(self):
        """ verify certificates in the certificate chain
        """
        self.lst_result=[]
        self.verify_certchain_result = False
        for i in range(1, len(self.lst_certs_fn)):
            cmd_line = 'openssl verify -ignore_critical -verbose -CAfile {}'.format(os.path.join(self.cc_chain_path, self.lst_certs_fn[0]))
            untrusted_str = ''
            if i > 1:
                for j in range(1, i):
                    untrusted_str += " -untrusted {}".format(os.path.join(self.cc_chain_path, self.lst_certs_fn[j]))
            cmd_line += "{} {}".format(untrusted_str, os.path.join(self.cc_chain_path, self.lst_certs_fn[i]))
            #print('cmd_line = {}'.format(cmd_line))
            try:
                result = subprocess.run(cmd_line, shell=True, check=True, capture_output=True, text=True)
                if result.returncode == 0: # PASS
                    self.lst_result.append(result.returncode)
                else:
                    self.lst_result.append(1)
            except subprocess.CalledProcessError as e:
                print(f"Command failed with exit code {e.returncode}:")
                print(e.stderr)
                return e

        if self.lst_result == [0, 0, 0, 0, 0, 0]:
            self.verify_certchain_result = True

        import logging
        if logging.getLogger().handlers == []:
            logging.basicConfig(level=logging.INFO, handlers= [logging.StreamHandler()])

        logger.info('-- result: {}, verify_cert_chain :{}'.format(self.lst_result, 'PASS' if self.verify_certchain_result else 'FAIL'))
        #self.show_certificates()


    def check_num_6_cert(self):
        """ check number 6 certificate
         If found below, it is related to DAM setting:

         openssl x509 -inform pem -noout -text -in 006_alias.pem
         X509v3 CRL Distribution Points:
                Full Name:
                  URI:https://tsDE.intel.com/content/DICE/crls/DICE_DE1_Indirect.crl                CRL Issuer:
                  DirName:CN = DICE DE1
        """
        self.cert_6 = os.path.join(self.cc_chain_path, self.lst_certs_fn[5])
        print('-- certificate #6: {}'.format(self.cert_6))
        proc = subprocess.Popen(['openssl', 'x509', '-text', '-noout', '-in', '{}'.format(self.cert_6)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = proc.communicate()
        self.cert6_outmsg = out.decode()
        print('{}'.format(self.cert6_outmsg))

        if 'URI:https://tsci.intel.com/content/DICE/crls/DICE_SC1_Indirect.crl' in self.cert6_outmsg:
            print('-- alias id certificate 6 in chain PASS ')
            return True
        if 'URI:https://tsDE.intel.com/content/DICE/crls/DICE_DE1_Indirect.crl' in self.cert6_outmsg:
            print('-- alias id certificate 6 in chain FAIL -- DAM disable cause the issue, entered debug policy...')
            return False


    def create_certs(self):
        self.certs = []
        position = 1
        for content in self.lst_certs:
            self.certs.append(self.create_cert(content, position))
            position += 1

    def create_cert(self, cert_content, position):
        proc = subprocess.Popen(['openssl', 'x509', '-text'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = proc.communicate(cert_content.encode())

        subject = ''
        issuer = ''
        date = None
        for line in out.decode().split('\n'):
            match = re.match("^\s*(\w*): .*CN ?= ?(.*)$", line)
            if match:
                if match.group(1) == 'Subject':
                    subject = match.group(2)
                elif match.group(1) == 'Issuer':
                    issuer = match.group(2)
            else:
                m = re.match("^\s*Not After\s?: (?P<date>.*)GMT$", line)
                if m:
                    date = datetime.strptime(m.group(1).strip(), '%b %d %H:%M:%S %Y')

        return Cert(subject, issuer, cert_content, expiry=date, position=position)


    def construct_tree(self):
        roots_dir = {} # stores only root certs here
        issuers_dir = {c.subject : c for c in self.certs}
        for c in self.certs:
            if c.subject in roots_dir:
                c = roots_dir[c.subject]
                # this is not self-signed cert, but was added temporarily to roots by other cert as missing parent
                c.missing = False
                del roots_dir[c.subject]

            if c.subject == c.issuer:
                # this is self-signed cert, lets add it to roots
                roots_dir[c.issuer] = c
            else:
                # not self-signed cert
                if c.issuer in roots_dir:
                    roots_dir[c.issuer].add_child(c)
                elif c.issuer in issuers_dir:
                    issuers_dir[c.issuer].add_child(c)
                else:
                    # this is not self signed cert, and has no parent in roots yet
                    # so let's create temporary root and add it to roots
                    missing_root = Cert(c.issuer, 'Unknown issuer', '', missing=True)
                    roots_dir[c.issuer] = missing_root
                    missing_root.add_child(c)

        self.roots = [r for r in roots_dir.values()]

    def print_roots_content(self):
        for root in self.roots:
            self.print_cert_content(root)

    def print_cert_content(self, root):
        now = datetime.now()
        if not root.missing and root.expiry and now < root.expiry:
            print(root.content, end='', file=sys.stderr)
        for c in root.children:
            self.print_cert_content(c)


    def print_cert_roots(self, position=True, expiry=True):
        printable_elements = [[],[]]
        for root in self.roots:
            self.generate_tree_elements_to_print(root, 0, printable_elements, position=position, expiry=expiry)

        max_first = 0
        for e in printable_elements[0]:
            max_first = max(max_first, len(e))

        for e1, e2 in zip(printable_elements[0], printable_elements[1]):
            spaces = max_first - len(e1)
            tabs = ' '*spaces
            print(e1, tabs, e2)


    def generate_tree_elements_to_print(self, root, level, printable_elements, spaces_for_level = 4, last = False, position = False, expiry = False):
        prefix_spaces = level * spaces_for_level
        prefix = ' '*prefix_spaces
        if level == 0:
            prefix += '\u2501'
        else:
            if last:
                prefix += '\u2517\u2501'
            else:
                prefix += '\u2523\u2501'

        postfix = f'[{root.position}]' if position and not root.missing else ''
        postfix2 = ''
        if root.expiry:
            now = datetime.now()
            # now = datetime(2023,8,19)
            if now > root.expiry:
                postfix2 = f'[EXPIRED on: {root.expiry}]'
            elif now + timedelta(days=30) > root.expiry:
                postfix2 = f'[going to expire on: {root.expiry}]'
            elif expiry:
                postfix2 = f'[valid until: {root.expiry}]'

        postfixes = postfix + ' ' + postfix2
        printable_elements[1].append(postfixes)

        presence = ' (NOT PRESENT IN THIS PEM FILE)' if root.missing else ''
        printable_elements[0].append(f'{prefix} {root.subject.strip()}{presence}')
        for i,child in enumerate(root.children):
            last = False if i < len(root.children) - 1 else True
            self.generate_tree_elements_to_print(child, level + 1, printable_elements, last=last, position=position, expiry=expiry)

    def show_certificates(self):
        """ show certificate as a certificate tree
        """
        self.create_certs()
        self.construct_tree()
        self.print_cert_roots(True, True)


class BHS_CPU_Attestation(PARSE_SPDM_BHS):
    """ class for verification of GNR/SRF/CWF CPU attestation

    :param spdm_transaction_file: SPDM transaction data in binary file as "10 84 ... 10 04 ...10 e1 ... ..."

    """
    cert_chain_start_pos = 168  # Certificate Chain position
    cert_chain_add_len   = 52   # (total_Length(2)+Reserved(2)+RootHash(48))

    def __init__(self, spdm_transaction_file):
        """ constructor """
        self.spdm_file = spdm_transaction_file
        self.dict_spdm = ConfigDict()
        super().__init__(self.spdm_file)
        self.ccobj = GNR_Certificate_Chain(self.cert_chain_der)
        #fsize = os.path.getsize(self.spdm_file)
        #with open(self.spdm_file, 'rb') as f:
        #    self.M2 = f.read(fsize-96)
        self.M2=b''
        for (k, s) in self.lst_code_size[:-1]:
            self.M2 +=self.dict_spdm[k][0]
        # add all '0x82' and '0x02'
        for (g, c) in zip(self.dict_spdm['0x82'], self.dict_spdm['0x02']):
            self.M2 += g + c
        self.M2 += self.dict_spdm['0x83'][0]+ self.dict_spdm['0x03'][0][:-96]  # Note not include 96 bytes of signature for M2 calculation

        self.m2hash_hex = hashlib.sha384(self.M2).hexdigest()
        self.M2Hash = bytearray.fromhex(self.m2hash_hex)

    def verify_cert_chain(self):
        """ verify certificate chain """
        self.ccobj.verify_cert_chain()
        if self.ccobj.verify_certchain_result:
            self.ccobj.show_certificates()

    def verify_roothash(self):
        """ verify roothash """
        self.verify_roothash = False
        path = os.path.abspath(__file__)
        f_rootca=os.path.join(os.path.dirname(path), 'rootca', 'DICE_RootCA.cer')
        with open(f_rootca, 'rb') as f:
            self.rootca_data = f.read()
        self.calc_roothash_hex = hashlib.sha384(self.rootca_data).hexdigest()
        logger.info("\ncalculated rootca_hash: {}\n          roothash_hex: {}".format(self.calc_roothash_hex, self.root_hash.hex() ))
        if self.calc_roothash_hex == self.root_hash.hex():
            self.verify_roothash = True
            logger.info("\n-- Verification RootHash PASS ! " )

    def verify_cert_chain_hash(self):
        """ verify certificate chain hash """
        self.verify_certchainhash = False
        self.cert_chain_hash_hex = hashlib.sha384(self.bdata[self.cert_chain_start_pos:(self.cert_chain_start_pos+self.cert_chain_add_len)] + self.cert_chain).hexdigest()
        self.chall_auth_certchainhash = self.dict_spdm['0x03'][0][4:4+48].hex()
        #print("calculated cert_chain_hash: {}\n chall_auth_certchainhash:{}".format(self.cert_chain_hash_hex, self.chall_auth_certchainhash) )
        logger.info("\ncalculated cert_chain_hash: {}\n  chall_auth_certchainhash: {}".format(self.cert_chain_hash_hex, self.chall_auth_certchainhash) )
        if self.cert_chain_hash_hex == self.chall_auth_certchainhash:
            self.verify_certchainhash = True
            logger.info("\n-- Verification CertChainHash PASS ! " )


    def get_pubkey(self):
        """ get public key """
        cmd_get_pubkey = "openssl x509 -in {} -pubkey -noout > {}".format(os.path.join(self.ccobj.cc_chain_path,  '007_alias_spdm.pem'), 'cpu_spdm_public_key.pem')
        result = subprocess.run(cmd_get_pubkey,  shell=True, check=True, capture_output=True, text=True)
        self.cpu_spdm_public_key = 'cpu_spdm_public_key.pem'

    def verify_M2(self):
        """ verify M2 """
        self.get_pubkey()
        self.signature_R = self.dict_spdm['0x03'][0][-96:-48]
        self.signature_S = self.dict_spdm['0x03'][0][-48:]
        ## change endianess of R and S for PFR
        self.signature_R = self.signature_R[::-1]
        self.signature_S = self.signature_S[::-1]
        self.VK = self.cpu_spdm_public_key
        #print('-- signature: R: {}, S: {}'.format(self.signature_R.hex(), self.signature_S.hex()))
        R, S = self.signature_R, self.signature_S
        with open(self.VK) as f:
            vk = VerifyingKey.from_pem(f.read())
        r, s = int.from_bytes(R, byteorder='big'), int.from_bytes(S, byteorder='big')
        order = ecdsa.NIST384p.generator.order()
        #print(r, s, order)
        signature = sigencode_der(r, s, order)
        #print(signature.hex())
        try:
            assert vk.verify(signature, self.M2, hashlib.sha384, sigdecode=sigdecode_der)
        except:
            logger.info('-- Verification CHALLENGE_AUTH Signature Failed')
            raise
            self.verify_chall_auth_signature = False
            return False
        logger.info('-- Verification CHALLENGE_AUTH Signature PASS !')
        self.verify_chall_auth_signature = True
        return True

    def verify(self):
        """ verify spdm transaction data """
        self.verify_roothash()
        self.verify_cert_chain_hash()
        self.verify_cert_chain()
        self.verify_M2()


class BHS_SPDM_ATTESTATION_DATA(BHS_CPU_SPDM_PARSER):
    """ class for SPDM data in BHS CPU (GNR/SRF/CWF) attestation operation

    :param spdm_transaction_file: SPDM transaction data either in binary or in hex string format, as "10 84 ... 10 04 ...10 e1 ... ..."
        bin file: binary data as "10 <cmd-code> <data>", one follows another.
        txt file: hex string without 0x, data bytes can be separated with random number of blank lines or spaces.

    """
    def __init__(self, spdm_transaction_file):
        """ constructor """
        self.spdm_file = spdm_transaction_file
        self.dict_spdm = ConfigDict()
        super().__init__(self.spdm_file)

        self.ccobj = GNR_Certificate_Chain(self.cert_chain_der)
        #fsize = os.path.getsize(self.spdm_file)
        #with open(self.spdm_file, 'rb') as f:
        #    self.M2 = f.read(fsize-96)
        self.M2=b''
        for (k, s) in self.lst_code_size[:-1]:
            self.M2 +=self.dict_spdm[k][0]
        # add all '0x82' and '0x02'
        for (g, c) in zip(self.dict_spdm['0x82'], self.dict_spdm['0x02']):
            self.M2 += g + c
        self.M2 += self.dict_spdm['0x83'][0]+ self.dict_spdm['0x03'][0][:-96]  # Note not include 96 bytes of signature for M2 calculation

        self.m2hash_hex = hashlib.sha384(self.M2).hexdigest()
        self.M2Hash = bytearray.fromhex(self.m2hash_hex)

class MCTP_OVER_I3C_SPDM10():
    """ class for process MCTP over I3C SPDM 1.0 packet

      MCTP over I3C Format:
      |Board|Device|'<RX<'/'>TX>'|HdrVer[3:0]|DstEID|SrcEID|SOM[7],EOM[6],PktSeq[5:4],TO[3],MsgTag[2:0]|MsgType=05|SPDM_Ver=10|SPDM10_Code|<spdm_payload data>

      dict_msg_mctp_spdm10

    """
    lst_SPDM_TX = ['81', '82', '83', '84', 'E0', 'E1', 'E3']
    lst_SPDM_RX = ['01', '02', '03', '04', '60', '61', '63']

    def __init__(self, msgline,  preline_dict_msg_mctp_spdm10={}):
        self.msgline  = msgline
        self.preline_dict_msg_mctp_spdm10 = preline_dict_msg_mctp_spdm10
        self.is_spdm = False
        self.dict_msg_mctp_spdm10 = ConfigDict()
        self.dict_msg_mctp_spdm10['is_spdm'] = False


    def check_spdm_data(self):
        """ check if contains spdm data """
        flag1, flag2, flag3, rflag = False, False, False, False
        if ( '>TX>' in self.msgline ) or ('<RX<' in self.msgline) :
            flag1 = True
        if (not flag1):
            self.dict_msg_mctp_spdm10['is_spdm'] = False
            return

        #print('pre_line: {}'.format(self.preline_dict_msg_mctp_spdm10))
        #print('cur_line: {}'.format(self.msgline))

        hex_pattern = r'[^0-9a-fA-F ]'  # non hex string none space pattern
        lst_data = re.sub(hex_pattern, '', self.msgline.split('asti3c:')[-1]).strip().split(' ')

        if (lst_data[4] == '05') and (lst_data[5] == '10') and (lst_data[6] in (self.lst_SPDM_TX + self.lst_SPDM_RX)):
            self.dict_msg_mctp_spdm10['is_spdm'] = True
            SeqByte = int(lst_data[3], 16)
            self.dict_msg_mctp_spdm10['code'] = lst_data[6]
            self.dict_msg_mctp_spdm10['data'] = ''.join(lst_data[7:])
            self.dict_msg_mctp_spdm10['som'] = (SeqByte & 0x80) >> 7
            self.dict_msg_mctp_spdm10['eom'] = (SeqByte & 0x40) >> 6
            self.dict_msg_mctp_spdm10['seq'] = (SeqByte & 0x30) >> 4
            self.dict_msg_mctp_spdm10['brd'] = 'bnc' if ('mctpd-BNC_Baseboard' in self.msgline) else 'avc'
            self.dict_msg_mctp_spdm10['dev'] = self.msgline.split('MCTP_I3C_MNG_')[-1].split('[')[0].lower()

        elif (self.preline_dict_msg_mctp_spdm10['is_spdm'] == True):
            if (self.preline_dict_msg_mctp_spdm10['eom'] != 1):  # continue spdm packet data
                SeqByte = int(lst_data[3], 16)
                self.dict_msg_mctp_spdm10['is_spdm'] = True
                self.dict_msg_mctp_spdm10['som']  = (SeqByte & 0x80) >> 7
                self.dict_msg_mctp_spdm10['eom']  = (SeqByte & 0x40) >> 6
                self.dict_msg_mctp_spdm10['seq']  = (SeqByte & 0x30) >> 4
                self.dict_msg_mctp_spdm10['code'] = self.preline_dict_msg_mctp_spdm10['code'] # same code as before
                self.dict_msg_mctp_spdm10['data'] = ''.join(lst_data[4:])
        #print('is_spdm: {}'.format(self.dict_msg_mctp_spdm10['is_spdm']))
        return self.dict_msg_mctp_spdm10['is_spdm']

    def process_msgline(self):
        """ process single message line check if its SPDM data """
        pass


class CPU_SPDM_10(object):
    """ class for SPDM 1.0 protocol operations

        :param lst_spdm_msg: list of spdm message from 0x84 to 0x60
    """
    meas_index_desc = {'1': 'SoC boot time FW', \
                       '2': 'Descriptor Region Configuration', \
                       '3': 'FIT Record 4', \
                       '4': 'uCode FIT patch', \
                       '5': 'Startup ACM', \
                       '8': 'Boot Policy Manifest'
                       }

    def __init__(self, lst_spdm_msg_raw):
        """ constructor """
        self.lst_spdm_msg_raw = lst_spdm_msg_raw
        self.lst_spdm_msg     = []
        self.dict_spdm_protocol= ConfigDict()

    def combine_lst_msg(self, lst_seg_msg):
        """ combine lst of segment message as one

            input:
                ConfigDict([('is_spdm', True), ('code', '02'), ('data', '0000C800CC10941100004A284657C5509147DA86D2C82DFF98360182EFAA26D3DCFA7AE485F4DC61B3BCB3A854AFC9A6A58F4DAEC35B2594FF0E308201'), ('som', 1), ('eom', 0), ('seq', 0), ('brd', 'avc'), ('dev', 'cpu1')])
                ConfigDict([('is_spdm', True), ('som', 0), ('eom', 0), ('seq', 1), ('code', '02'), ('data', 'CB30820151A003020102020101300A06082A8648CE3D040303301D311B301906035504030C12496E74656C204449434520526F6F742043413020170D32303039')])
                ConfigDict([('is_spdm', True), ('som', 0), ('eom', 0), ('seq', 2), ('code', '02'), ('data', '30313030303030305A180F39393939313233313233353935395A301D311B301906035504030C12496E74656C204449434520526F6F742043413076301006072A')])
                ConfigDict([('is_spdm', True), ('som', 0), ('eom', 1), ('seq', 3), ('code', '02'), ('data', '8648CE3D020106052B8104002203620004')])

            output:
                ConfigDict([('is_spdm', True), ('som', 1), ('eom', 1), ('seq', 0), ('code', '02'), ('data', 'combine_data'), ('brd', 'avc'), ('dev', 'cpu1')])
             combine_data =
            '0000C800CC10941100004A284657C5509147DA86D2C82DFF98360182EFAA26D3DCFA7AE485F4DC61B3BCB3A854AFC9A6A58F4DAEC35B2594FF0E308201'+\
            'CB30820151A003020102020101300A06082A8648CE3D040303301D311B301906035504030C12496E74656C204449434520526F6F742043413020170D32303039'+\
            '30313030303030305A180F39393939313233313233353935395A301D311B301906035504030C12496E74656C204449434520526F6F742043413076301006072A'+\
            '8648CE3D020106052B8104002203620004')
        """
        single_dict = ConfigDict()
        lst_key = ['is_spdm', 'code', 'som', 'eom', 'seq', 'brd', 'dev']
        lst_val = [True, lst_seg_msg[0]['code'], 1, 1, 0, lst_seg_msg[0]['brd'], lst_seg_msg[0]['dev']]
        for (k, v) in zip(lst_key, lst_val):
            single_dict[k]=v
        single_dict['data'] =''
        for i in lst_seg_msg:
            single_dict['data'] += i['data']
        return single_dict


    def merge_segment_msg_data(self):
        """ merge multiple segment packet in spdm message protocol
            CERTIFICATE and MESSAGE
            self.lst_spdm_msg_raw --> self.lst_spdm_msg
        """
        temp=ConfigDict()
        lst_seg_msg = []
        start_flag = False
        for d in self.lst_spdm_msg_raw:
            if (not start_flag) and (d['som'] == 1) and (d['eom'] == 1):  # no merge action if som=eom=1
                self.lst_spdm_msg.append(d)
            if (not start_flag) and (d['som'] == 1) and (d['eom'] == 0):  #
                start_flag = True
                lst_seg_msg.append(d)
            if (start_flag==True) and (d['som'] == 0) and (d['eom'] == 0):  #
                lst_seg_msg.append(d)
            if (start_flag==True) and (d['som'] == 0) and (d['eom'] == 1):  #
                lst_seg_msg.append(d)
                self.lst_spdm_msg.append(self.combine_lst_msg(lst_seg_msg))
                start_flag  = False
                lst_seg_msg = []

    def get_certificate(self):
        """ get certificate data
        """
        if len(self.lst_spdm_msg) == 0:
            self.merge_segment_msg_data()
        self.spdm_cert_chain=''
        for (req, res) in zip(self.lst_spdm_msg[0::2], self.lst_spdm_msg[1::2]):
            #print('--req:{} \n--res:{}\n\n'.format(req, res))
            if req['code'] == '82' and res['code'] == '02':
                print("req['data']={}".format(req['data']))  # '00 00 D007 C800'
                (p1, p2, req_offset, req_len) = struct.unpack('<BBHH', bytes.fromhex(req['data']))
                fmt = '<BBHH{}s'.format(req_len)
                print("res['data']={}, length={}".format(res['data'], len(bytes.fromhex(res['data']))))
                (p1, p2, portionlen, remainlen, certchain) = struct.unpack(fmt, bytes.fromhex(res['data']))
                self.spdm_cert_chain += certchain.hex()

        (self.total_len, self.root_ca_hash) = struct.unpack('<I48s', bytes.fromhex(self.spdm_cert_chain[:52*2]))
        self.cpu_cert_chain = self.spdm_cert_chain[52*2:]
        # save as binary file for processing
        with open("cpu_cert_chain.bin", 'wb') as f1:
            f1.write(bytes.fromhex(self.cpu_cert_chain))

        self.cert_chain_obj = GNR_Certificate_Chain(self.cpu_cert_chain)

    def show_certificates(self):
        """ show certificate chain"""
        self.cert_chain_obj.show_certificates()


    def parse_protocol_message (self):
        """ parse SPDM 1.0 protocol message merge all segments
        """
        for m in self.lst_spdm_msg:
            self.dict_spdm_protocol
        pass


    def verify_certificate_chain(self):
        """ verify certifcate chain """
        self.cert_chain_obj.verify_cert_chain()


    def get_all_cpu_measurements(self):
        """ get all CPU responded measurements """
        if len(self.lst_spdm_msg) == 0:
            self.merge_segment_msg_data()
        req_meas_fmt1 = '<BB32s'
        res_meas_fmt1 = '<BBB3s'
        res_meas_fmt2 = '<BBHBH'

        self.lst_meas   = []
        self.dict_meas  = ConfigDict()
        self.total_meas = 0
        for (req, res) in zip(self.lst_spdm_msg[0::2], self.lst_spdm_msg[1::2]):

            if req['code'] =='E0' and res['code'] == '60':
                #print(res['data'])
                (req_p1, req_p2, req_nounce) = struct.unpack(req_meas_fmt1, bytes.fromhex(req['data']))
                #(res_p1, res_p2, num_blk, measrec_len, meas_idx, meas_spec, meas_size, meas_value_type, meas_value_size) = struct.unpack('<BBB3sBBHBH', bytes.fromhex(res['data'][:13]))
                (res_p1, res_p2, num_blk, measrec_len) = struct.unpack(res_meas_fmt1, bytes.fromhex(res['data'][:6*2]))
                meas_rec_len = struct.unpack('<I', measrec_len+b'\x00')[0]

                if req_p1==1 and req_p2==0: # request total # of meas
                    # res with total #
                    self.total_meas = res_p1
                    assert(req_p2==0 and meas_rec_len == 0)

                if req_p1==1 and (req_p2>=1 and req_p2<=0xfe):
                    # res with index p2 meas
                    lst_val = struct.unpack(res_meas_fmt2, bytes.fromhex(res['data'][6*2:13*2]))
                    lst_key = ('meas_idx', 'meas_spec', 'meas_size', 'meas_v_type', 'meas_v_size')
                    for (k,v) in zip(lst_key, lst_val):
                        self.dict_meas[k] = v

                    res_meas_fmt3 = '<{}s32sH96s'.format(self.dict_meas['meas_v_size'])
                    lst_v = struct.unpack(res_meas_fmt3, bytes.fromhex(res['data'][13*2:]))
                    lst_k = ('measurement', 'nounce', 'opaquelen', 'signature')
                    for (k, v) in zip(lst_k, lst_v):
                        self.dict_meas[k] = v

                    # append of lst_meas
                    #print('--dict_meas:{}'.format(self.dict_meas))
                    self.lst_meas.append(self.dict_meas)
                    self.dict_meas  = ConfigDict()


    def show_measurement(self):
        """ display all measurements """
        for d in self.lst_meas:
            logger.info('-- index:{} -- {:32s} -- {}'.format(d['meas_idx'], self.meas_index_desc['{}'.format(d['meas_idx'])], d['measurement'].hex()))

    def verify_measurement(self):
        """ verify measurements data """
        logger.info('-- verify measurement ')
        pass

    def verify_m2(self):
        """ """
        logger.info('-- verify M2 ')
        pass


    def verify_protocol(self):
        """ verify

        from intelprot import cpu_attestation as att
        obj1=att.BHS_CRB_MCTP_TRACE('888.11_mctp_log_1.log')
        obj1.parse_raw_file()
        obj1.parse_spdm_data()
        obj2=att.CPU_SPDM_10(obj1.lst_cpu1_msg_queue[0])
        obj2.get_certificate()

        with open('t_obj2_lst_spdm_code_data.txt', 'w') as f:
            for m in obj2.lst_spdm_msg:
                f.write('-- {} : {}\n\n'.format(m['code'], m['data']))

        """
        self.verify_certificate_chain()
        self.verify_measurement()
        self.verify_m2()




class BHS_CRB_MCTP_TRACE(object):
    """
        class for processing MCTP trace file collected from Intel BHS RPs (Avenue City and Beachnut City)

    :param mctp_trace_filename: MCTP trace file collected from BMC raw file without any modification.
    :param mctp_agent: device of mctp trace, in list of (pfr, cpu1, cpu2), the analysis is based on all tx/rx of the mctp agent
    :param output_file: output SPDM packets from the mctp agent

    """
    lst_SPDM_TX = ['81', '82', '83', '84', 'E0', 'E1', 'E3']
    lst_SPDM_RX = ['01', '02', '03', '04', '60', '61', '63']

    def __init__(self, mctp_trace_filename, mctp_agent="cpu1"):
        """ constructor """
        self.mctp_trace_f    = mctp_trace_filename
        self.mctp_agent      = mctp_agent
        self.dict_spdm       = ConfigDict()  # spdm data packets for the agent
        self.lst_cpu1_spdm_msg    = []   # list of spdm message from code 84 to 60 for cpu1
        self.lst_cpu1_msg_queue   = []   # contains multiple spdm protocol transaction flows from 84 to 60 for cpu1
        self.lst_cpu2_spdm_msg    = []   # list of spdm message from code 84 to 60 for cpu2
        self.lst_cpu2_msg_queue   = []   # contains multiple spdm protocol transaction flows from 84 to 60 for cpu2
        # save all lines
        self.all_lines  = []
        self.pfr_lines  = []
        self.cpu1_lines = []
        self.cpu2_lines = []
        #self.cpu3_lines = []
        #self.cpu4_lines = []
        # save all spdm lines for a specific device in mctp trace including pfr, cpu1/2/3/4
        self.pfr_spdm_lines  = []
        self.cpu1_spdm_lines = []
        self.cpu2_spdm_lines = []
        #self.cpu3_spdm_lines = []
        #self.cpu4_spdm_lines = []

    def parse_raw_file(self):
        """ parse raw file: save only SPDM packets for self.mctp_agent

        """
        with open(self.mctp_trace_f, 'r') as f1:
            self.all_lines = f1.readlines()

        [self.pfr_lines.append(line)  for line in self.all_lines if ('MCTP_I3C_MNG_PFR' in line)]
        [self.cpu1_lines.append(line) for line in self.all_lines if ('MCTP_I3C_MNG_CPU1' in line)]
        [self.cpu2_lines.append(line) for line in self.all_lines if ('MCTP_I3C_MNG_CPU2' in line)]

        pre_line=''
        preline_dict = {}
        preline_dict['is_spdm'] = False
        self.cpu1_spdm_lines  = []
        for line in self.cpu1_lines:
            lineobj = MCTP_OVER_I3C_SPDM10(line, preline_dict)
            lineobj.check_spdm_data()
            if lineobj.dict_msg_mctp_spdm10['is_spdm']:
                self.cpu1_spdm_lines.append(line)
            preline_dict = lineobj.dict_msg_mctp_spdm10
            preline = line

        pre_line=''
        preline_dict = {}
        preline_dict['is_spdm'] = False
        self.cpu2_spdm_lines  = []
        for line in self.cpu2_lines:
            lineobj = MCTP_OVER_I3C_SPDM10(line, preline_dict)
            lineobj.check_spdm_data()
            if lineobj.dict_msg_mctp_spdm10['is_spdm']:
                self.cpu2_spdm_lines.append(line)
            preline_dict = lineobj.dict_msg_mctp_spdm10
            preline = line

        pre_line=''
        preline_dict = {}
        preline_dict['is_spdm'] = False
        self.pfr_spdm_lines  = []
        for line in self.pfr_lines:
            lineobj = MCTP_OVER_I3C_SPDM10(line, preline_dict)
            lineobj.check_spdm_data()
            if lineobj.dict_msg_mctp_spdm10['is_spdm']:
                self.pfr_spdm_lines.append(line)
            preline_dict = lineobj.dict_msg_mctp_spdm10
            preline = line

    def get_spdm_data(self, line, som, eom):
        """ get spdm data from a line """
        hex_pattern = r'[^0-9a-fA-F ]'  # non-hex and non-space string pattern
        lst_data = re.sub(hex_pattern, '', line.split('asti3c:')[-1]).strip().split(' ')
        #print('lst_data = {}'.format(lst_data))
        if (som == 1) and (eom == 1):
            return ' '.join(lst_data[5:])+'\n'+'\n'
        if (som == 1) and (eom == 0):
            return ' '.join(lst_data[5:])+'\n'
        if (som == 0) and (eom == 0):
            return ' '.join(lst_data[4:])+'\n'
        if (som == 0) and (eom == 1):
            return ' '.join(lst_data[4:])+'\n'+'\n'

    def parse_spdm_data(self):
        """ parse spdm data from spdm_lines for a specific device, such as cpu1 or pfr
            This includes single line spdm packet and multiple lines spdm packets

            single line spdm pkt:
                01 EID EID C8 + 05 10 + <opcode> + ...    <som=1><eom=1>

            multiple line spdm pkt:
                01 EID EID 80 + 05 10 + <opcode: 02> + ...  <som=1><eom=0><seq=0>
                01 EID EID 10 + data ...                    <som=0><eom=0><seq=1>
                01 EID EID 20 + data ...                    <som=0><eom=0><seq=2>
                01 EID EID 70 + data ...                    <som=0><eom=1><seq=3>
        """
        self.cpu1_spdm_data = []
        self.cpu2_spdm_data = []
        self.lst_cpu1_spdm_msg    = []   # list of spdm message from code 84 to 60 for cpu1
        self.lst_cpu1_msg_queue   = []   # contains multiple spdm protocol transaction flows from 84 to 60 for cpu1
        pre_line=''
        preline_dict = {}
        self.lst_cpu1_msg_queue   = []
        for line in self.cpu1_spdm_lines:
            lineobj = MCTP_OVER_I3C_SPDM10(line, preline_dict)
            lineobj.check_spdm_data()
            if lineobj.dict_msg_mctp_spdm10['is_spdm']:
                line_spdm = self.get_spdm_data(line, lineobj.dict_msg_mctp_spdm10['som'], lineobj.dict_msg_mctp_spdm10['eom'])
                self.cpu1_spdm_data.append(line_spdm)
                if lineobj.dict_msg_mctp_spdm10['code'] == '84' and len(self.lst_cpu1_spdm_msg) > 12:
                    self.lst_cpu1_msg_queue.append(self.lst_cpu1_spdm_msg)
                    self.lst_cpu1_spdm_msg = []
                self.lst_cpu1_spdm_msg.append(lineobj.dict_msg_mctp_spdm10)
            preline_dict = lineobj.dict_msg_mctp_spdm10
            preline=line
        self.lst_cpu1_msg_queue.append(self.lst_cpu1_spdm_msg) # save last list to queue

        pre_line=''
        preline_dict = {}
        self.lst_cpu2_spdm_msg    = []
        self.lst_cpu2_msg_queue   = []
        for line in self.cpu2_spdm_lines:
            lineobj = MCTP_OVER_I3C_SPDM10(line, preline_dict)
            lineobj.check_spdm_data()
            if lineobj.dict_msg_mctp_spdm10['is_spdm']:
                line_spdm = self.get_spdm_data(line, lineobj.dict_msg_mctp_spdm10['som'], lineobj.dict_msg_mctp_spdm10['eom'])
                self.cpu2_spdm_data.append(line_spdm)
                if lineobj.dict_msg_mctp_spdm10['code'] == '84' and len(self.lst_cpu2_spdm_msg) > 12:
                    self.lst_cpu2_msg_queue.append(self.lst_cpu2_spdm_msg)
                    self.lst_cpu2_spdm_msg = []
                self.lst_cpu2_spdm_msg.append(lineobj.dict_msg_mctp_spdm10)
            preline_dict = lineobj.dict_msg_mctp_spdm10
            preline=line
        self.lst_cpu2_msg_queue.append(self.lst_cpu2_spdm_msg) # save last list to queue


    def save_data(self):
        """ save all intermediat data for analysis/debug purpose """
        format_data = "%y%m%d-%H%M%S"
        current_datetime = datetime.datetime.now()
        ts=current_datetime.strftime(format_data)

        p = os.path.join(os.getcwd(), 'save_{}_{}'.format(os.path.splitext(self.mctp_trace_f)[0], ts))
        # clean up previous saved folder, only keep latest one in folder
        delete_subfolders_by_name(os.getcwd(), 'save_{}'.format(os.path.splitext(self.mctp_trace_f)[0]))
        pathlib.Path(p).mkdir(parents=True, exist_ok=True)

        with open(os.path.join(p, 'pfr_spdm_lines.log'), 'w') as f1:
            for line in self.pfr_spdm_lines: f1.write(line)

        with open(os.path.join(p, 'cpu1_spdm_lines.log'), 'w') as f2:
            for line in self.cpu1_spdm_lines: f2.write(line)

        with open(os.path.join(p, 'cpu1_spdm_data.log'), 'w') as f3:
            for line in self.cpu1_spdm_data: f3.write(line)

        with open(os.path.join(p, 'cpu1_spdm_msg_queue.log'), 'w') as f4:
            idx=0
            for m in self.lst_cpu1_msg_queue:
                f4.write('\n---- lst_cpu1_msg_queue: index {}\n'.format(idx))
                for d in m:
                    f4.write('-- {}\n'.format(d))
                idx += 1

        with open(os.path.join(p, 'cpu2_spdm_lines.log'), 'w') as f2:
            for line in self.cpu2_spdm_lines: f2.write(line)

        with open(os.path.join(p, 'cpu2_spdm_data.log'), 'w') as f3:
            for line in self.cpu2_spdm_data: f3.write(line)

        with open(os.path.join(p, 'cpu2_spdm_msg_queue.log'), 'w') as f4:
            idx=0
            for m in self.lst_cpu2_msg_queue:
                f4.write('\n---- lst_cpu2_msg_queue: index {}\n'.format(idx))
                for d in m:
                    f4.write('-- {}\n'.format(d))
                idx += 1

        #save the cpu1 first spdm protocol message as a binary file "cpu1_spdm_transaction.bin"
        tmpobj = CPU_SPDM_10(self.lst_cpu1_msg_queue[0])
        tmpobj.merge_segment_msg_data()
        with open(os.path.join(p, 'cpu1_spdm_transaction.bin'), 'wb') as f5:
            for m in tmpobj.lst_spdm_msg:
                f5.write(bytes.fromhex('10' + m['code'] + m['data']))

        with open(os.path.join(p, 'cpu1_spdm_transaction.log'), 'w') as f6:
            for m in tmpobj.lst_spdm_msg:
                if len(m['data']) < 128:
                    f6.write('10'+' '+ m['code'] +' '+ m['data']+'\n')
                else:
                    f6.write('10'+' '+ m['code'] +'\n')
                    data_len=len(m['data'])
                    for i in range(0, data_len, 64):
                        f6.write(m['data'][i:(i+64-1)] +'\n')


class BHS_BMC_PROT_MCTP(object):
    """ class to process BMC as PRoT trace collected from openBMC SPDM
    """
    def __init__(self, openbmc_prot_trace):
        self.raw_trace = openbmc_prot_trace
        self.cert_chain = ''

    def get_certificate_lines(self):
        """
            extract lines block with cerificate data

            Certificate (offset 0xc8, size 0xc8):
            0000: 8a 6e 18 1f 6f 81 a2 fb e1 ad f9 72 f6 3b 8e 8f 0a 73 fd 96 2f e9 dd e6 08 1b 0d 55 e0 e6 73 c8
            0020: 22 7f a9 9a 59 8d 0c a4 27 0a bb f4 20 e2 6b 61 3f 74 e5 09 d1 50 ed fb 52 92 a3 78 f4 e6 5c a2
            0040: 1e a0 1d bb fd a8 a4 04 83 40 81 2f da 2e ab 75 bd 84 3a ff 0b 7c 3e 60 34 b6 bf bb 08 35 99 d6
            0060: a3 63 30 61 30 1f 06 03 55 1d 23 04 18 30 16 80 14 3d 3b 83 86 d5 05 aa 02 14 24 12 c5 3b 6f bc
            0080: 38 8f 3e 89 f3 30 1d 06 03 55 1d 0e 04 16 04 14 3d 3b 83 86 d5 05 aa 02 14 24 12 c5 3b 6f bc 38
            00a0: 8f 3e 89 f3 30 0f 06 03 55 1d 13 01 01 ff 04 05 30 03 01 01 ff 30 0e 06 03 55 1d 0f 01 01 ff 04
            00c0: 04 03 02 01 06 30 0a 06
            ...
            Certificate (offset ***, size 0xc8):
            {data-block}
        """
        hex_pattern = r'0x[0-9a-fA-F]+'
        try:
            with open(self.raw_trace, 'r') as f:
                self.lines = f.readlines()
            self.lst_offset_size, self.lst_start_line, self.lst_parse_line_num = [], [], []
            i = 0
            for line in self.lines:
                if line.startswith('Certificate (offset'):
                    matches = re.findall(hex_pattern, line)
                    (o, s) = matches
                    offset, size = int(o, 16), int(s, 16)
                    self.lst_offset_size.append((offset, size))
                    self.lst_start_line.append(i+1)
                    self.lst_parse_line_num.append(math.ceil(size/32))
                i +=1
        except FileNotFoundError:
            print(f"Error: The file '{file_path}' was not found.")

    def parse_block_lines(self, start_line, num_f_line):
        """ parse a block of lines """
        hexstr = ''
        block_lines = self.lines[start_line:(start_line + num_f_line)]
        for l in block_lines:
            hexstr += ''.join(l.split(':')[1].strip().split(' '))
        #print('-- hexstr:\n{}'.format(hexstr))
        return hexstr

    def process_certificate(self):
        """
        """
        self.get_certificate_lines()
        for (st_line, num_line) in zip(self.lst_start_line, self.lst_parse_line_num):
            #print("** start_line={}, num_of_lines={}".format(st_line, num_line))
            self.cert_chain += self.parse_block_lines(st_line, num_line)
        self.total_cert_bytes= struct.unpack('<I', bytes.fromhex(self.cert_chain[0:8]))[0]
        self.root_dice_hash  = self.cert_chain[8:104]
        self.cert_chain_data = self.cert_chain[104:]


    def show(self):
        print('-- total:{}'.format(self.total_cert_bytes))
        print('-- root_dice_hash:{}'.format(self.root_dice_hash))
        print('-- cert_chain_data: {}'.format(self.cert_chain_data))


def main(args):
    """ verify CPU attestation SPDM protocol """
    parser = argparse.ArgumentParser(description="-- CPU attestation verification utility ")

    subparser = parser.add_subparsers(dest='file_source')
    crb_trace = subparser.add_parser('crb_trace')
    crb_trace.add_argument('-p', '--platform',    metavar="[platform of CPU]", dest='cpu_platform', default='bhs', help="which platform for the cpu : bhs or oks, default is 'bhs' ")
    crb_trace.add_argument('-i', '--mctp_trace',  metavar="[Input file of mctp trace that is collected from CRB BMC using MCTP bridge]", dest='input_file', help='input SPDM transaction data file, either binary or hex string')
    crb_trace.add_argument('-v', '--verify',      nargs='*', type=str, dest='lst_verify', help="parse and verify legacy cpu spdm data transaction for the listed items {cert., meas., m2}")
    crb_trace.add_argument('-s', '--show',        nargs='*', type=str, dest='lst_show',   help="show listed items from the trace file")
    crb_trace.add_argument('-l', '--logfile',     metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")

    prot_trace = subparser.add_parser('prot_trace')
    prot_trace.add_argument('-p', '--platform',    metavar="[platform of CPU]", dest='cpu_platform', default='bhs', help="which platform for the cpu : bhs or oks, default is 'bhs' ")
    prot_trace.add_argument('-i', '--prot_trace',  metavar="[Input file of spdm trace that is collected from openBMC as PRoT]", dest='input_file', help='input SPDM transaction data file')
    prot_trace.add_argument('-v', '--verify',     nargs='*', type=str, dest='lst_verify', help="parse and verify legacy cpu spdm data transaction for the listed items {cert., meas., m2}")
    prot_trace.add_argument('-s', '--show',       nargs='*', type=str, dest='lst_show',   help="show listed items from the trace file")
    prot_trace.add_argument('-l', '--logfile',     metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")

    spdm_trace = subparser.add_parser('spdm_data')
    spdm_trace.add_argument('-p', '--platform',   metavar="[platform of CPU]", dest='cpu_platform', default='bhs', help="which platform for the cpu : bhs or oks, default is 'bhs' ")
    spdm_trace.add_argument('-i', '--spdm_data',  metavar="[Input file of spdm trace that is collected from openBMC as PRoT]", dest='input_file', help='input SPDM transaction data file, either binary or hex string')
    spdm_trace.add_argument('-v', '--verify',     nargs='*', type=str, dest='lst_verify', default=['cert', 'meas'], help="parse and verify legacy cpu spdm data transaction for the item listed: ['cert, meas'], default is to verify both")
    spdm_trace.add_argument('-s', '--show',       nargs='*', type=str, dest='lst_show',   default=['cert', 'meas'], help="show listed items: ['cert', 'meas'] from the trace file, default is show both")
    spdm_trace.add_argument('-l', '--logfile',    metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")

    args = parser.parse_args(args)

    if args.logfile != None:
        logging.basicConfig(level=logging.INFO,
                        handlers= [
                          logging.FileHandler(args.logfile, mode='w'),
                          logging.StreamHandler()
                        ]
                      )
    else:
        logging.basicConfig(level=logging.INFO, handlers= [ logging.StreamHandler()])
    """
    if args.cpu_platform == 'bhs':
        cpuatt_obj1 = BHS_CRB_MCTP_TRACE(args.input_file)
        cpuatt_obj.verify()
    """
    if args.file_source == 'crb_trace':
        logger.info('\n-- Processing CRB MCTP Tace: {} --\n'.format(args.input_file))
        att_obj1 = BHS_CRB_MCTP_TRACE(args.input_file)
        att_obj1.parse_raw_file()
        att_obj1.parse_spdm_data()
        att_obj1.save_data()
        att_obj2 = CPU_SPDM_10(att_obj1.lst_cpu1_msg_queue[0])  # select the first trace for CPU1 to process
        att_obj2.get_certificate()
        att_obj2.get_all_cpu_measurements()
        if 'cert' in args.lst_verify:
            att_obj2.verify_certificate_chain()
        if 'meas' in args.lst_verify:
            att_obj2.verify_measurement()

        if 'cert' in args.lst_show:
            att_obj2.show_certificates()
        if 'meas' in args.lst_show:
            att_obj2.show_measurement()


    if args.file_source == 'prot_trace':
        logger.info('\n-- Processing PRoT SPDM Tace: {} --\n'.format(args.input_file))

    if args.file_source == 'spdm_data':
        logger.info('-- Processing SPDM data file: {}'.format(args.input_file))
        print(args.lst_verify)
        print(args.lst_show)
        #obj1=

    print(args)

if __name__ == '__main__':
    main(sys.argv[1:])
