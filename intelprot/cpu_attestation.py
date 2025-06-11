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

import struct, hashlib, struct, os, sys, string, re
import argparse
import pathlib, subprocess
from collections import OrderedDict

import pathlib, subprocess
import ecdsa
from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der
from binaryornot.check import is_binary

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

class PARSE_SPDM_BHS(object):
    """ parse SPDM transaction data collected from BHS CPU attestation

    :param spdm_transaction_file : all spdm transaction data in a file, it is either binary file or a text file with hexstr separated with line or space

    """
    lst_code_size = (('0x84', 4), ('0x04',  8), \
                     ('0xE1', 4), ('0x61', 12), \
                     ('0xE3', 32), ('0x63',36), \
                     ('0x81', 4), ('0x01', 52), \
                     ('0x82', 8) )

    def __init__(self, spdm_transaction_file):
        self.dict_spdm = ConfigDict()
        self.dict_spdm = { k:[] for k in dict_bhs_spdm_code }

        # process input file, either binary or hex string text file
        self.process_file(spdm_transaction_file)

        curpos=0   # current position
        for (k, s) in self.lst_code_size:
            #pattern=b'\x10'+bytes.fromhex(k[2:])
            self.dict_spdm[k].append(self.bdata[curpos:curpos+s])
            curpos += s
        self.cert_pos = curpos
        self.get_cert_size = struct.unpack('<H', self.bdata[(curpos-2):(curpos)])[0]
        self.total_len_certchain = struct.unpack('<H', self.bdata[(curpos+8):(curpos+8+2)])[0]
        self.root_hash   = self.bdata[(curpos+12):(curpos+12+48)]
        self.len_cert   = self.get_cert_size+8
        self.cert_chain = self.bdata[(curpos+8+4+48):(curpos+self.get_cert_size+8)]
        self.dict_spdm['0x02'].append(self.bdata[curpos:(curpos + self.len_cert)])
        curpos += 8 + self.get_cert_size
        while True:
            self.dict_spdm['0x82'].append(self.bdata[curpos:(curpos + 8)])
            curpos += 8
            self.dict_spdm['0x02'].append(self.bdata[curpos:(curpos + 8+ self.get_cert_size)])
            self.cert_chain += self.bdata[(curpos+8):(curpos +8+self.get_cert_size)]
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

class Cert:
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

    :param cert_chain_file: binary file of certificate chain data in bytes

    """
    lst_cert_name = ['dice_root', 'sc1', 'gnr', 'gnr_manuf', 'idevid', 'alias', 'alias_spdm']

    def __init__(self, cert_chain_file):
        """ constructor """
        self.lst_certs_fn= ['{:03d}_'.format(self.lst_cert_name.index(c)+1) + c +'.pem' for c in self.lst_cert_name]
        logging.getLogger().setLevel(logging.INFO)
        if is_binary(cert_chain_file):
            self.fn_cert_chain_der = cert_chain_file
        else:
            if os.path.splitext(cert_chain_file)[-1] == '.pem': # PEM format Cert Chain
                self.fn_cert_chain_pem = cert_chain_file
                self.cc_path   = os.path.dirname(self.fn_cert_chain_pem)
                self.cc_chain_path = os.path.join(self.cc_path, 'cert_chain')
                pathlib.Path(self.cc_chain_path).mkdir(parents=True, exist_ok=True)
                print(self.fn_cert_chain_pem)
                self.extract_certs_from_pem()
                return
            else: # other txt format, save as binary file first
                # process hexstr text file separate with bytes, remove all line break and blank space
                with open(cert_chain_file, 'r') as f:
                    hexdata = f.read()
                clean_hexdata = hexdata.replace(" ", "").replace("\n", "")
                self.bdata = bytes.fromhex(clean_hexdata)
                self.fn_cert_chain_der = os.path.splitext(cert_chain_file)[0]+'.crt'
                with open(self.fn_cert_chain_der, 'wb') as f:
                    f.write(self.bdata)

        self.fn_cert_chain_pem = os.path.splitext(self.fn_cert_chain_der)[0]+'.pem'
        self.cc_path   = os.path.dirname(self.fn_cert_chain_der)
        self.cc_chain_path = os.path.join(self.cc_path, 'cert_chain')
        pathlib.Path(self.cc_chain_path).mkdir(parents=True, exist_ok=True)
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

        logger.info('-- result: {}, verify_cert_chain :{}'.format(self.lst_result, 'PASS' if self.verify_certchain_result else 'FAIL'))

    def check_num_6_cert(self):
        """ check number 6 certificate
         If found below, it is related to DAM setting:

         X509v3 CRL Distribution Points:
                Full Name:
                  URI:https://tsDE.intel.com/content/DICE/crls/DICE_DE1_Indirect.crl                CRL Issuer:
                  DirName:CN = DICE DE1
        """
        self.cert_6 = os.path.join(self.cc_chain_path, self.lst_certs_fn[5])
        print('-- certificate #6: {}'.format(self.cert_6))
        proc = subprocess.Popen(['openssl', 'x509', '-text', '-noout', 'in', '{}'.format(self.cert_6)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = proc.communicate()
        self.cert6_outmsg = out.decode()


    def create_certs(self):
        self.certs = []
        position = 1
        for content in self.lst_certs:
            self.certs.append(self.create_cert(content, position))
            position += 1
        #return certs


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


def main(args):
    """ verify CPU attestation SPDM protocol """
    parser = argparse.ArgumentParser(description="-- CPU attestation verification utility ")
    parser.add_argument('-p', '--platform',   metavar="[platform of CPU : bhs or oks]", dest='cpu_platform', default='bhs', help="which platform for the cpu : bhs or oks, default is 'bhs' ")
    parser.add_argument('-i', '--fname_spdm',   metavar="[Input file of spdm data in binary or in hex text format]", dest='input_file', help='input SPDM transaction data file, either binary or hex string')
    parser.add_argument('-v', '--verify',  action='store_true', help="verify spdm data transaction")
    parser.add_argument('-l', '--logfile', metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")
    args = parser.parse_args(args)
    print(args)
    if args.logfile != None:
        logging.basicConfig(level=logging.DEBUG,
                        handlers= [
                          logging.FileHandler(args.logfile, mode='w'),
                          logging.StreamHandler()
                        ]
                      )
    else:
        logging.basicConfig(level=logging.DEBUG, handlers= [ logging.StreamHandler()])

    if args.cpu_platform == 'bhs':
        cpuatt_obj = BHS_CPU_Attestation(args.input_file)
        cpuatt_obj.verify()

if __name__ == '__main__':
    main(sys.argv[1:])
