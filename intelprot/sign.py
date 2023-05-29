#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  :platform: Linux, Windows
  :synopsis: PFR sining module. This module is to sign an image for pfr using private keys.
             It also supports pfr image analysis and verification.
             It can be used as stanalone with command line arguments.

  It also includes external sign class and command line execution.

  ..Command line execution::

  >python -m intelprot.sign -h   # get help
  >python -m intelprot.sign -i <input_unsigned_image> -t <pc type> -n <csk_id> -r <root private key> -c <csk private key> -o <output_signed_image>

    author: "Scott Huang (scott.huang@intel.com)"
"""
from __future__ import print_function
from __future__ import division

import hashlib, struct, argparse, sys, os
import xml.etree.ElementTree as ET
from collections import OrderedDict
from intelprot import keys

import logging
logger = logging.getLogger(__name__)

BLOCK_MAGIC_PFR_2  = (0xB6EAFD19, 0xF27F28D7, 0xA757A046, 0xC7B88C74, 0x14711C2F, 0xC7B88C74, 0xDE64437D, 0x15364367, 0xDE64437D)
BLOCK_MAGIC_PFR_3  = (0xB6EAFD19, 0xF27F28D7, 0xA757A046, 0x08F07B47, 0x14711C2F, 0x08F07B47, 0xEA2A50E9, 0x15364367, 0xEA2A50E9)

BLOCK_KEY = ('b0_tag', 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384', 'b0_pad', \
          'b1_tag', 'b1_rsvd', \
          'b1r_tag', 'b1r_cur', 'b1r_per', 'b1r_keyid', 'b1r_x', 'b1r_y', 'b1r_rsvd', \
          'b1c_tag', 'b1c_cur', 'b1c_per', 'b1c_keyid', 'b1c_x', 'b1c_y', 'b1c_rsvd', 'b1c_sig', 'b1c_sigR', 'b1c_sigS', \
          'b1b_tag', 'b1b_sig', 'b1b_sigR', 'b1b_sigS', \
          'b1_pad')

B0_RSVD_SIZE  = 4
B0_PAD_SIZE   = 32
B1_RSVD_SIZE  = 12
B1R_RSVD_SIZE = 20
B1C_RSVD_SIZE = 20
B1_PAD_SIZE   = 412
B1_CSK_SIZE   = 232

DECOMM_PCTYPE  = 0x200

_dict_PC_TYPE_CSK_PERMISSION = \
  {"cpld capsule": (0x0, 0x10), \
    "pch pfm":     (0x1, 0x01), \
    "pch capsule": (0x2, 0x02), \
    "bmc pfm":     (0x3, 0x04), \
    "bmc capsule": (0x4, 0x08), \
    "afm":         (0x6, 0x20), \
    "seamless":    (0x5, 0x02), \
    "cfm":         (0x7, 0x40)  # this is for CPLD FW online update capsule, it is named as CFM capsule
    }

def get_csk_permission(pc_type):
  d = _dict_PC_TYPE_CSK_PERMISSION
  print("pc_type = {}".format(pc_type))
  if pc_type == DECOMM_PCTYPE: return 0x10   # this is for decommision capsule
  if isinstance(pc_type, int):
    for k, v in d.items():
      if v[0] == pc_type: return v[1]
  if isinstance(pc_type, str):
    for k, v in d.items():
      if k == pc_type: return v[1]


# for nested dictionary
class ConfigDict(OrderedDict):
  """ define an ordered dictionary """
  def __missing__(self, key):
    val = self[key] = ConfigDict()
    return val

class Signing(object):
  """ Signing class

  :param image: unsigned image file name
  :param pc_type: protect content type

     Bit[7:0]:

      * 00h = PFR CPLD Update capsule
      * 01h = PFR PCH PFM
      * 02h = PFR PCH Update Capsule
      * 03h = PFR BMC PFM
      * 04h = PFR BMC Update Capsule
      * 05h = PFR PCH/CPU Seamless Update Capsule
      * 06h = PFR AFM

  :param csk_id: ID of CSK
  :param rk_prv_pem: root private key in pem format
  :param csk_prv_pem: csk private key in pem format

  """
  def __init__(self, image, pc_type, csk_id, rk_prv_pem, csk_prv_pem):
    self.image_unsigned = image
    self.pc_type        = int(pc_type)
    self.csk_id         = int(csk_id)
    self.rk_prv         = rk_prv_pem
    self.csk_prv        = csk_prv_pem
    self.pfr_version = 3 if keys.get_curve(rk_prv_pem) == 'NIST384p' else 2

    if not self.verify_key():
      logger.warning('--- pfr_version={} need baselen={} key !'.format(self.pfr_version, int(self.pfr_version)*16))
      raise ValueError('-- invalid keys for the PFR version !')
    self.image_signed   = os.path.splitext(self.image_unsigned)[0]+'_signed_pfr{:d}.bin'.format(self.pfr_version)
    self.blk_dict       = ConfigDict()

    if int(self.pfr_version) >= 3:
      block_magic = [struct.pack('<I', i) for i in BLOCK_MAGIC_PFR_3]
    elif int(self.pfr_version) == 2:
      block_magic = [struct.pack('<I', i) for i in BLOCK_MAGIC_PFR_2]

    (self.blk_dict['b0_tag'], self.blk_dict['b1_tag'], self.blk_dict['b1r_tag'], self.blk_dict['b1r_cur'], \
    self.blk_dict['b1c_tag'], self.blk_dict['b1c_cur'], self.blk_dict['b1c_sig'], \
    self.blk_dict['b1b_tag'], self.blk_dict['b1b_sig'] ) = block_magic

    self.blk_dict['b0_rsvd']   = bytearray(B0_RSVD_SIZE)
    self.blk_dict['b0_pad']    = bytearray(B0_PAD_SIZE)
    self.blk_dict['b1_rsvd']   = bytearray(B1_RSVD_SIZE)
    self.blk_dict['b1r_per']   = struct.pack('<I', 0xffffffff)
    self.blk_dict['b1r_keyid'] = struct.pack('<I', 0xffffffff)
    self.blk_dict['b1r_rsvd']  = bytearray(B1R_RSVD_SIZE)
    self.blk_dict['b1c_rsvd']  = bytearray(B1C_RSVD_SIZE)
    self.blk_dict['b1_pad']    = bytearray(B1_PAD_SIZE) # pad for 1024B

  def verify_key(self):
    (baselen1, curvename1) = keys.get_curve_baselen(self.rk_prv)
    (baselen2, curvename2) = keys.get_curve_baselen(self.csk_prv)
    if int(self.pfr_version) == 2 and baselen1 == 32 and baselen2 == 32: return True
    if int(self.pfr_version) == 3 and baselen1 == 48 and baselen2 == 48: return True
    logger.warning("-- Your pfr_version does not match with key length !")
    logger.warning("-- rk_prv : {}{}".format(baselen1, curvename1))
    logger.warning("-- csk_prv: {}{}".format(baselen2, curvename2))
    return False

  def set_signed_image(self, outimage):
    """ set output image """
    self.image_signed = outimage

  def sign(self):
    """ signing image
    """
    pclen = os.stat(self.image_unsigned).st_size
    padlen = 0
    if (pclen % 128) != 0:
      padlen = 128 - (pclen % 128)
    print("pclen, padlen", pclen, padlen)
    pclen  += padlen
    print("pclen, padlen", pclen, padlen)
    with open(self.image_unsigned, 'rb') as f:
      bdata  = f.read()
      bdata += bytes(b'\xff'*padlen)
    self.hash256= hashlib.sha256(bdata).hexdigest()
    self.hash384= hashlib.sha384(bdata).hexdigest()
    # 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384',
    self.blk_dict['b0_pclen']   = struct.pack('<I', pclen)
    self.blk_dict['b0_pctyp']   = struct.pack('<I', self.pc_type)
    self.blk_dict['b0_hash256'] = bytes.fromhex(self.hash256)
    self.blk_dict['b0_hash384'] = bytes.fromhex(self.hash384)
    rkprvk = keys.PrivateKey().read_from_pem(self.rk_prv)
    self.blk_dict['b1r_x'], self.blk_dict['b1r_y'] = rkprvk.X, rkprvk.Y

    csk_permission = struct.pack('<I', get_csk_permission(self.pc_type))

    self.blk_dict['b1c_per'] = csk_permission
    self.blk_dict['b1c_keyid'] = struct.pack('<I', int(self.csk_id))
    cskprvk = keys.PrivateKey().read_from_pem(self.csk_prv)
    self.blk_dict['b1c_x'], self.blk_dict['b1c_y'] = cskprvk.X, cskprvk.Y
    self.csksign_data = b''
    for k in ('b1c_cur', 'b1c_per', 'b1c_keyid', 'b1c_x', 'b1c_y', 'b1c_rsvd'):
      self.csksign_data += self.blk_dict[k]
    self.blk_dict['b1c_sigR'], self.blk_dict['b1c_sigS'] = keys.get_RS_signdata(self.rk_prv, self.csksign_data)

    #print("self.csksign_data.hex = {}".format(self.csksign_data.hex()))
    #print("--hash384: ", hashlib.sha384(self.csksign_data).hexdigest())

    self.blk0_data = b''
    for k in ('b0_tag', 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384', 'b0_pad'):
      self.blk0_data += self.blk_dict[k]

    self.blk_dict['b1b_sigR'], self.blk_dict['b1b_sigS'] = keys.get_RS_signdata(self.csk_prv, self.blk0_data)

    with open(self.image_signed, 'wb') as f, open(self.image_unsigned, 'rb') as f1:
      #total=0
      for k in BLOCK_KEY:
        f.write(self.blk_dict[k])
      f.write(f1.read())
      f.write(b'\xff'*padlen)


class Signing_No_B1CSK(object):
  """ Signing class

  :param image: unsigned image file name
  :param pc_type: protect content type

     Bit[7:0]:

      * 00h = PFR CPLD Update capsule
      * 01h = PFR PCH PFM
      * 02h = PFR PCH Update Capsule
      * 03h = PFR BMC PFM
      * 04h = PFR BMC Update Capsule
      * 05h = PFR PCH/CPU Seamless Update Capsule
      * 06h = PFR AFM

  :param csk_id: ID of CSK
  :param rk_prv_pem: root private key in pem format

  """
  def __init__(self, image, pc_type, csk_id, rk_prv_pem):
    self.image_unsigned = image
    self.pc_type        = pc_type
    self.csk_id         = csk_id
    self.rk_prv         = rk_prv_pem
    self.pfr_version = 3 if keys.get_curve(self.rk_prv) == 'NIST384p' else 2
    self.image_signed   = os.path.splitext(self.image_unsigned)[0]+'_signed_pfr{}.bin'.format(self.pfr_version)
    self.blk_dict       = ConfigDict()

    if int(self.pfr_version) >= 3:
      block_magic = [struct.pack('<I', i) for i in BLOCK_MAGIC_PFR_3]
    elif int(self.pfr_version) == 2:
      block_magic = [struct.pack('<I', i) for i in BLOCK_MAGIC_PFR_2]

    (self.blk_dict['b0_tag'], self.blk_dict['b1_tag'], self.blk_dict['b1r_tag'], self.blk_dict['b1r_cur'], \
    self.blk_dict['b1c_tag'], self.blk_dict['b1c_cur'], self.blk_dict['b1c_sig'], \
    self.blk_dict['b1b_tag'], self.blk_dict['b1b_sig'] ) = block_magic

    self.blk_dict['b0_rsvd']   = bytearray(B0_RSVD_SIZE)
    self.blk_dict['b0_pad']    = bytearray(B0_PAD_SIZE)
    self.blk_dict['b1_rsvd']   = bytearray(B1_RSVD_SIZE)
    self.blk_dict['b1r_per']   = struct.pack('<I', 0xffffffff)
    self.blk_dict['b1r_keyid'] = struct.pack('<I', 0xffffffff)
    self.blk_dict['b1r_rsvd']  = bytearray(B1R_RSVD_SIZE)
    self.blk_dict['b1c_rsvd']  = bytearray(B1C_RSVD_SIZE)
    self.blk_dict['b1_pad']    = bytearray(B1_PAD_SIZE + B1_CSK_SIZE) # add B1_CSK size to pad for 1024B

  def set_signed_image(self, outimage):
    """ set output image """
    self.image_signed = outimage

  def sign(self):
    """ signing image
    """
    pclen = os.stat(self.image_unsigned).st_size
    padlen = 0
    if (pclen % 128) != 0:
      padlen = 128 - (pclen % 128)
    print("pclen, padlen", pclen, padlen)
    pclen  += padlen
    print("pclen, padlen", pclen, padlen)
    with open(self.image_unsigned, 'rb') as f:
      bdata  = f.read()
      bdata += bytes(b'\xff'*padlen)
    self.hash256= hashlib.sha256(bdata).hexdigest()
    self.hash384= hashlib.sha384(bdata).hexdigest()
    # 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384',
    self.blk_dict['b0_pclen']   = struct.pack('<I', pclen)
    self.blk_dict['b0_pctyp']   = struct.pack('<I', self.pc_type)
    self.blk_dict['b0_hash256'] = bytes.fromhex(self.hash256)
    self.blk_dict['b0_hash384'] = bytes.fromhex(self.hash384)
    rkprvk = keys.PrivateKey().read_from_pem(self.rk_prv)
    self.blk_dict['b1r_x'], self.blk_dict['b1r_y'] = rkprvk.X, rkprvk.Y

    #print(self.blk0)
    self.blk0_data = b''
    for k in ('b0_tag', 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384', 'b0_pad'):
      self.blk0_data += self.blk_dict[k]

    # block 0 data is signed with root key if no CSK entry.
    self.blk_dict['b1b_sigR'], self.blk_dict['b1b_sigS'] = keys.get_RS_signdata(self.rk_prv, self.blk0_data)

    with open(self.image_signed, 'wb') as f, open(self.image_unsigned, 'rb') as f1:
      #total=0
      lst_no_b1csk=[]
      [lst_no_b1csk.append(x) for x in BLOCK_KEY if x.startswith('b1c') is False]  # filter out "b1c_*" in key list
      for k in lst_no_b1csk:
        f.write(self.blk_dict[k])
      f.write(f1.read())
      f.write(b'\xff'*padlen)


def get_csk_entry_hash(permission, csk_id, csk_pub, hashfunc='sha384', outfile='csk_entry_hash.bin'):
  """
  This function is to get csk entry hash data to be signed by root private key.
  This function is used for external signing.

  :param permission: permission, = 0x3 for ifwi, 0x4: bmc pfm; 0x8: bmc update
  :param csk_id: CSK ID number
  :param csk_pub: CSK public key in PEM format
  :param hashfunc: hash function, either 'sha384' or 'sha256'. Default is 'sha384' for secp384r1
  """
  outfile = os.path.join(os.getcwd(), outfile)
  if hashfunc == 'sha384': curvemagic = 0x08F07B47
  if hashfunc == 'sha256': curvemagic = 0xC7B88C74
  csk_entry_data = struct.pack('<I', curvemagic)
  csk_entry_data += struct.pack('<I', permission)
  csk_entry_data += struct.pack('<I', csk_id)
  pubkey = keys.PublicKey().read_from_pem(csk_pub)
  csk_entry_data += pubkey.X + pubkey.Y
  csk_entry_data += bytearray(20)
  if hashfunc == 'sha384':
    csk_entry_hash = hashlib.sha384(csk_entry_data).hexdigest()
  if hashfunc == 'sha256':
    csk_entry_hash = hashlib.sha256(csk_entry_data).hexdigest()
  with open(outfile, 'wb') as f:
    f.write(bytes.fromhex(csk_entry_hash))
  return csk_entry_hash


def rk_sign_csk_entry(rk_prv, csk_entry_hash):
  """
  Root key sign CSK entry hash data, return signature R and S

  :param rk_prv: root private key
  :param csk_entry_hash: csk entry hash data to be signed
  """
  R, S = keys.get_RS_signdata(rk_prv, bytes.fromhex(csk_entry_hash))
  return (R, S)


class Ext_Signing(object):
  """
  Class for external signing operation.
  This is used by system builder (ODM) to sign content using CSK without knowing the root private key.
  It is given the csk  entry signature R and S provided by Root key owner (OEM)

  ODM (CSK owner) gives CSK Public key to OEM (RK owner) to generate csk entry signature R and S
  OEM gives ODM root public key and CSK entry signature R and S

  :param image: unsigned image file name
  :param pc_type: protect content type

     Bit[7:0]:

      * 00h = PFR CPLD Update capsule
      * 01h = PFR PCH PFM
      * 02h = PFR PCH Update Capsule
      * 03h = PFR BMC PFM
      * 04h = PFR BMC Update Capsule
      * 05h = PFR PCH/CPU Seamless Update Capsule
      * 06h = PFR AFM

  :param csk_id: ID of CSK
  :param rk_pub: root public key in pem format
  :param csk_prv: csk private key in pem format
  :param csk_entry_sigR: CSK entry signature R in hex string format
  :param csk_entry_sigS: CSK entry signature S in hex string format

  """
  def __init__(self, image, pc_type, csk_id, rk_pub, csk_prv, csk_entry_sigR, csk_entry_sigS):
    self.image_unsigned = image
    self.pc_type        = int(pc_type)
    self.csk_id         = int(csk_id)
    self.rk_pub         = rk_pub
    self.csk_prv        = csk_prv
    self.csk_entry_sigR = csk_entry_sigR
    self.csk_entry_sigS = csk_entry_sigS
    self.pfr_version = 3 if keys.get_curve(rk_pub) == 'NIST384p' else 2

    if not self.verify_key():
      logger.warning('--- pfr_version={} need baselen={} key !'.format(self.pfr_version, int(self.pfr_version)*16))
      raise ValueError('-- invalid keys for the PFR version !')
    self.image_signed   = os.path.splitext(self.image_unsigned)[0]+'_signed_pfr{:d}.bin'.format(self.pfr_version)
    self.blk_dict       = ConfigDict()

    if int(self.pfr_version) >= 3:
      block_magic = [struct.pack('<I', i) for i in BLOCK_MAGIC_PFR_3]
    elif int(self.pfr_version) == 2:
      block_magic = [struct.pack('<I', i) for i in BLOCK_MAGIC_PFR_2]

    (self.blk_dict['b0_tag'], self.blk_dict['b1_tag'], self.blk_dict['b1r_tag'], self.blk_dict['b1r_cur'], \
    self.blk_dict['b1c_tag'], self.blk_dict['b1c_cur'], self.blk_dict['b1c_sig'], \
    self.blk_dict['b1b_tag'], self.blk_dict['b1b_sig'] ) = block_magic

    self.blk_dict['b0_rsvd']   = bytearray(B0_RSVD_SIZE)
    self.blk_dict['b0_pad']    = bytearray(B0_PAD_SIZE)
    self.blk_dict['b1_rsvd']   = bytearray(B1_RSVD_SIZE)
    self.blk_dict['b1r_per']   = struct.pack('<I', 0xffffffff)
    self.blk_dict['b1r_keyid'] = struct.pack('<I', 0xffffffff)
    self.blk_dict['b1r_rsvd']  = bytearray(B1R_RSVD_SIZE)
    self.blk_dict['b1c_rsvd']  = bytearray(B1C_RSVD_SIZE)
    self.blk_dict['b1_pad']    = bytearray(B1_PAD_SIZE) # pad for 1024B

  def verify_key(self):
    (baselen1, curvename1) = keys.get_curve_baselen(self.rk_pub)
    (baselen2, curvename2) = keys.get_curve_baselen(self.csk_prv)
    if int(self.pfr_version) == 2 and baselen1 == 32 and baselen2 == 32: return True
    if int(self.pfr_version) == 3 and baselen1 == 48 and baselen2 == 48: return True
    logger.warning("-- Your pfr_version does not match with key length !")
    logger.warning("-- rk_pub : {}{}".format(baselen1, curvename1))
    logger.warning("-- csk_prv: {}{}".format(baselen2, curvename2))
    return False

  def set_signed_image(self, outimage):
    """ set output image """
    self.image_signed = outimage

  def sign(self):
    """ signing image
    """
    pclen = os.stat(self.image_unsigned).st_size
    padlen = 0
    if (pclen % 128) != 0:
      padlen = 128 - (pclen % 128)
    print("pclen, padlen", pclen, padlen)
    pclen  += padlen
    print("pclen, padlen", pclen, padlen)
    with open(self.image_unsigned, 'rb') as f:
      bdata  = f.read()
      bdata += bytes(b'\xff'*padlen)
    self.hash256= hashlib.sha256(bdata).hexdigest()
    self.hash384= hashlib.sha384(bdata).hexdigest()
    # 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384',
    self.blk_dict['b0_pclen']   = struct.pack('<I', pclen)
    self.blk_dict['b0_pctyp']   = struct.pack('<I', self.pc_type)
    self.blk_dict['b0_hash256'] = bytes.fromhex(self.hash256)
    self.blk_dict['b0_hash384'] = bytes.fromhex(self.hash384)
    rkpubk = keys.PublicKey().read_from_pem(self.rk_pub)
    self.blk_dict['b1r_x'], self.blk_dict['b1r_y'] = rkpubk.X, rkpubk.Y

    csk_permission = struct.pack('<I', get_csk_permission(self.pc_type))

    self.blk_dict['b1c_per'] = csk_permission
    self.blk_dict['b1c_keyid'] = struct.pack('<I', int(self.csk_id))
    cskprvk = keys.PrivateKey().read_from_pem(self.csk_prv)
    self.blk_dict['b1c_x'], self.blk_dict['b1c_y'] = cskprvk.X, cskprvk.Y
    #self.csksign_data = b''
    #for k in ('b1c_cur', 'b1c_per', 'b1c_keyid', 'b1c_x', 'b1c_y', 'b1c_rsvd'):
    #  self.csksign_data += self.blk_dict[k]
    self.blk_dict['b1c_sigR'], self.blk_dict['b1c_sigS'] = bytes.fromhex(self.csk_entry_sigR), bytes.fromhex(self.csk_entry_sigS)

    #print("self.csksign_data.hex = {}".format(self.csksign_data.hex()))
    #print("--hash384: ", hashlib.sha384(self.csksign_data).hexdigest())

    self.blk0_data = b''
    for k in ('b0_tag', 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384', 'b0_pad'):
      self.blk0_data += self.blk_dict[k]

    self.blk_dict['b1b_sigR'], self.blk_dict['b1b_sigS'] = keys.get_RS_signdata(self.csk_prv, self.blk0_data)

    with open(self.image_signed, 'wb') as f, open(self.image_unsigned, 'rb') as f1:
      #total=0
      for k in BLOCK_KEY:
        f.write(self.blk_dict[k])
      f.write(f1.read())
      f.write(b'\xff'*padlen)


def main(args):
  """ main program

  :param input_img: input image, -i --input_img
  :param pc_type:   protect content type, -t --pc_type
  :param csk_id: csk ID, -n --csk_id
  :param rk_prv: root private key, -r rk_prv
  :param csk_prv: csk private key, -c --csk_prv
  :param out_img: output image, default is <input_img>_signed_pfr<pfr_ver>.bin, -o --out_img

  ..example::

   - run in Python console or in another python scripts
   >>> from intelprot import sign
   >>> sign.main(['-i', input_image, 't', pc_type, '-v', 'n', csk_id, 'r', rk_prv, 'c', csk_prv])
   or:
   >>> x=sign.Signing(input_image, pc_type, csk_id, rk_prv, csk_prv)
   >>> x.sign()

   For external signing::

    >python -m intelprot.sign -extsign -h
    >python -m intelprot.sign extsign -i PFM_signed.bin -t 3 -n 2 -rk key_root_pub.pem -csk key_csk_prv.pem \
    -sigR  f43c9041e75328c89ab42a8981abe5cdeac9c6d513ad929c2f30ef104ae38a615fdd8d8f08c9d30423ba39da7a8e8c0c \
    -sigS 4f147c189d9a9eefda99375fba1d4e47aeafac1a205ae7fbe124b45d9f4af6c6106b8caebbd7a2ffea3f2461d9cb9528 \
    -o out_test_extsign_image.bin

  """
  parser = argparse.ArgumentParser(description='pfr sign tool in python')
  parser.add_argument('-i', '--input_img',  metavar="[input image]",           dest='input_img',  default=None, help='raw image to be signed')
  parser.add_argument('-t', '--pc_type',    metavar="[protect content type]",  dest='pc_type',    default=1, help='PC type')
  parser.add_argument('-n', '--csk_id',     metavar="[CSK ID]",                dest='csk_id',     default=0, help='CSK ID')
  parser.add_argument('-r', '--rk_prv',     metavar="[RK private]",            dest='rk_prv',     default=None, help='root private key')
  parser.add_argument('-c', '--csk_prv',    metavar="[CSK private]",           dest='csk_prv',    default=None, help='csk private key')
  parser.add_argument('-o', '--out_img',    metavar="[output image]",          dest='out_img',    default=None, help='output image')

  subparser = parser.add_subparsers(dest='signtype')
  exts = subparser.add_parser('extsign')
  exts.add_argument('-i', '--input_img',  metavar="[input image]",           dest='input_img',  default=None, help='raw image to be signed')
  exts.add_argument('-t', '--pc_type',    metavar="[protect content type]",  dest='pc_type',    default=1, help='PC type')
  exts.add_argument('-n', '--csk_id',     metavar="[CSK ID]",                dest='csk_id',     default=0, help='CSK ID')
  exts.add_argument('-rk', '--rk_pub',     metavar="[RK public]",             dest='rk_pub',     default=None, help='root public key')
  exts.add_argument('-csk', '--csk_prv',    metavar="[CSK private]",           dest='csk_prv',    default=None, help='csk private key')
  exts.add_argument('-sigR', '--csk_sigR',   metavar="[CSK entry signature R]", dest='csk_sigR',   default=None, help='csk entry signature R')
  exts.add_argument('-sigS', '--csk_sigS',   metavar="[CSK entry signature S]", dest='csk_sigS',   default=None, help='csk entry signature S')
  exts.add_argument('-o', '--out_img',    metavar="[output image]",          dest='out_img',    default=None, help='output image')

  args = parser.parse_args(args)
  logger.info(args)
  if args.signtype is None:
    # image, pc_type, csk_id, rk_prv_pem, csk_prv_pem
    x=Signing(args.input_img, args.pc_type, args.csk_id, args.rk_prv, args.csk_prv)
    if args.out_img is not None:
      x.set_signed_image(args.out_img)
    x.sign()

  if args.signtype == 'extsign':
    print('external signing')
    print(args)
    x= Ext_Signing(args.input_img, args.pc_type, args.csk_id, args.rk_pub, args.csk_prv, args.csk_sigR, args.csk_sigS)
    if args.out_img is not None:
      x.set_signed_image(args.out_img)
    x.sign()


if __name__ == '__main__':
  main(sys.argv[1:])
