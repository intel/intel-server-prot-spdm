#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
   :platform: Linux, Windows
   :synopsis: Python script to update CPLD unisgned capsule and sign it

   cpld module includes function to build cpld update capsule.
   The unsigned recovery capsule is the pfr_cfm1_auto.rpd generated from Quartus. It requies swap bytes convertion and then sign it with block sign.
   Then use both RK and CSK private keys to sign it. The RK/CSK default are reference platform keys.

   Build CPLD update capsule in Python console
   ============================================

   code block::

     >>>from intelprot import cpld
     >>>mycpld = cpld.PFR_CPLD(pfr_cfm1_auto.rpd, platform, svn, csk_id)
     >>>mycpld.build_update_capsule( )

   command line
   ------------

   python (or python3 for Linux) should be in system executable path.
   save the keys and unsigned capsule in work folder.
   It requires Python 3.8 or later Python

   command line::

     >python -m intelprot.cpld -h                 # help
     >python -m intelprot.cpld build_capsule  -h  # help menu to build  capsule from cfm1 rpd file
     >python -m intelprot.cpld modify_capsule -h  # help menu to modify capsule from existing one (change cskid, svn)


   Note
   ====

   RoT SVN number in mailbox 02h only get changed after successful recovery update with different SVN number

"""
import os, sys, shutil, struct, argparse, pathlib
from collections import OrderedDict
import binascii
import codecs
import re
import struct
import unittest
import logging

from intelprot import sign, utility, keys

logger = logging.getLogger(__name__)

_CPLD_CAP_PCTYPE  = 0   # pc_type for CPLD update capsule

BLK0_FMT = '<IIII32s48s32s'
BLK0_KEY = ['b0_tag', 'pc_len', 'pc_type', 'b0_rsvd1', 'hash256', 'hash384', 'b0_rsvd2']
BLK1_FMT = 'I12sIIII48s48s20sIIII48s48s20sI48s48sII48s48s'
BLK1_KEY_B1R   = ['b1_tag', 'b1_rsvd1', 'b1r_tag', 'b1r_curve', 'b1r_permission', 'b1r_keyid', 'b1r_pubX', 'b1r_pubY', 'b1r_rsvd2']
BLK1_KEY_B1CSK = ['b1csk_tag', 'b1csk_curve', 'b1csk_permission', 'b1csk_keyid', 'b1csk_pubX', 'b1csk_pubY', 'b1csk_rsvd1', 'b1csk_sig_magic', 'b1csk_sigR', 'b1csk_sigS']
BLK1_KEY_B1B0  = ['b1b0_tag', 'b1b0_sig_magic', 'b1b0_sigR', 'b1b0_sigS']

BLK1_KEY = BLK1_KEY_B1R + BLK1_KEY_B1CSK + BLK1_KEY_B1B0

BLK_SIGN_FMT = BLK0_FMT + BLK1_FMT
BLK_SIGN_KEY = BLK0_KEY + BLK1_KEY

# for nested dictionary
class ConfigDict(OrderedDict):
  """ define an ordered dictionary """
  def __missing__(self, key):
    val = self[key] = ConfigDict()
    return val


class PFR_CPLD(object):
  """ class for PFR cpld image operation and build and sign update capsule

  :param pfr_cfm1_rpd: pfr_cfm1_rpd file in compile output
  :param platform: reference platform name : ['wht', 'egs', 'bhs', 'idv', 'ksv'] or ['whitley', 'eaglestream', 'birchstream', 'idaville', 'kaseyville']
  :param svn: SVN number used in update capsule, default is 0
  :param csk_id: CSK ID, it is needed csk_id to do signature, default is 0

  """
  def __init__(self, pfr_cfm1_rpd, platform, svn= 0, csk_id=0):
    self.rpd_file = pfr_cfm1_rpd
    if platform == 'wht': plt = 'whitley'
    elif platform == 'egs': plt = 'eaglestream'
    elif platform == 'bhs': plt = 'birchstream'
    elif platform == 'idv': plt = 'idaville'
    elif platform == 'ksv': plt = 'kaseyville'
    else:
      plt = platform.replace(' ', '').lower()  # remove space and convert to lower case
    self.pltfrm = plt
    print("platform : ", self.pltfrm)
    if self.pltfrm not in ['whitley', 'eaglestream', 'birchstream', 'idaville', 'kaseyville']:
      raise ValueError

    self.rk_prv  = os.path.join(os.path.dirname(__file__), 'keys', self.pltfrm, 'key_root_prv.pem')
    self.csk_prv = os.path.join(os.path.dirname(__file__), 'keys', self.pltfrm,  'key_csk_prv.pem')
    self.svn = svn
    self.csk_id = csk_id
    self.unsigned_cap = 'temp_unsigned_cpld_cap_svn{}_cskid{}.bin'.format(self.svn, self.csk_id)
    self.signed_cap   = '{}_cpld_signed_cap_svn{}_cskid{}.bin'.format(self.pltfrm, self.svn, self.csk_id)


  def build_update_capsule(self):
    """ build signed update capsule based on pfr_cfm1_rpd file

    """
    try:
      rpd_f = open(self.rpd_file, 'rb')
    except IOError as e:
      print("File I/O error({0}): {1}".format(e.errno, e.strerror))
      raise

    convert = Convert()
    svn = convert.integer_to_bytes(self.svn, 4)

    stream = PFRBitstream()
    stream.initialize()
    stream.append(svn)
    stream.read(rpd_f)

    # swap the endianness of the bytes
    for i in range(4, stream.size(), 4):
      array = stream.get_raw_byte_array()
      array[i], array[i+1], array[i+2], array[i+3] = \
      array[i+3], array[i+2], array[i+1], array[i]

    #reverse the bit order of each byte because we need to do this before writing the RPD into CFM
    #skip svn in the first 4 bytes
    for i in range(4, stream.size()):
      stream.get_raw_byte_array()[i] = reverse_bits(stream.get_raw_byte_array()[i])

    output_f = open(self.unsigned_cap, 'wb')
    stream.write(output_f)

    rpd_f.close()
    output_f.close()

    # sign the 'temp_unsigned_cpld_cap.bin' file using reference key
    mycpld = sign.Signing(self.unsigned_cap, _CPLD_CAP_PCTYPE, self.csk_id, self.rk_prv, self.csk_prv)
    mycpld.set_signed_image(self.signed_cap)
    mycpld.sign()


class UpdateCapsule(object):
  """
  class for process of signed cpld update capsule, including:

    1) replace with customer generate key to sign
    2) build new update capsule with another CSK_ID
    3) build new update capsule with another SVN

  :param signed_image: signed cpld update capsule file name
  :param platform: reference platform name

  """
  def __init__(self, signed_image, platform):
    self.signed_image = signed_image
    self.cap_dict = ConfigDict()
    self.unsigned_cap = 'temp_unsigned_cap.bin'
    self.get_unsigned_cap()
    if platform == 'wht': plt = 'whitley'
    elif platform == 'egs': plt = 'eaglestream'
    elif platform == 'bhs': plt = 'birchstream'
    elif platform == 'idv': plt = 'idaville'
    elif platform == 'ksv': plt = 'kaseyville'
    else:
      plt = platform.replace(' ', '').lower()  # remove space and convert to lower case
    self.pltfrm = plt
    print("platform : ", self.pltfrm)
    if self.pltfrm not in ['whitley', 'eaglestream', 'birchstream']:
      raise ValueError
    self.rk_prv  = os.path.join(os.path.dirname(__file__), 'keys', self.pltfrm, 'key_root_prv.pem')
    self.csk_prv = os.path.join(os.path.dirname(__file__), 'keys', self.pltfrm,  'key_csk_prv.pem')


  def get_unsigned_cap(self, out_image=None):
    """ process a signed image
    """
    with open(self.signed_image, 'rb') as f:
      blk_data=f.read(0x400)
    s = struct.calcsize(BLK_SIGN_FMT)
    lst_temp = struct.unpack(BLK_SIGN_FMT, blk_data[0:s])
    for (k, v) in zip(BLK_SIGN_KEY, lst_temp):
      self.cap_dict[k] = v

    pc_len = self.cap_dict['pc_len']
    with open(self.signed_image, 'rb') as f, open(self.unsigned_cap, 'wb') as f1:
      f.seek(0x400)
      pc_content = f.read(pc_len)
      hash256 = utility.get_hash256(pc_content)
      hash384 = utility.get_hash384(pc_content)
      print(hash256, '--', self.cap_dict['hash256'].hex())
      print(hash384, '--', self.cap_dict['hash384'].hex())

      if (bytes.fromhex(hash256) == self.cap_dict['hash256']) or \
      (bytes.fromhex(hash384) == self.cap_dict['hash384']):
        f1.write(pc_content)
        self.pc_content = pc_content

    self.svn = struct.unpack('<I', pc_content[0:4])[0]
    self.csk_id = self.cap_dict['b1csk_keyid']
    if self.cap_dict['b1r_curve'] == 0x08F07B47:
      self.key_curve = 'NIST384p'
    elif self.cap_dict['b1r_curve'] == 0xC7B88C74:
      self.key_curve = 'NIST256p'


  def with_new_keys(self, rk_prv, csk_prv):
    """ generate new update capsule with new keys
    """
    # verify key curve first with existing capsule
    rk_prv_kurve = keys.get_curve(rk_prv)
    rk_prv_kurve = keys.get_curve(csk_prv)
    with open(rk_prv, 'rt') as f, open(csk_prv, 'rt') as f1:
      f_read, f1_read = f.read(), f1.read()
      if ('PUBLIC' in f_read) or ('PRIVATE' not in f_read):
        print("-- Error: wrong format of root private key !")
        raise ValueError
      if ('PUBLIC' in f1_read) or ('PRIVATE' not in f1_read):
        print("-- Error: wrong format of csk private key !")
        raise ValueError
    rk_curve  = keys.get_curve(rk_prv)
    csk_curve = keys.get_curve(csk_prv)
    if (rk_curve != self.key_curve) or (csk_curve != self.key_curve):
      print("-- Error: wrong format of sign keys")
      raise ValueError

    """
    self.cap_dict['b1r_curve'] == 0xC7B88C74 #for secp256r1
    self.cap_dict['b1r_curve'] == 0x08F07B47 #for secp384r1
    self.cap_dict['b1csk_curve'] == 0xC7B88C74 #for secp256
    self.cap_dict['b1csk_curve'] == 0x08F07B47 #for secp384r1
    """
    self.rk_prv  = rk_prv
    self.csk_prv = csk_prv


  def with_new_svn(self, new_svn):
    """ generate new update capsule with new SVN
    """
    self.svn = new_svn

  def with_new_cskid(self, new_csk_id):
    """ generate new update capsule with new CSK ID
    """
    self.csk_id = new_csk_id


  def rebuild_capsule(self):
    """ rebuild capsule """
    self.signed_cap = 'cpld_signed_cap_updated_svn_svn{}_cskid{}.bin'.format(self.svn, self.csk_id)
    new_svn_bytes=(self.svn).to_bytes(4, 'little')
    with open(self.unsigned_cap, 'wb') as f:
      f.write(new_svn_bytes)
      f.write(self.pc_content[4:])

    mycpld = sign.Signing(self.unsigned_cap, _CPLD_CAP_PCTYPE, self.csk_id, self.rk_prv, self.csk_prv)
    mycpld.set_signed_image(self.signed_cap)
    mycpld.sign()


def reverse_bits(byte):
  """
  Reverse bits of a byte reversed byte[7:0] -> byte[0:7]

  :params: byte from 0x00 - 0xFF
  :return: reversed bits value of byte

  takes a single byte and returns a that byte reversed byte[7:0] -> byte[0:7]

  a = int.from_bytes(byte, "big") # convert to integer
  n = int('{:08b}'.format(a)[::-1], 2)
  r = n.to_bytes(1, 'big')

  """
  byte = (byte & 0xAA)>>1 | (byte & 0x55)<<1
  byte = (byte & 0xCC)>>2 | (byte & 0x33)<<2
  byte = (byte & 0xF0)>>4 | (byte & 0x0F)<<4
  return byte

class Convert(object):
  """
  format conversion utility methods
    - little endian byte order is always assumed.
  """
  def bytearray_to_hex_string(self, byte_array, offset=0, num_of_bytes=None, endianness='little'):
    """
     bytearray_to_hex_string(bytearray([0xA,0xB,0xC,0xD])), "0xD0C0B0A"
    """
    if num_of_bytes is None:
      num_of_bytes = len(byte_array) - offset

    hex_string_list = []
    ba = byte_array[offset:offset+num_of_bytes]
    if endianness != 'big': ba = ba[::-1]

    for byte in ba:
      hex_string_list.append( "%02X" % byte )

    hex_string = "0x" + ''.join( hex_string_list ).strip()

    # remove leading zeros
    hex_string = re.sub(r'0x[0]*', '0x', hex_string)

    if hex_string == "0x":
      hex_string = "0x0"

    return hex_string

  def hex_string_to_bytes(self, hex_string, num_of_bytes=None, endianness='little'):
    """ convert hexstring to bytes """
    if hex_string[0:2] == '0x':
      hex_string = hex_string[2:]

    hex_string = '0'*(len(hex_string) % 2) + hex_string
    num_hex_bytes = len(hex_string)//2
    if num_of_bytes is None:
      num_of_bytes = num_hex_bytes
    if num_of_bytes < num_hex_bytes:
      raise BufferError("Cannot fit hex string into specified num_of_bytes")

    hex_string = '00'*(num_of_bytes-num_hex_bytes) + hex_string

    ret = bytearray(num_of_bytes)
    for i in range(0, len(hex_string), 2):
      val = int(hex_string[i:i+2], 16)
      offset = i//2
      if endianness != 'big':
        offset = -(1+offset)  # Move backwards instead of forwards
      ret[offset] = val

    return ret

  def bytearray_to_integer(self, byte_array, offset=0, num_of_bytes=None, endianness='little'):
    """ byte bytearray to integer """
    if len(byte_array) == 0:
      return 0

    if num_of_bytes is None:
      num_of_bytes = len(byte_array) - offset

    byte_array = byte_array[offset:offset+num_of_bytes]
    if endianness != 'big': byte_array = byte_array[::-1]

    return int(binascii.hexlify(byte_array), base=16)

  def integer_to_bytes(self, n, length, endianness='little'):
    """ integer to bytes """
    h = '%02x'%int(n)
    s = codecs.decode(('0'*(len(h) % 2) + h).zfill(length*2),'hex')
    ba = bytearray(s)
    if endianness != 'big':
      ba = ba[::-1]
    if len(ba) > length:
      ba = ba[0:length]
    return ba

  def swap32(self, i):
    """ swap double words

      0x12345678 --> 0x78563412
    """
    return struct.unpack("<I", struct.pack(">I", i))[0]


class PFRBitstream(object):
  """
  This is a class that represents an arbitrary bit-stream used in PFR collateral.
  """
  def __init__(self):
    PFRBitstream.initialize(self, byte_array=None)

  def initialize(self, byte_array=None, size=0):
    """
    Initialize an PFRBitstream instance so that it can pass validate().
    This function is not meant to be run after read().
    """
    if byte_array is None:
      self.__raw = bytearray([0xFF] * size)
    elif size != 0:
      raise ValueError("size attribute to initialize method if only valid if byte_array not specified")
    else:
      self.__raw = byte_array

  def size(self):
    return len(self.__raw)

  def append(self, byte_array=None, size=0):
    if byte_array is None:
      if size <= 0:
        raise ValueError('size attribute to append method is <= 0')
      else:
        self.__raw += bytearray([0]*size)
    elif size != 0:
      raise ValueError('size attribute to initialize method if only valid if byte_array not specified')
    else:
      self.__raw += byte_array

  def validate(self):
    return True

  def update(self):
    pass

  def get_raw_byte_array(self):
    return self.__raw

  def get_raw_value(self, offset, size, endianness='little'):
    assert (offset + size <= self.size())
    raw_byte_array = self.get_raw_byte_array()

    if endianness == 'big':
      return raw_byte_array[offset:offset + size][::-1]
    else:
      return raw_byte_array[offset:offset + size]

  def get_value(self, offset, size=4, endianness='little'):
    return Convert().bytearray_to_integer(self.get_raw_value(offset=offset, size=size, endianness=endianness))

  def set_raw_value(self, byte_array, offset, endianness='little'):
    sz = len(byte_array)
    assert (offset + sz <= self.size())

    if endianness == 'big':
      self.__raw[offset:offset + sz] = byte_array[0:sz][::-1]
    else:
      self.__raw[offset:offset + sz] = byte_array[0:sz]

  def set_value(self, value, offset, size=4, endianness='little'):
    ba = Convert().integer_to_bytes(n=value, length=size)
    assert (len(ba) == size)
    self.set_raw_value(byte_array=ba, offset=offset, endianness=endianness)

  def write(self, fp):
    self.validate()
    fp.write(self.get_raw_byte_array())

  def read(self, fp):
    if fp.closed:
      return
    self.append(byte_array=bytearray(fp.read()))



def main(args):
  """ pfr cpld capsule in command line

    build new update capsule from pfr_cfm1_auto.rpd file, or modify existing capsule with new SVN, new csk id or sign with new keys

    Usage in Command Prompt::

      >python -m intelprot.cpld -h
      >python -m intelprot.cpld build_capsule  -h
      >python -m intelprot.cpld modify_capsule -h

  """
  parser = argparse.ArgumentParser(description="-- Pfr CPLD update capsule utility ")

  subparser = parser.add_subparsers(dest='action')
  cmdcap = subparser.add_parser('build_capsule', description="build pfr update capsule from pfr_cfm1_auto.rpd file")
  cmdcap.add_argument('-rpd', '--rpd_file',   metavar="[compile output CFM1 rpt file]", dest='rpd',   help='compile output pfr_cfm1_auto.rpd')
  cmdcap.add_argument('-plt', '--platform',   metavar="[reference platform]", dest='plt',   help='reference platform: select one in [\"wht\", \"egs\", \"bhs\"]')
  cmdcap.add_argument('-svn', '--svn_num',  metavar="[svn number]",  dest= 'svn', default = 0, help='SVN in update capsule for anti-roll back, default is 0')
  cmdcap.add_argument('-cskid', '--csk_id',  metavar="[csk id number]",  dest= 'csk_id', default = 0, help='csk id number 0-127, default is 0')

  cmdcap1 = subparser.add_parser('modify_capsule', description="modify existing capsule with new SVN, with new CSK_ID, or with new keys")
  cmdcap1.add_argument('-cap', '--update_cap_file', metavar="[signed cpld update capsule]", dest='scap',   help='signed cpld update capsule file released in BKC')
  cmdcap1.add_argument('-plt', '--platform',   metavar="[reference platform]", dest='plt', \
        help='reference platform, need it load reference keys, select one in ["wht\", \"egs\", \"bhs\"]')

  cmdcap1.add_argument('-cskid', '--new csk_id',   metavar="[new csk id number]",  dest= 'csk_id', default=None, help='csk id number 0-127, default is no change')
  cmdcap1.add_argument('-svn',   '--new svn_num',  metavar="[new svn number]",  dest= 'svn', default=None, help='SVN in update capsule for anti-roll back, default is no change')
  cmdcap1.add_argument('-rk',  '--root_private',   metavar="[root private key]", default=None, dest= 'rk_prv',  help='root private key in pem format, default is no change')
  cmdcap1.add_argument('-csk', '--csk_private',    metavar="[csk private key]",  default=None, dest= 'csk_prv', help='csk private key in pem format, default is no change')

  args = parser.parse_args(args)
  print(args)

  if args.action =="build_capsule":
    print('-- build cpld update capsule from {} file'.format(args.rpd))
    newcap=PFR_CPLD(args.rpd, args.plt, args.svn, args.csk_id)
    newcap.build_update_capsule()

  if args.action =="modify_capsule":
    print('-- modify cpld update capsule from {} file'.format(args.scap))
    capobj = UpdateCapsule(args.scap, args.plt)
    if args.csk_id != None: capobj.with_new_cskid(int(args.csk_id, 0))
    if args.svn != None: capobj.with_new_svn(int(args.svn, 0))
    if args.rk_prv != None and args.csk_prv != None: capobj.with_new_keys(args.rk_prv, args.csk_prv)
    # rebuild capsule
    capobj.rebuild_capsule()

if __name__ == '__main__':
  main(sys.argv[1:])
