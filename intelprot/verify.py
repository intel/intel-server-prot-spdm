#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PFR verification module

"""
  This module is to verify pfr ifwi and BMC image.
  It also supports pfr image analysis and verification.

"""
from __future__ import print_function
from __future__ import division

__author__    = "Scott Huang (scott.huang@intel.com)"

import hashlib, struct, argparse, sys, os, re
import xml.etree.ElementTree as ET
from collections import OrderedDict
from operator import itemgetter
from intelprot import keys, pfm, ifwi, bmc

import logging
logger = logging.getLogger(__name__)

BLK0_MAGIC     = 0xB6EAFD19
BLK1_MAGIC     = 0xF27F28D7
BLK1_RK_MAGIC  = 0xA757A046
BLK1_CSK_MAGIC = 0x14711C2F
BLK1_B0_MAGIC  = 0x15364367
BLK1_CMAGIC_2  = 0xC7B88C74
BLK1_CMAGIC_3  = 0x08F07B47
BLK1_SMAGIC_2  = 0xDE64437D
BLK1_SMAGIC_3  = 0xEA2A50E9

BLOCK_MAGIC_PFR_2  = (0xB6EAFD19, 0xF27F28D7, 0xA757A046, 0xC7B88C74, 0x14711C2F, 0xC7B88C74, 0xDE64437D, 0x15364367, 0xDE64437D)
BLOCK_MAGIC_PFR_3  = (0xB6EAFD19, 0xF27F28D7, 0xA757A046, 0x08F07B47, 0x14711C2F, 0x08F07B47, 0xEA2A50E9, 0x15364367, 0xEA2A50E9)

BLOCK_FMT = '<IIII32s48s32sI12sIIII48s48s20sIIII48s48s20sI48s48sII48s48s412s'
BLOCK_KEY = ('b0_tag', 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384', 'b0_pad', \
          'b1_tag', 'b1_rsvd', \
          'b1r_tag', 'b1r_cur', 'b1r_per', 'b1r_keyid', 'b1r_x', 'b1r_y', 'b1r_rsvd', \
          'b1c_tag', 'b1c_cur', 'b1c_per', 'b1c_keyid', 'b1c_x', 'b1c_y', 'b1c_rsvd', 'b1c_sig', 'b1c_sigR', 'b1c_sigS', \
          'b1b_tag', 'b1b_sig', 'b1b_sigR', 'b1b_sigS', \
          'b1_pad')

BLOCK0_SIZE   = 128
CSKSIGN_START = 280
CSKSIGN_SIZE  = 128
BLOCK_SIZE    = 1024


# for nested dictionary
class ConfigDict(OrderedDict):
  """ define an ordered dictionary """
  def __missing__(self, key):
    val = self[key] = ConfigDict()
    return val

class PFM_signed(object):
  """ verification class for PFR PFM signed image file or binary data

  :param signed_image_bdata: signed pfm image file or binary data bytes
  :param pfr_ver: PFR version 2.0 or 3.0
  :param rk_prv_pem: root private key in PEM format
  :param csk_prv_pem: csk private key in PEM format

  """
  def __init__(self, signed_image_bdata, pfr_ver, rk_prv_pem, csk_prv_pem):
    if isinstance(signed_image_bdata, (bytes, bytearray)):
      self.bdata = signed_image_bdata
    else:
      with open(signed_image_bdata, 'rb') as f:
        self.bdata = f.read()
    self.pfr_version = pfr_ver
    self.rk_prv  = rk_prv_pem
    self.csk_prv = csk_prv_pem
    self.blk_data = self.bdata[0:BLOCK_SIZE]
    self.pc_data = self.bdata[BLOCK_SIZE:]

  def validate(self):
    self.block = BLOCK(self.blk_data, self.pc_data, self.pfr_version, self.rk_prv, self.csk_prv)
    result = self.block.validate()
    logger.info("-- PASS") if result else logger.info("-- FAIL")


class Verify_PFM(object):
  """ verification class of unsigned PFM image file or binary data

  :param image_bdata:  unsigned pfm image file or data bytes

  """
  def __init__(self, image_bdata):
    self.pfmobj = pfm.PFM(image_bdata)

  def validate(self):
    """ validate PFM setting in unsigned pfm image (or binary data) against its active pfr image (or binary data) """
    self.pfmobj.show_spi()
    self.pfmobj.show_smb()
    # verify no undefined gap in PFM SPI region
    self.show_spi_lst = self.pfmobj.show_spi_lst
    lst_region= []
    for i in self.show_spi_lst:
       lst_region.append((int(i[3], 0), int(i[4], 0), i[-1]))
    lst_region_sorted = sorted(lst_region, key=itemgetter(0))
    rtn = True
    pre_end = 0x0
    logger.info("-- lst_spi_region_sorted:")
    for i in lst_region_sorted:
      logger.info("**** 0x{:08x} --> 0x{:08x}".format(i[0], i[1]))
      rtn &= (i[0] == pre_end)
      pre_end = i[1]
    logger.info('pre_end: 0x{:08x}'.format(pre_end))
    # check 64MB, 128MB, and 256MB image size
    rtn &= (pre_end == 0x04000000) or (pre_end == 0x08000000) or (pre_end == 0x10000000)
    return rtn

class Capsule_signed(object):
  """ PFR Capsule verification class """
  def __init__(self, signedcap_image_bdata, pfr_ver, rk_prv_pem, csk_prv_pem):
    if isinstance(signedcap_image_bdata, (bytes, bytearray)):
      self.bdata = signedcap_image_bdata
    else:
      with open(signedcap_image_bdata, 'rb') as f:
        self.bdata = f.read()
    self.pfr_version = pfr_ver
    self.rk_prv  = rk_prv_pem
    self.csk_prv = csk_prv_pem
    self.blk_data = self.bdata[0:BLOCK_SIZE]
    self.unisgned_cap_data = self.bdata[BLOCK_SIZE:]
    self.pc_data = self.bdata[BLOCK_SIZE:]

  def validate(self):
    """ verify the signature """
    self.block = BLOCK(self.blk_data, self.pc_data, self.pfr_version, self.rk_prv, self.csk_prv)
    self.unsigned_cap = Capsule_unsigned(self.unisgned_cap_data, self.pfr_version, self.rk_prv, self.csk_prv)
    rtn = (self.block).validate()
    logger.info('validate block: ', rtn)
    rtn &= (self.unsigned_cap).validate()
    return rtn


class Capsule_unsigned(object):
  """ PFR Capsule verification class """
  def __init__(self, cap_image_bdata, pfr_ver, rk_prv_pem, csk_prv_pem):
    if isinstance(cap_image_bdata, (bytes, bytearray)):
      self.bdata = cap_image_bdata
    else:
      with open(cap_image_bdata, 'rb') as f:
        self.bdata = f.read()
    self.pfr_version = pfr_ver
    self.rk_prv   = rk_prv_pem
    self.csk_prv  = csk_prv_pem
    self.blk_data = self.bdata[0:BLOCK_SIZE]
    self.pc_len, self.pc_type = struct.unpack('<II', self.bdata[4:12])
    self.pc_data  = self.bdata[BLOCK_SIZE:(BLOCK_SIZE + self.pc_len)]

  def validate(self):
    """ verify the signature """
    self.block = BLOCK(self.blk_data, self.pc_data, self.pfr_version, self.rk_prv, self.csk_prv)
    result = self.block.validate()
    logger.info("-- validation result:", result)
    return result


class PFR_IFWI(object):
  """ PFR IFWI verification class

  if optional root key (either private or public) and csk private key are provided
  validate functino will validate the signature.

  If no key provided, it will skip signature validation.

  :param ifwi_image: PFR IFWI image.
  :param rk_key: root key, either private or public key in PEM format, optional
  :param csk_prv: CSK private key in PEM format, optional

  """
  def __init__(self, ifwi_image, rk_key=None, csk_prv=None, logfile=None):
    self.image = ifwi_image
    self.rk_key  = rk_key
    self.csk_prv = csk_prv
    self.logfile = logfile
    if self.logfile != None:
      logging.getLogger().handlers = []

  def validate(self):
    """ Verify PFR compliant IFWI image

    Validate items::

    #. verify pfm spi region has no undefined gap
    #. verify pfm spi hash data matches with calculation
    #. verify public key hash in provisioned in BIOS
    #. verify block signed signature in capsule

    """
    if not logging.getLogger().hasHandlers():
      if self.logfile:
        logging.basicConfig(level=logging.DEBUG,
              handlers= [logging.FileHandler(self.logfile, mode='w'),logging.StreamHandler()])
      else:
        logging.basicConfig(level=logging.DEBUG, handlers= [logging.StreamHandler()])
    #else:
    #  logger = logging.getLogger(__name__)

    self.prov = ifwi.Agent(self.image)
    self.prov.get_prov_data()
    act, rcv = int(self.prov._pfrs['ifwi_active'], 0), int(self.prov._pfrs['ifwi_recovery'], 0)
    logger.info("act = 0x{:08x}, rcv = 0x{:08x}".format(act, rcv))
    with open(self.image, 'rb') as f:
      f.seek(act)
      pfm_act = f.read(64*1024)
      f.seek(rcv)
      pfm_rcv = f.read(16*1024*1024)

    actpfmobj = Verify_PFM(pfm_act)
    rcvpfmobj = Verify_PFM(pfm_rcv)
    rtn  = actpfmobj.validate()
    rtn &= rcvpfmobj.validate()

    # verify active pfm hash data
    lst_hash=[]
    for i in actpfmobj.show_spi_lst:
      if i[2] != 0:
        lst_hash.append((int(i[3], 0), int(i[4], 0), i[-1]))
    verify_hash = True
    with open(self.image, 'rb') as f:
      for i in lst_hash:
        hashd = ''
        f.seek(i[0])
        bdata = f.read(i[1]-i[0])
        if len(i[2]) == 48*2:
          hashd = hashlib.sha384(bdata).hexdigest()
        elif len(i[2]) == 32*2:
          hashd = hashlib.sha256(bdata).hexdigest()
        else:
          print(len(i[2]))
          verify_hash = False
        #print('0x{:08x} - 0x{:08x} -- hash: {}, calc_hash:{}'.format(i[0], i[1], i[2], hashd))
        verify_hash &= (hashd == i[2])
    rtn &= verify_hash

    # verify root public key hash provisioning
    if self.rk_key is not None:
      self.calc_rkhash = keys.get_rk_hashbuffer(self.rk_key)
      self.keym_rkhash = self.prov._keym['keyhash_buffer2']
      logger.info('calc_rkhash: {}'.format(self.calc_rkhash))
      logger.info('keym_rkhash: {}'.format(self.keym_rkhash))
      rtn &= (self.calc_rkhash == self.keym_rkhash)

    # verify signature
    if self.rk_key is not None and self.csk_prv is not None:
      verify_sign = True
      verify_sign &= BLOCK_1K_Signed(pfm_act, self.rk_key, self.csk_prv).validate()
      verify_sign &= BLOCK_1K_Signed(pfm_rcv, self.rk_key, self.csk_prv).validate()
      rtn &= verify_sign

    return rtn


class PFR_BMC(object):
  """ PFR BMC FW verification class

    if optional root key (either private or public) and csk private key are provided
    validate functino will validate the signature.
    If no key provided, it will skip signature validation.
    staging image need validate separately.

  :param ifwi_image: PFR IFWI image.
  :param rk_key: root key, either private or public key in PEM format, optional
  :param csk_prv: CSK private key in PEM format, optional
  :param logfile: logfile name, optional

  """
  def __init__(self, bmc_image, rk_key=None, csk_prv=None, logfile=None):
    self.image = bmc_image
    self.rk_key  = rk_key
    self.csk_prv = csk_prv
    if logfile != None:
      self.logfile = logfile
      logging.getLogger().handlers=[]

  def validate(self):
    """ verify PFR BMC image

    This function will search active and recovery PFM offset from PFR BMC image

    Validate items::

    #. verify pfm spi region
    #. verify pfm hash data
    #. verify AFM capsule if included
    #. verify signature if key is provided

    """
    if not logging.getLogger().hasHandlers():
      if self.logfile:
        logging.basicConfig(level=logging.DEBUG,
              handlers= [logging.FileHandler(self.logfile, mode='w'),logging.StreamHandler()])
      else:
        logging.basicConfig(level=logging.DEBUG, handlers= [logging.StreamHandler()])

    with open(self.image, 'rb') as f:
      self.bdata = f.read()

    st_tag = pfm.PFM_MAGIC
    st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
    lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), self.bdata)]
    #[print('0x{:08x}'.format(int(i, 0))) for i in lst_addr]
    act_addr = int(lst_addr[0], 0)  #0x00080400
    rcv_addr = int(lst_addr[1], 0)  #0x02a00800

    with open(self.image, 'rb') as f:
      f.seek(act_addr)
      act_pfm = f.read(64*1024)
      f.seek(rcv_addr)
      rcv_pfm = f.read(64*1024)

    actpfmobj = Verify_PFM(act_pfm)
    rcvpfmobj = Verify_PFM(rcv_pfm)
    rtn1 = actpfmobj.validate()
    rtn2 = rcvpfmobj.validate()
    logger.info("actpfmobj.validate:{}, rcvpfmobj.validate:{}".format(rtn1, rtn2))
    rtn = rtn1 & rtn2

    st_tag = AFM_MAGIC
    st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
    lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), self.bdata)]

    # if AFM is included
    if len(lst_addr) != 0:
      with open(self.image, 'rb') as f:
        f.seek(0x07E00000)
        self.act_afm = f.read(128*1024)
        f.seek(0x07E20000)
        self.rcv_afm = f.read(128*1024)
      actafmobj = Verify_AFM(self.act_afm, self.rk_key, self.csk_prv, self.logfile)
      rtn &= actafmobj.validate()
      rcvafmobj = Verify_AFM(self.rcv_afm, self.rk_key, self.csk_prv, self.logfile)
      rtn &= rcvafmobj.validate()

    return rtn


AFM_MAGIC = 0x8883CE1D
AFM_STUCT_FMT = "<IBBH16sI"
AFM_STUCT_KEY = ('tag', 'svn', 'rsvd', 'revision', 'oem_data', 'header_size')
AFM_HEADER_FMT = "<BBHII"
AFM_HEADER_KEY = ('spi_type', 'dev_addr', 'dev_uuid', 'length', 'fw_addr')
DEVICE_HEADER_SIZE = 0xC

AFM_DEV_FMT = "<HBBBHBBBHIHH20s512s4sI"
AFM_DEV_KEY = ('uuid', 'busid', 'devaddr', 'bindingspec', 'bsversion', 'policy', 'svn', 'rsvd1', 'afmversion', 'curvemagic', \
'manfstr', 'manfid', 'rsvd2', 'pubkeyxy', 'pubkeyexp', 'totalmea')

class Verify_AFM(object):
  """ class for AFM verification

  Decode AFM capsule to a json file, and also verify the format and signature
  if AFM TAG offset is 0x400, it is active AFM
  if AFM_TAG offset is 0x800, it is recover/staging capsule

  :param afm_cap: AFM active, or recovery/staging capsule, either binary data or binary file.
  :param rk_key: root key, either private or public key. If external signing, root public key is used
  :param csk_prv: CSK private key

  """
  def __init__(self, afm_cap, rk_key, csk_prv, logfile=None):
    self.pfr_ver = keys.get_pfr_version(rk_key)
    self.rk_key  = rk_key
    self.csk_prv = csk_prv
    if logfile != None:
      self.logfile = logfile

    if isinstance(afm_cap, str):
      if os.path.isfile(afm_cap):
        self.bsize = os.stat(afm_cap).st_size
        with open(afm_cap, 'rb') as f:
          self.bdata = f.read()
    elif isinstance(afm_cap, (bytes, bytearray)):
      self.bdata = afm_cap
      self.bsize = len(self.bdata)
    else:
      logger.critical("Error: wrong argment {}, eith binary file or binary data".format(afm_cap))
    self.afm_dict = ConfigDict()  # empty dictionary

    t = struct.unpack("<I", self.bdata[0x400:0x404])[0]
    #print("afm Tag: {:X}".format(t))

    if t == AFM_MAGIC:
      self.afm_type = 'active_afm'
      self.afm_tag_offset = 0x400
    elif t == BLK0_MAGIC:
      self.afm_type = 'recv_stag_afm'
      self.afm_tag_offset = 0x800
    else:
      logger.critical("Error: wrong format !")

    # scan afm struct/header
    lst_temp = struct.unpack(AFM_STUCT_FMT, self.bdata[self.afm_tag_offset: self.afm_tag_offset+struct.calcsize(AFM_STUCT_FMT)])
    for (k, v) in zip(AFM_STUCT_KEY, lst_temp):
      self.afm_dict[k] = v

    total_header_size = lst_temp[-1]
    #print("Total AFM Header Size: 0x{:X}".format(total_header_size))
    self.dev_num = int(total_header_size/DEVICE_HEADER_SIZE)
    for i in range(0, self.dev_num):
      lst_devhdr=struct.unpack(AFM_HEADER_FMT, self.bdata[(self.afm_tag_offset+struct.calcsize(AFM_STUCT_FMT)+i*0xC): (self.afm_tag_offset+struct.calcsize(AFM_STUCT_FMT)+(i+1)*0xC)])
      #print(lst_devhdr)
      for (k, v) in zip(AFM_HEADER_KEY, lst_devhdr):
        self.afm_dict["dev{}".format(i)][k] = v

    st_addr = self.afm_tag_offset
    for i in range(0, self.dev_num):
      st_addr += self.afm_dict['dev{}'.format(i)]['length']
      self.afm_dict['dev{}'.format(i)]['start_offset'] = st_addr
      lst_dev = struct.unpack(AFM_DEV_FMT, self.bdata[st_addr:st_addr+struct.calcsize(AFM_DEV_FMT)])
      for (k, v) in zip(AFM_DEV_KEY, lst_dev):
        self.afm_dict['dev{}'.format(i)][k] = v

    self.lst_dev_uuid, self.lst_dev_addr = [], []
    for i in range(0, self.dev_num):
      self.lst_dev_uuid.append(self.afm_dict['dev{}'.format(i)]['dev_uuid'])
      self.lst_dev_addr.append(self.afm_dict['dev{}'.format(i)]['dev_addr'])


  def validate_afm_struct_header(self):
    """ validate afm header """
    start_offset = self.afm_tag_offset - 0x400
    rtn  = self.afm_dict['tag'] == AFM_MAGIC
    rtn &= self.afm_dict['svn'] <= 64
    rtn &= self.afm_dict['header_size'] % 12 == 0

    for i in range(0, self.dev_num):
      rtn &= self.afm_dict['dev{}'.format(i)]['spi_type'] == 3
      rtn &= self.afm_dict['dev{}'.format(i)]['length'] % 0x1000 == 0
      rtn &= (self.afm_dict['dev{}'.format(i)]['fw_addr'] - 0x07e00000) % 0x1000 == 0

    if self.dev_num > 1:
      for i in range(1, self.dev_num):
        rtn &= self.afm_dict['dev{}'.format(i)]['fw_addr'] > self.afm_dict['dev{}'.format(i-1)]['fw_addr']
        rtn &= (self.afm_dict['dev{}'.format(i)]['fw_addr'] - self.afm_dict['dev{}'.format(i-1)]['fw_addr']) %0x1000 == 0

    pc_type = struct.unpack('<I', self.bdata[(start_offset + 8):(start_offset + 12)])[0]
    rtn &= pc_type == 0x6
    obj = BLOCK_1K_Signed(self.bdata[start_offset:], self.rk_key, self.csk_prv)
    rtn &= obj.validate()
    result = "PASS" if rtn else "Fail"
    logger.info("-- verify afm_struct_header: {}".format(result))
    return rtn


  def validate_afm_device(self, idx):
    """ validate afm single device

    This validation only check format. It does not include measurement data and SPDM protocol
    """
    start_offset = self.afm_dict['dev{}'.format(idx)]['start_offset']
    rtn = BLOCK_1K_Signed(self.bdata[(start_offset-0x400):], self.rk_key, self.csk_prv).validate()

    pc_type = struct.unpack('<I', self.bdata[(start_offset-0x400) + 8:(start_offset-0x400) + 12])[0]
    rtn &= pc_type == 0x6
    #rtn &= self.lst_dev_addr.count(self.afm_dict['dev{}'.format(idx)]['dev_addr']) == 1
    rtn &= self.lst_dev_uuid.count(self.afm_dict['dev{}'.format(idx)]['dev_uuid']) == 1
    result = "PASS" if rtn else "Fail"
    logger.info("-- verify afm_device {} : {}".format(idx, result))
    return rtn


  def validate(self):
    """ verify AFM capsule """
    # verify signature
    rtn  = BLOCK_1K_Signed(self.bdata, self.rk_key, self.csk_prv).validate()
    logger.info("1-RTN:{}".format(rtn))
    """
    print("\nAFM Type: {}\n".format(self.afm_type))
    print("afm_struct:")
    for k in AFM_STUCT_KEY:
      print(k, self.afm_dict[k])
    print("\nAFM_DEV_NUM: {}".format(self.dev_num))
    for i in range(0, self.dev_num):
      print("afm_devive: {}".format(i))
      for k in AFM_HEADER_KEY:
        print(k, self.afm_dict['dev{}'.format(i)][k])
    """
    rtn &= self.validate_afm_struct_header()
    for i in range(0, self.dev_num):
      rtn &= self.validate_afm_device(i)
    result = "PASS" if rtn else "Fail"
    logger.info("-- verify afm capsule : {}".format(result))
    return rtn


class BLOCK_1K_Signed(object):
  """ Class for 1K (1024 Bytes) Block Signed Data Verification

  A generic class to verify all kinds of 1024 Bytes Block signed data verification
  The Hash algorithm is based on the private key curves
  The protect content starts from offset 1024 with protect content length padding to mutiple of 128B

  The root key param takes either private or public key in PEM format.
  When in external signing, the root private key is not visiable to CSK owner, in this case, use root public key

  :param block_signed_data_file: block signed data or file name.
  :param rk_key: root private key (regular signed) or root public key (for external sign)
  :param csk_prv: CSK private key

  """
  def __init__(self, blk_signed_data_file, rk_key, csk_prv, logfile=None):
    self.pfr_ver = keys.get_pfr_version(rk_key)
    if logfile != None:
      self.logfile = logfile
    if isinstance(blk_signed_data_file, (bytes, bytearray)):
      self.bdata = blk_signed_data_file
      self.bsize = len(self.bdata)
    elif os.path.isfile(blk_signed_data_file):
      print("isfile ")
      self.bsize = os.stat(blk_signed_data_file).st_size
      with open(blk_signed_data_file, 'rb') as f:
        self.bdata = f.read()
    elif isinstance(blk_signed_data_file, (bytes, bytearray)):
      self.bdata = blk_signed_data_file
      self.bsize = len(self.bdata)
    else:
      logger.error("Error: wrong argment {}, eith binary file or binary data".format(blk_signed_data_file))

    self.blk_data = self.bdata[0:BLOCK_SIZE]  # 1024 bytes, first 0x400 bytes
    #if len(blk_data) != BLOCK_SIZE :
    #  print('Error: block data size not match')
    self.blk0_data   = self.blk_data[0:BLOCK0_SIZE]
    self.csksig_data = self.blk_data[CSKSIGN_START:(CSKSIGN_START+CSKSIGN_SIZE)]
    self.pc_data = self.bdata[BLOCK_SIZE:]
    self.rk_key  = rk_key
    self.csk_prv = csk_prv
    self.blk_dict= ConfigDict()
    lst_temp = struct.unpack(BLOCK_FMT, self.blk_data)
    for (k, v) in zip(BLOCK_KEY, lst_temp):
      #print(k, ' = ', v)
      self.blk_dict[k] = v

  def verify_pc_hash(self):
    """ verify protected data hash """
    pclen = self.blk_dict['b0_pclen']
    hash256 = hashlib.sha256(self.pc_data[0:pclen]).hexdigest()
    hash384 = hashlib.sha384(self.pc_data[0:pclen]).hexdigest()
    logger.info('hash256 : block0.hash256 {:s}'.format(self.blk_dict['b0_hash256'].hex()))
    logger.info('hash256 : pcdata.hash256 {:s}'.format(hash256))
    logger.info('hash384 : block0.hash384 {:s}'.format(self.blk_dict['b0_hash384'].hex()))
    logger.info('hash384 : pcdata.hash384 {:s}'.format(hash384))
    #rtn = True if ((self.blk_dict['b0_hash256'].hex() == hash256) and (self.blk_dict['b0_hash384'].hex() == hash384)) else False
    # skip b0_hash256 for PFR3.0
    rtn = True if (self.blk_dict['b0_hash384'].hex() == hash384) else False
    logger.error('FAIL -- verify_pc_hash error') if (not rtn) else logger.info('PASS -- verify_pc_hash')
    return rtn

  def verify_magic(self):
    lst_magic = (self.blk_dict['b0_tag'], self.blk_dict['b1_tag'], \
                 self.blk_dict['b1r_tag'], self.blk_dict['b1r_cur'], \
                 self.blk_dict['b1c_tag'], self.blk_dict['b1c_cur'], self.blk_dict['b1c_sig'],
                 self.blk_dict['b1b_tag'], self.blk_dict['b1b_sig'] )
    rtn  = (int(self.pfr_ver) == 2) and (lst_magic == BLOCK_MAGIC_PFR_2)
    rtn |= (int(self.pfr_ver) == 3) and (lst_magic == BLOCK_MAGIC_PFR_3)
    logger.info('-- FAIL: verify Magic') if (not rtn) else logger.info('PASS: verify Magic')
    return rtn

  def verify_pubkey_xy(self):
    """ verify root public key component X and Y """
    if keys.get_eckey_type(self.rk_key) == 'private':
      rkobj = keys.PrivateKey().read_from_pem(self.rk_key)
    if keys.get_eckey_type(self.rk_key) == 'public':
      rkobj = keys.PublicKey().read_from_pem(self.rk_key)
    self.rkpubX,  self.rkpubY = rkobj.get_pubkey_xy()

    cskobj = keys.PrivateKey().read_from_pem(self.csk_prv)
    self.cskpubX,  self.cskpubY = cskobj.get_pubkey_xy()

    logger.info('calculated: \n rkpubX = {:s}, \n rkpubY = {:s}'.format(self.rkpubX.hex(), self.rkpubY.hex()))
    logger.info('\n from image: \n rkpubx = {:s}, \n rkpuby = {:s}'.format(self.blk_dict['b1r_x'].hex(), self.blk_dict['b1r_y'].hex()))
    logger.info('calculated: \n cskpubX = {:s}, \n cskpubY = {:s}'.format(self.cskpubX.hex(), self.cskpubY.hex()))
    logger.info('\n from image: \n cskpubx = {:s}, \n cskpuby = {:s}'.format(self.blk_dict['b1c_x'].hex(), self.blk_dict['b1c_y'].hex()))
    rtn = (self.rkpubX == self.blk_dict['b1r_x']) and (self.rkpubY == self.blk_dict['b1r_y'])
    rtn &= (self.cskpubX == self.blk_dict['b1c_x']) and (self.cskpubY == self.blk_dict['b1c_y'])
    logger.info('-- FAIL: verify public key X, Y') if (not rtn) else logger.info('PASS: verify public key X, Y')
    return rtn

  def verify_signature(self):
    """ verify signature

    if root public key is provided, root key owner generate the signature for CSK entry
    skip verify csk entry signature

    """
    rtn = True
    if keys.get_eckey_type(self.rk_key) == 'private':
      rtn &= keys.verify_signature_from_prvkey(self.rk_key,  self.blk_dict['b1c_sigR'], self.blk_dict['b1c_sigS'], self.csksig_data)
      logger.info('from image: csksigr  = {:s}, \n csksigs = {:s}'.format(self.blk_dict['b1c_sigR'].hex(), self.blk_dict['b1c_sigS'].hex()))
      logger.info('FAIL -- verify csk signature') if (not rtn) else logger.info('PASS -- verify csk signature')

    # skip if it is root public key, root key owner generate the signature
    logger.info('--\nb1b_sigR={}, \nb1b_sigS={}, \nblk0_data={}'.format(self.blk_dict['b1b_sigR'].hex(), self.blk_dict['b1b_sigS'].hex(), self.blk0_data.hex()))

    rtn &= keys.verify_signature_from_prvkey(self.csk_prv, self.blk_dict['b1b_sigR'], self.blk_dict['b1b_sigS'], self.blk0_data)
    logger.info('from image: blk0sigr = {:s}, blk0sigs = {:s}'.format(self.blk_dict['b1b_sigR'].hex(), self.blk_dict['b1b_sigS'].hex()))
    logger.info('FAIL -- verify block0 signature') if (not rtn) else logger.info('PASS -- verify block0 signature')
    return rtn


  def validate(self):
    """ validate block 1 sign chain
    :returns: True/False
    """
    rtn = self.verify_pc_hash()
    rtn &= self.verify_magic()
    rtn &= self.verify_pubkey_xy()
    rtn &= self.verify_signature()
    return rtn

BLOCK_KCC_FMT = '<IIII32s48s32sI12sIIII48s48s20sII48s48s644s'
BLOCK_KCC_KEY = ('b0_tag', 'b0_pclen', 'b0_pctyp', 'b0_rsvd', 'b0_hash256', 'b0_hash384', 'b0_pad', \
          'b1_tag', 'b1_rsvd', \
          'b1r_tag', 'b1r_cur', 'b1r_per', 'b1r_keyid', 'b1r_x', 'b1r_y', 'b1r_rsvd', \
          'b1b_tag', 'b1b_sig', 'b1b_sigR', 'b1b_sigS', \
          'b1_pad')

BLOCK_MAGIC_KCC_PFR_2  = (0xB6EAFD19, 0xF27F28D7, 0xA757A046, 0xC7B88C74, 0x15364367, 0xDE64437D)
BLOCK_MAGIC_KCC_PFR_3  = (0xB6EAFD19, 0xF27F28D7, 0xA757A046, 0x08F07B47, 0x15364367, 0xEA2A50E9)

class BLOCK_1K_Signed_KCC(object):
  """ Class for 1K (1024 Bytes) Block Signed Data w/o CSK Verification

  A generic class to verify 1024 Bytes Block signed data w/o CSK verification
  The Hash algorithm is based on the private key curves
  The protect content starts from offset 1024 with protect content length padding to mutiple of 128B

  The root key param takes either private or public key in PEM format.
  When in external signing, the root private key is not visiable to CSK owner, in this case, use root public key

  :param block_signed_kcc: block signed KCC data or file name without CSK
  :param rk_key: root private key (regular signed) or root public key (for external sign)
  :param kcc_cskid: KCC CSK ID, default is 0
  :param logfile: log file name, optional

  """
  def __init__(self, blk_signed_kcc, rk_key, kcc_cskid=0, logfile=None):
    self.pfr_ver = keys.get_pfr_version(rk_key)
    if logfile != None:
      self.logfile = logfile
    if isinstance(blk_signed_kcc, (bytes, bytearray)):
      self.bdata = blk_signed_kcc
      self.bsize = len(self.bdata)
    elif os.path.isfile(blk_signed_kcc):
      #print("isfile ")
      self.bsize = os.stat(blk_signed_kcc).st_size
      with open(blk_signed_kcc, 'rb') as f:
        self.bdata = f.read()
    elif isinstance(blk_signed_kcc, (bytes, bytearray)):
      self.bdata = blk_signed_kcc
      self.bsize = len(self.bdata)
    else:
      logger.error("Error: wrong argment {}, eith binary file or binary data".format(blk_signed_nocsk_file))

    self.kcc_cskid = kcc_cskid
    self.blk_data  = self.bdata[0:BLOCK_SIZE]  # 1024 bytes, first 0x400 bytes
    self.blk0_data = self.blk_data[0:BLOCK0_SIZE]
    self.blk1_data = self.blk_data[BLOCK0_SIZE:(BLOCK0_SIZE+16+132+104)]
    self.pc_data = self.bdata[BLOCK_SIZE:]

    self.rk_key  = rk_key
    self.blk_dict= ConfigDict()
    lst_temp = struct.unpack(BLOCK_KCC_FMT, self.blk_data)
    for (k, v) in zip(BLOCK_KCC_KEY, lst_temp):
      #print(k, ' = ', v)
      self.blk_dict[k] = v

  def verify_pc_len_type(self):
    """ verify PC Type is KCC PC_Type=0x100, BIT[8] is 1 for KCC """
    rtn = False
    self.pc_len  = self.blk_dict['b0_pclen']
    self.pc_type = self.blk_dict['b0_pctyp']
    logger.info('PC Length= {}, PC_Type=0x{:x}'.format(self.pc_len, self.pc_type))
    if self.pc_len == 0x80 and self.pc_type == 0x100:
      rtn = True
    return rtn

  def verify_pc_hash(self):
    """ verify protected data hash """
    pclen = self.blk_dict['b0_pclen']
    hash256 = hashlib.sha256(self.pc_data[0:pclen]).hexdigest()
    hash384 = hashlib.sha384(self.pc_data[0:pclen]).hexdigest()
    logger.info('hash256 : block0.hash256 {:s}'.format(self.blk_dict['b0_hash256'].hex()))
    logger.info('hash256 : pcdata.hash256 {:s}'.format(hash256))
    logger.info('hash384 : block0.hash384 {:s}'.format(self.blk_dict['b0_hash384'].hex()))
    logger.info('hash384 : pcdata.hash384 {:s}'.format(hash384))
    #rtn = True if ((self.blk_dict['b0_hash256'].hex() == hash256) and (self.blk_dict['b0_hash384'].hex() == hash384)) else False
    rtn = True if (self.blk_dict['b0_hash384'].hex() == hash384) else False # skip hash256 verification
    logger.error('FAIL -- verify_pc_hash error') if (not rtn) else logger.info('PASS -- verify_pc_hash')
    return rtn

  def verify_magic(self):
    lst_magic = (self.blk_dict['b0_tag'], self.blk_dict['b1_tag'], \
                 self.blk_dict['b1r_tag'], self.blk_dict['b1r_cur'], \
                 self.blk_dict['b1b_tag'], self.blk_dict['b1b_sig'] )
    rtn  = (int(self.pfr_ver) == 2) and (lst_magic == BLOCK_MAGIC_KCC_PFR_2)
    rtn |= (int(self.pfr_ver) == 3) and (lst_magic == BLOCK_MAGIC_KCC_PFR_3)
    logger.info('-- FAIL: verify Magic') if (not rtn) else logger.info('PASS: verify Magic')
    return rtn

  def verify_pubkey_xy(self):
    """ verify root public key component X and Y """
    if keys.get_eckey_type(self.rk_key) == 'private':
      rkobj = keys.PrivateKey().read_from_pem(self.rk_key)
    if keys.get_eckey_type(self.rk_key) == 'public':
      rkobj = keys.PublicKey().read_from_pem(self.rk_key)
    self.rkpubX,  self.rkpubY = rkobj.get_pubkey_xy()

    logger.info('calculated: \n rkpubX = {:s}, \n rkpubY = {:s}'.format(self.rkpubX.hex(), self.rkpubY.hex()))
    logger.info('\n from image: \n rkpubx = {:s}, \n rkpuby = {:s}'.format(self.blk_dict['b1r_x'].hex(), self.blk_dict['b1r_y'].hex()))

    rtn = (self.rkpubX == self.blk_dict['b1r_x']) and (self.rkpubY == self.blk_dict['b1r_y'])
    #rtn &= (self.cskpubX == self.blk_dict['b1c_x']) and (self.cskpubY == self.blk_dict['b1c_y'])
    logger.info('-- FAIL: verify public key X, Y') if (not rtn) else logger.info('PASS: verify public key X, Y')
    return rtn

  def verify_signature(self):
    """ verify signature

    if root public key is provided, root key owner generate the signature for CSK entry
    skip verify csk entry signature

    """
    rtn = True
    if keys.get_eckey_type(self.rk_key) == 'private':
      rtn &= keys.verify_signature_from_prvkey(self.rk_key, self.blk_dict['b1b_sigR'], self.blk_dict['b1b_sigS'], self.blk0_data)
      logger.info('from image: blk0sigr = {:s}, blk0sigs = {:s}'.format(self.blk_dict['b1b_sigR'].hex(), self.blk_dict['b1b_sigS'].hex()))
      logger.info('FAIL -- verify block0 signature') if (not rtn) else logger.info('PASS -- verify block0 signature')

    # skip if it is root public key, root key owner generate the signature
    logger.info('--\nb1b_sigR={}, \nb1b_sigS={}, \nblk0_data={}'.format(self.blk_dict['b1b_sigR'].hex(), self.blk_dict['b1b_sigS'].hex(), self.blk0_data.hex()))
    return rtn


  def validate(self):
    """ validate block 1 sign chain
    :returns: True/False
    """
    rtn = self.verify_pc_len_type()
    rtn &= self.verify_pc_hash()
    rtn &= self.verify_magic()
    rtn &= self.verify_pubkey_xy()
    rtn &= self.verify_signature()
    return rtn

class Verify_KCC(object):
  """ class for PFR Key Calcellation Cerificate Capsule verification

  :param kcc_image: PFR KCC capsule image.
  :param rk_key: root private key in PEM format
  :param logfile: logfile name, optional

  """
  def __init__(self, kcc_image, rk_key=None, kcc_cskid=0, logfile=None):
    self.image = kcc_image
    self.rk_key = rk_key
    self.kcc_cskid = kcc_cskid
    if logfile != None:
      self.logfile = logfile
      logging.getLogger().handlers=[]

  def verify_payload_cskid(self):
    """ verify payload size and CSK ID """
    rtn = False
    with open(self.image, 'rb') as f:
      f.seek(BLOCK_SIZE)
      self.payload = f.read()
      cskid = struct.unpack('<I', self.payload[0:4])[0]
    logger.info("CSKID from KCC: {}, CSKID to be verified:{}".format(cskid, self.kcc_cskid))
    logger.info("KCC payload size:0x{:x}".format(len(self.payload)))
    if (self.kcc_cskid == cskid) and (len(self.payload) == 0x80):
      rtn = True
    return rtn

  def show(self):
    """ show KCC """
    print("-- CSK ID: {}, Payload Size: {}".format(self.cskid, len(self.payload)))

  def validate(self):
    obj=BLOCK_1K_Signed_KCC(self.image, self.rk_key, self.kcc_cskid, self.logfile)
    rtn = obj.validate()
    rtn &= self.verify_payload_cskid()
    return rtn


def main(args):
  """ verify PFR image or stgaing capsure"""
  parser = argparse.ArgumentParser(description="-- PFR Verification")

  # verify pfr ifwi
  subparser = parser.add_subparsers(dest='action')
  signcap = subparser.add_parser('capsule')
  signcap.add_argument('-i', '--input_bin',   metavar="[Input bin file or data bytes]", dest='input_bin', help='signed pfm/capsule image, or signed binary data')
  signcap.add_argument('-rk', '--rk_key', metavar="[root key]",  dest='rk_key', help='root key, either private or public')
  signcap.add_argument('-csk', '--csk_prv', metavar="[csk private key]",  dest='csk_prv', help='CSK private key')
  signcap.add_argument('-log', '--logfile', metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")

  afmcap = subparser.add_parser('afm')
  afmcap.add_argument('-i', '--input_bin',   metavar="[Input bin file or data bytes]", dest='input_bin', help='signed pfm/capsule image, or signed binary data')
  afmcap.add_argument('-rk', '--rk_key', metavar="[root key]",  dest='rk_key', help='root key, either private or public in PEM format')
  afmcap.add_argument('-csk', '--csk_prv', metavar="[csk private key]",  dest='csk_prv', help='CSK private key')
  afmcap.add_argument('-log', '--logfile', metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")

  pfmcap = subparser.add_parser('pfm')
  pfmcap.add_argument('-i', '--input_bin',   metavar="[Input bin file or data bytes]", dest='input_bin', help='signed pfm/capsule image, or signed binary data')
  #pfmcap.add_argument('-rk', '--rk_key', metavar="[root key]",  dest='rk_key', help='root key, either private or public')
  #pfmcap.add_argument('-csk', '--csk_prv', metavar="[csk private key]",  dest='csk_prv', help='CSK private key')
  pfmcap.add_argument('-log', '--logfile', metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")

  # verify PFR_IFWI
  pfrifwi = subparser.add_parser('ifwi')
  pfrifwi.add_argument('-i',   '--input_bin',   metavar="[Input PFR IFWI image]", dest='input_bin', help='PFR compliant IFWI image')
  pfrifwi.add_argument('-rk',  '--rk_key', metavar="[root key]",  dest='rk_key', help='root private key in PEM format')
  pfrifwi.add_argument('-csk', '--csk_prv', metavar="[csk private key]",  dest='csk_prv', help='CSK private key in PEM format')
  pfrifwi.add_argument('-log', '--logfile', metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")

  # verify pfr BMC
  pfrbmc = subparser.add_parser('bmc')
  pfrbmc.add_argument('-i',   '--input_bin',   metavar="[Input PFR BMC image]", dest='input_bin', help='PFR compliant BMC image')
  pfrbmc.add_argument('-rk',  '--rk_key', metavar="[root key]",  dest='rk_key', help='root private key in PEM format')
  pfrbmc.add_argument('-csk', '--csk_prv', metavar="[csk private key]",  dest='csk_prv', help='CSK private key in PEM format')
  pfrbmc.add_argument('-log', '--logfile', metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")

  args = parser.parse_args(args)
  if args.logfile != None:
    logging.basicConfig(level=logging.DEBUG,
                    handlers= [
                      logging.FileHandler(args.logfile, mode='w'),
                      logging.StreamHandler()
                    ]
                  )
  else:
    logging.basicConfig(level=logging.DEBUG, handlers= [ logging.StreamHandler()])

  if args.action == 'capsule':
    if args.rk_key == None or args.csk_prv == None:
      print("-- To vaerify capsule, you would need inlcude RK and CSK private keys in pem format ")
      raise ValueError("-- Required to include signing keys to verify capsule")
    BLOCK_1K_Signed(args.input_bin, args.rk_key, args.csk_prv).validate()

  if args.action == 'afm':
    if args.rk_key == None or args.csk_prv == None:
      raise ValueError("-- Required to include signing keys to verify AFM capsule")
    obj=Verify_AFM(args.input_bin, args.rk_key, args.csk_prv)
    obj.validate()

  if args.action == 'pfm':
    obj=Verify_PFM(args.input_bin)
    obj.validate()

  if args.action == 'ifwi':
    obj=PFR_IFWI(args.input_bin, args.rk_key, args.csk_prv, args.logfile)
    obj.validate()

  if args.action == 'bmc':
    obj=PFR_BMC(args.input_bin, args.rk_key, args.csk_prv, args.logfile)
    obj.validate()

if __name__ == '__main__':
  main(sys.argv[1:])
