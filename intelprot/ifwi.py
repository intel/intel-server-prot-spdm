#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    This module is to analysis or to customize integrated firmware image (IFWI) image)::

     * add cpld update capsule to IFWI staging area
     * extract PFR provision data from bios region
     * update BMC PFM active offset

    command line execution::

     >python -m intelprot.ifwi -i <pfr_ifwi_image>
     >python -m intelprot.ifwi -i <pfr_ifwi_image> -show_prov

     # update BMC active pfm offset
     >python -m intelprot.ifwi -i <pfr_ifwi_image> -bmc_pfm <bmc_active_offset>

     # example: from BMC offset from 0x80000 to 0x1FC00000, a new ifwi image will be generated.
     >python -m intelprot.ifwi -i <pfr_ifwi_image> -bmc_pfm 0x1fc0000


"""
from __future__ import print_function
from __future__ import division

__author__    = "Scott Huang (scott.huang@intel.com)"
__docformat__ = 'reStructuredText'

import sys, os, struct, hashlib, re, binascii, time, datetime, getopt, argparse
import json, codecs, struct, shutil, collections, base64
from xml.dom import minidom
from functools import partial
from collections import OrderedDict
import pathlib, shutil

import logging
logger = logging.getLogger(__name__)

from intelprot import pfm, utility, sign

_PFRS_TAG = '__PFRS__'
_PFRS_KEYS =  ( "struct_ID",
                "struct_ver",
                "rsvd1",
                "elem_size",
                "cntl_flags",
                "rsvd2",
                "cpld_smbaddr",
                "ifwi_active",
                "ifwi_recovery",
                "ifwi_staging",
                "bmc_active",
                "bmc_recovery",
                "bmc_staging")

_PFRS_FMT = '<8sBBHI3sBIIIIII'

_KEYM_TAG = '__KEYM__'
_KEYM_KEYS = ('struct_ID',
              'struct_ver',
              'rsvd1',
              'keySigOffset',
              'rsvd2',
              'keyManifestVer',
              'KMSVN',
              'keyManifestID',
              'kmPubkey_Alg',
              'num_keydigest',
              'keyhash_usage1',
              'keyhash_Alg1',
              'keyhash_size1',
              'keyhash_buffer1',
              'keyhash_usage2',
              'keyhash_Alg2',
              'keyhash_size2',
              'keyhash_buffer2')

_KEYM_STRUCT_ID   = b'__KEYM__'
_KEYM_STRUCT_VER  = 0x21
_KEYM_SIGOFFSET_3 = 0x90
_KEYM_SIGOFFSET_2 = 0x70
_KEYM_USAGE_PFR   = 0x10
_KEYM_HASH_ALG_2  = 0x000B
_KEYM_HASH_ALG_3  = 0x000C
_KEYM_HASH_SIZE_2 = 0x0020
_KEYM_HASH_SIZE_3 = 0x0030

_KEYM_FMT_2 = '<8sB3sH3sBBBHHQHH32sQHH32s'
_KEYM_FMT_3 = '<8sB3sH3sBBBHHQHH48sQHH48s'

BLOCKSIZE = 4096  # typical page size
BLOCKS = 1024     # somewhat arbitrary
CHUNK_SIZE = BLOCKS * BLOCKSIZE  # chunk size


class Agent(object):
  """ extract PFR provision UFM data from PFR ifwi binary image

  """
  def __init__(self, input_img):
    self._image   = input_img
    self._pfr_ver = 0
    self._pfrs = {}
    self._keym = {}

  def get_pfrs_value(self):
    """ get provision data

    extract pfr offset provision UFM data from __PFRS__ structure
    """
    #logger.info("-- get_pfrs_value ")
    with open(self._image, 'rb') as f:
      lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(str.encode(_PFRS_TAG)), f.read())]
      #print("lst_addr={}".format(lst_addr))
      if len(lst_addr)== 0:
        logger.error("-- ERROR: unable to find _PFRS_TAG '__PFRS__' inside ifwi image !")
        return -1
      staddr = int(lst_addr[0], 0)
      self.pfrs_start = staddr
      f.seek(staddr)
      tmp_lst = struct.unpack(_PFRS_FMT, f.read(struct.calcsize(_PFRS_FMT)))
      #print(tmp_lst)
      for (k,v) in zip(_PFRS_KEYS, tmp_lst):
        if isinstance(v, bytes) and (k != 'struct_ID'): v=v.hex()
        if isinstance(v, int): v=hex(v)
        self._pfrs[k]=v

  def get_keym_value(self):
    """ extract root public key hash from __KEYM__ structure

    """
    #logger.info("-- get_keym_value ")
    with open(self._image, 'rb') as f:
      lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(str.encode(_KEYM_TAG)), f.read())]
      if len(lst_addr)== 0:
        logger.error("-- ERROR: unable to find _KEYM_TAG:'__KEYM__' inside ifwi image !")
        return -1
      staddr=int(lst_addr[0], 0)
      f.seek(staddr)
      keymtag = f.read(8)
      (ver, rsvd, keysigoffset)=struct.unpack('<B3sH', f.read(6))
      #print('-- keymtag :', keymtag)
      if (keymtag == _KEYM_STRUCT_ID) and (ver == _KEYM_STRUCT_VER):
        if keysigoffset == _KEYM_SIGOFFSET_2:
          self._pfr_ver = 2.0
          f.seek(staddr)
          tmp_lst = struct.unpack(_KEYM_FMT_2, f.read(struct.calcsize(_KEYM_FMT_2)))

        if keysigoffset == _KEYM_SIGOFFSET_3:
          self._pfr_ver = 3.0
          f.seek(staddr)
          tmp_lst = struct.unpack(_KEYM_FMT_3, f.read(struct.calcsize(_KEYM_FMT_3)))

        for (k, v) in zip(_KEYM_KEYS, tmp_lst):
          if (k != 'struct_ID') and isinstance(v, (bytes, bytearray)): v=v.hex()
          if isinstance(v, int): v=hex(v)
          self._keym[k] = v
        if int(self._keym['keyhash_usage2'], 0) == 0x10:
          self._keyhash = self._keym['keyhash_buffer2']
        if int(self._keym['keyhash_usage1'], 0) == 0x10:
          self._keyhash = self._keym['keyhash_buffer1']

  def get_prov_data(self):
    """ get provision data

    extract root public key hash from __KEYM__ structure
    extract pfr offset provision UFM data from __PFRS__ structure
    """
    self.get_pfrs_value()
    self.get_keym_value()

  def show(self):
    """ log structure data """
    if self._pfr_ver == 0:
      self.get_prov_data()
    for k in _KEYM_KEYS:
      logger.info("--{:20s}: {}".format(k, self._keym[k]))
    logger.info("-- PFR root public key hash: {} \n".format(self._keyhash))
    for k in _PFRS_KEYS:
      logger.info("--{:20s}: {}".format(k, self._pfrs[k]))

  def logger(self):
    logging.basicConfig(level=logging.DEBUG, handlers= [logging.StreamHandler()])


ACTV_PFM_SIZE  = 0x10000
RECV_CAP_SIZE  = 0x1400000
STAG_CAP_SIZE  = 0x1400000

class IFWI(object):
  """ class for IFWI image operation

  :param ifwi_image: pfr ifwi image

  """
  def __init__(self, ifwi_image):
    self.ifwi_image = ifwi_image
    obj=Agent(ifwi_image)
    obj.get_prov_data()
    self.pfrs = obj._pfrs
    self.keym = obj._keym
    self.pfrs_start = obj.pfrs_start # PFRS_ start offset
    self.pfr_rk_hash = obj._keyhash
    with open(self.ifwi_image, 'rb') as f:
      f.seek(int(self.pfrs['ifwi_active'], 0))
      self.act_pfm = pfm.PFM(f.read(ACTV_PFM_SIZE))
      f.seek(int(self.pfrs['ifwi_recovery'],0))
      self.rcv_pfm = pfm.PFM(f.read(RECV_CAP_SIZE))
      f.seek(int(self.pfrs['ifwi_staging'], 0))
      self.stg_pfm = pfm.PFM(f.read(STAG_CAP_SIZE))


  def update_bmc_active(self, bmc_active_offset):
    """ update BMC active PFM offset

    :param bmc_active_offset: BMC active PFM offset

    """
    self.new_ifwi_image = os.path.splitext(self.ifwi_image)[0]+"_update.bin"
    self.bmc_act_offset = self.pfrs_start + struct.calcsize('<8sBBHI3sBIII')
    with open(self.ifwi_image, 'rb') as f1, open(self.new_ifwi_image, 'wb') as f2:
      f1.seek(0)
      f2.write(f1.read(self.bmc_act_offset))
      f2.write(struct.pack('<I', int(bmc_active_offset, 0) ) )
      f1.seek(self.bmc_act_offset+4)
      f2.write(f1.read())

  def add_capsule(self, start_addr, capsule_image):
    """ add capsule image to ifwi image

    This function can be used to include staging capsule to pfr ifwi image.
    or adding cpld signed update capsule to PCH/CPU SPI image

    :param start_addr: start address of signed capsule
    :param capsule_image: capsule image file to be added

    """
    self.new_ifwi_image = os.path.splitext(self.ifwi_image)[0]+"_update.bin"
    shutil.copy(self.ifwi_image, self.new_ifwi_image)
    with open(self.new_ifwi_image, 'r+b') as fd1, open(capsule_image, 'rb') as fd2:
      fd1.seek(start_addr)
      fd1.write(fd2.read())

  def get_rcv_capsule(self):
    self.rcv_cap = os.path.splitext(self.ifwi_image)[0]+"_rcv_cap.bin"
    with open(self.ifwi_image, 'rb') as f1, open(self.rcv_cap, 'wb') as f2:
      f1.seek(int(self.pfrs['pch_recovery'],0))
      f2.write(f1.read(RECV_CAP_SIZE))

  def show(self):
    msg  = '\n-- IFWI provision:\n active: {}, recovery: {}, staging: {}'.format(self.pfrs['ifwi_active'], self.pfrs['ifwi_recovery'],self.pfrs['ifwi_staging'])
    msg += '\n-- BMC provision:\n active: {}, recovery: {}, staging: {}'.format(self.pfrs['bmc_active'], self.pfrs['bmc_recovery'],self.pfrs['bmc_staging'])
    msg += '\n-- PFR root public key hash: {}'.format(self.pfr_rk_hash)
    logger.info(msg)
    logger.info('-- Active PFM:\n')
    self.act_pfm.show()
    if self.rcv_pfm.no_pfm_tag is False:
      logger.info('\n-- Recovery Capsule:\n')
      self.rcv_pfm.show()
    else:
      logger.info('\n-- No recovery capsule found.')

    if self.stg_pfm.no_pfm_tag is False:
      logger.info('\n-- Staging Capsule:\n')
      self.stg_pfm.show()
    else:
      logger.info('\n-- No staging capsule found.')



# for nested dictionary
class ConfigDict(OrderedDict):
  """ define an ordered dictionary """
  def __missing__(self, key):
    val = self[key] = ConfigDict()
    return val


FIT4_LEN_OFFSET = 20
FIT4_TAG        = b'BTGC' # "42544743"
FIT4_FMT = '<I12sBBBBIIHBBHHHH48s'
FIT4_KEY = ('recordlen', 'rsvd0', 'rsvd3', 'rsvd2', 'rsvd1', 'debug_policy', \
            'btg_entry_type', 'btg_entry_len', 'btg_content_version', 'btg_content_type', 'btg_chksum', \
            'bp_rstr', 'bp_type', 'bp_revocation', 'bp_keytype', 'bp_keyhash')

class FIT4(object):
  """
  define class FIT type 4 for analysis
  """
  def __init__(self, image):
    self.image  = image
    self.fit4_json_file = os.path.join(os.path.dirname(__file__), 'json', 'bhs_fit_type4.json')
    print(self.fit4_json_file)
    with open(self.fit4_json_file, 'r') as f:
      self.fit4_manifest = json.load(f)  #ConfigDict()

    self.fit4_dict = ConfigDict()
    st_tag = FIT4_TAG
    with open(self.image, 'rb') as f:
      lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), f.read())]
      self.tag_addr = int(lst_addr[-1], 16)
      f.seek(self.tag_addr - FIT4_LEN_OFFSET)
      self.record_len= struct.unpack('<I', f.read(4))[0]
      f.seek(self.tag_addr - FIT4_LEN_OFFSET)
      self.fit4_bdata = f.read(self.record_len)

  def get_fit4_data(self):
    """ get FIT type 4 data
    """
    lst_temp = struct.unpack(FIT4_FMT, self.fit4_bdata)
    for (k, v) in zip(FIT4_KEY, lst_temp):
      self.fit4_dict[k] = v
      if k =='btg_entry_type':
        self.fit4_dict[k] = v.to_bytes(4, 'little')

  def get_bp_rstr(self):
    """ decode bp_rstr """
    pass

  def get_bp_type(self):
    """ decode bp_type """
    pass
  def get_bp_revocation(self):
    """ decode bp_revocation """
    pass
  def get_bp_keytype(self):
    """ decode bp key type"""
    pass
  def get_bp_keyhash(self):
    """ get bp key hash """
    pass
  def dump_to_json(self):
    """ dump to json file """
    jsonfile = os.path.splitext(self.image)[0]+"_fit4.json"
    with open(jsonfile, 'w') as fp:
      json.dump(self.fit4_dict, fp, indent=4)

  def show(self):
    """print FIT4 data """
    for k in FIT4_KEY:
      print ('{:<20s} = {}'.format(k, self.fit4_dict[k]))

PAGE_SIZE = 0x1000 # 4KB one page
PFR_START, PFR_END = 0x3fe0000, 0x8000000  # PFR Region 14 range
PBC_TAG   = 0x5F504243

class BHS_IFWI(object):
  """ class for single BHS PFR IFWI operation """
  def __init__(self, *args):
    self.ACT_IMG_SIZE = 0x4000000 # 64MB  64*1024*1024 = 0x4000000
    self.ACT_PFM_SIZE = 0x20000   # 128KB 128*1024     = 0x20000
    self.REC_CAP_SIZE = 0x2000000 # 32MB  32*1024*1024 = 0x2000000
    self.STA_CAP_SIZE = 0x2000000 # 32MB  32*1024*1024 = 0x2000000
    self.rk  = os.path.join(os.path.dirname(__file__), 'keys', 'birchstream', 'key_root_prv.pem')
    self.csk = os.path.join(os.path.dirname(__file__), 'keys', 'birchstream', 'key_csk_prv.pem')
    if len(args) == 2:
      self.ifwi_image1 = args[0]  # first  64MB image
      self.ifwi_image2 = args[1]  # second 64MB image
      self.combine_ifwi()         # combine as one, need rebuild with updated hash data
    elif len(args) == 1:
      self.ifwi_image  = args[0]   # 1x128MB image filename
    else:
      looger.error("-- Error: only one or two arguments")

    self.csk_id = 0
    self.pfm_pc_type = 0x1
    self.upd_pc_type = 0x2
    self.signed_pfm_image = 'signed_pfm.bin'
    self.signed_upd_image = 'signed_update_capsule.bin'

    # process single 1x128MB image
    obj = Agent(self.ifwi_image)
    obj.get_prov_data()
    self.pfrs = obj._pfrs
    self.keym = obj._keym
    self.pfrs_start = obj.pfrs_start # PFRS_ start offset
    self.pfr_rk_hash = obj._keyhash
    self.pfm_start = int(self.pfrs['ifwi_active'], 0)
    self.rcv_start = int(self.pfrs['ifwi_recovery'], 0)
    with open(self.ifwi_image, 'rb') as f:
      f.seek(0)
      with open('temp_part1_64MB.bin', 'wb') as f1:
        f1.write(f.read(self.ACT_IMG_SIZE))

      f.seek(self.pfm_start)
      with open('temp_signed_pfm.bin', 'wb') as f2:
        f2.write(f.read(self.ACT_PFM_SIZE))

      f.seek(self.rcv_start)
      with open('temp_signed_cap.bin', 'wb') as f3:
        f3.write(f.read(self.REC_CAP_SIZE))

      f.seek(int(self.pfrs['ifwi_staging'], 0))
      with open('temp_signed_stg.bin', 'wb') as f4:
        f4.write(f.read(self.STA_CAP_SIZE))

  def update_as_one_component(self):
    """
    1) update 0x14-0x17 Bit[9:8]   0x01-->0x00
    2) update FLCOMP.C0DEN (0x030) Bit[3:0] 0x07 --> 0x08, Bit[7:4] = 0xF
    """
    shutil.copyfile(self.ifwi_image, "temp_128MB.bin")
    with open(self.ifwi_image, 'wb') as fout, open("temp_128MB.bin", 'rb') as fin:
      fin.seek(0x14)
      flmap0=struct.unpack('<I', fin.read(4))[0]
      flmap0=flmap0 & 0xFFFFFCFF
      print("flmap0={}".format(hex(flmap0)))
      fin.seek(0x30)
      flcomp = struct.unpack('<I', fin.read(4))[0]
      flcomp = (flcomp & 0xFFFFFF00) | 0xF8
      print("flcomp={}".format(hex(flcomp)))
      fin.seek(0)
      for chunk in iter(partial(fin.read, CHUNK_SIZE), b''):
        fout.write(chunk)

      fout.seek(0x14)
      fout.write(struct.pack('<I', flmap0))
      fout.seek(0x30)
      fout.write(struct.pack('<I', flcomp))

    # remove temp_128MB.bin
    os.remove("temp_128MB.bin")

  def combine_ifwi(self):
    """ combine 2x64MB IFWI as 1x128MB flash """
    if self.ifwi_image1.strip('_1.bin') != self.ifwi_image2.strip('_2.bin'):
      print("-- Two image are not pair, please check use a pair of image")
    self.ifwi_image = self.ifwi_image1.strip('_1.bin') + '_128MB.bin'
    with open(self.ifwi_image, "wb") as outfile:
      for fname in [self.ifwi_image1, self.ifwi_image2]:
        for chunk in iter(partial(open(fname, "rb").read, CHUNK_SIZE), b''):
          outfile.write(chunk)
    self.update_as_one_component()

  def get_unsigned_pfm(self):
    """ get unsigned pfm """
    with open('temp_signed_pfm.bin', 'rb') as f:
      f.seek(4)
      self.pfm_pclen = struct.unpack('<I', f.read(4))[0]
      f.seek(0x400)
      with open('temp_unsigned_pfm.bin', 'wb') as f1:
        f1.write(f.read(self.pfm_pclen))
      f.seek(0x400+self.pfm_pclen)
      with open('temp_fvm_in_pfm.bin', 'wb') as f2:
        f2.write(f.read())  # read reset

  def update_unsigned_pfm(self):
    """ update unsigned pfm with new hash """
    pfmobj=pfm.PFM('temp_signed_pfm.bin')
    self.pfmobj = pfmobj
    self.pfmobj.process_fvm()     # process fvm inside pfm
    self.pfm_dict = ConfigDict()
    self.pfm_dict = pfmobj.pfm_dict
    for k in pfmobj.pfm_dict['spi']:
      mask    = pfmobj.pfm_dict['spi'][k]['mask']
      hashalg = pfmobj.pfm_dict['spi'][k]['hash_alg']
      if mask == 0x9D: pfmobj.pfm_dict['spi'][k]['mask'] = 0x1D
      if mask == 0x9F: pfmobj.pfm_dict['spi'][k]['mask'] = 0x1F
      if hashalg == 0x02:
        sta_addr = pfmobj.pfm_dict['spi'][k]['reg_start']
        end_addr = pfmobj.pfm_dict['spi'][k]['reg_end']
        hash_data = utility.get_hash384(self.ifwi_image, sta_addr, end_addr)
        pfmobj.pfm_dict['spi'][k]['hash_data'] = hash_data

    #save to file
    with open('temp_unsigned_pfm.bin', 'rb') as f:
      self.pfm_header=f.read(32)

    lst_key = ('type', 'mask', 'hash_alg', 'rsvd1', 'reg_start', 'reg_end', 'hash_data')
    with open('temp_unsigned_pfm_new.bin', 'wb') as f:
      f.write(self.pfm_header)
      data_len=32
      for k in pfmobj.pfm_dict['spi']:
        lstval=[]
        bdata=b''
        temp=pfmobj.pfm_dict['spi'][k]
        for key in lst_key:
          val = temp[key]
          if key=='hash_data': val = bytes.fromhex(val)
          lstval.append(val)
        #print(len(lstval), '--', lstval)
        bdata+=struct.pack("<BBHIII{}s".format(len(lstval[6])), lstval[0], lstval[1], lstval[2], lstval[3], lstval[4], lstval[5], lstval[6])
        f.write(bdata)
        data_len+=len(bdata)
      #print(hex(data_len))
      with open('temp_unsigned_pfm.bin', 'rb') as f1:
        f1.seek(data_len)
        restbdata=f1.read(self.pfm_pclen - data_len)
      f.write(restbdata)

  def sign_pfm(self):
    """ sign pfm
        image, pc_type, csk_id, rk_prv_pem, csk_prv_pem
    """
    signobj=sign.Signing('temp_unsigned_pfm_new.bin', self.pfm_pc_type, self.csk_id, self.rk, self.csk)
    signobj.set_signed_image('temp_signed_pfm_new.bin')
    signobj.sign()
    with open('signed_pfm.bin', 'wb') as f, open('temp_signed_pfm_new.bin', 'rb') as f1, open('temp_fvm_in_pfm.bin', 'rb') as f2:
      f.write(f1.read())
      f.write(f2.read())

  def get_pfm_entry(self):
    """
    get PFM entry from image as below list of list pfm entry in below format:

    [[(SPI_start, SPI_end), Mask, Hash384_info(2/0: Y/N), Include(1/0:Compress Y/N)], ...]
    List of pfm entry also include FVM list.

    """
    lst_key = ('type', 'mask', 'hash_alg', 'rsvd1', 'reg_start', 'reg_end', 'hash_data')
    lst_pfm_struct = []
    for k in self.pfm_dict['spi']:
      temp=self.pfm_dict['spi'][k]
      if temp['reg_start'] >= 0x3fe0000:
        compress_flag = 0x0
      else:
        compress_flag = 0x1
      lst=[(temp['reg_start'], temp['reg_end']), temp['mask'], temp['hash_alg'], compress_flag]
      lst_pfm_struct.append(lst)

    startidx, endidx = self.pfmobj.fvm_header.index('START'), self.pfmobj.fvm_header.index('END')
    fvm_mask         = 0x1D   # all FVM mask is fixed as 0x1D as static with hash384
    fvm_hash_present = 0x1    # all FVM hash data is presented
    fvm_include      = 0x1    # all FVM in included in update capsule, compress = 1
    for lstfvm in self.pfmobj.fvm_value:
      start_addr = int(lstfvm[startidx], 0)
      end_addr   = int(lstfvm[endidx],   0)
      lst=[(start_addr, end_addr), fvm_mask, fvm_hash_present, fvm_include]
      lst_pfm_struct.append(lst)

    self.lst_pfm_entry = lst_pfm_struct  # assign to self.lst_pfm_entry

    self.page_size = PAGE_SIZE
    self.empty     = b'\xff' * self.page_size
    self.pfr_ifwi_image_size = 128*1024*1024 # 128MB 0x8000000
    self.pbc_erase_bitmap = bytearray(int(self.pfr_ifwi_image_size/(PAGE_SIZE*8))) # (FlashSize)/(4K*8)
    self.pbc_comp_bitmap  = bytearray(int(self.pfr_ifwi_image_size/(PAGE_SIZE*8))) # (FlashSize)/(4K*8)
    self.pbc_comp_payload = 0


  def build_update_capsule(self):
    """ build recovery capsule of IFWI """
    exclude_pages = [[PFR_START//0x1000, (PFR_END-0x1000)//0x1000]]
    comp_payload  = b''   # compression payload
    self.get_pfm_entry()
    with open("ifwi_compressed.bin", "wb+") as upd:
      with open(self.ifwi_image, "rb") as f:
        # process all spi image parts
        for p in self.lst_pfm_entry:
          start_addr = p[0][0]
          end_addr   = p[0][1]
          pfm_mask   = p[1]     # pfm protection mask
          hash_flag  = p[2]     # to be hashed?
          compress   = p[3]     # compress flag
          # 1 page is 4KB, page number of address 0x40000 is 0x40
          page = start_addr >> 12         # one page is 0x1000, page number is address right-shift 12 bits

          #print("-->entry page: {}, start_addr = 0x{:x}, end_addr = 0x{:x}, p = {}".format(page, start_addr, end_addr, p))
          f.seek(start_addr)
          skip = False
          for chunk in iter(lambda: f.read(self.page_size), b''):
            chunk_len = len(chunk)
            if chunk_len != self.page_size:
              chunk = b''.join([chunk, b'\xff' * (self.page_size - chunk_len)])

            for pg in exclude_pages:
              if (page >= pg[0]) and (page <= pg[1]):
                skip = True
                break
            #print("-- process page: {}, skip = {}. compress".format(page, skip))
            if (not skip) and (compress == 1):
              #print("-- process page: {}, skip = {}. compress = {}, chunk != self.empty? = {}".format(page, skip, compress, (chunk != self.empty)))
              self.pbc_erase_bitmap[page >> 3] |= 1 << (7- (page % 8)) # Big endian bit map
              # add to the pbc map
              if chunk != self.empty:
                upd.write(chunk)  # write to file
                #print("****write page: {}, in range [start_addr = 0x{:x}, end_addr = 0x{:x}]".format(page, start_addr, end_addr))
                self.pbc_comp_bitmap[page >> 3] |= 1 << (7- (page % 8)) # Big Endian bit map
                self.pbc_comp_payload += chunk_len # compressed payload length in bytes
              #else:
                #print("-- empty page: {}, skip = {}. compress = {}, chunk != self.empty? = {}".format(page, skip, compress, (chunk != self.empty)))
            page += 1
            #print("-- process page: {}".format(page))
            if (page * self.page_size) >= end_addr:
              break
          #print("<--exit page: {}, start_addr = 0x{:x}, end_addr = 0x{:x}, p = {}".format(page, start_addr, end_addr, p))

      # pbc header
      pbc_tag = struct.pack('<I', PBC_TAG)
      pbc_ver = struct.pack('<I', 0x2)
      page_size = struct.pack('<I', 0x1000)  # page size 4*1024 = 0x1000
      patt_size = struct.pack('<I', 0x1)
      patt_comp = struct.pack('<I', 0xFF)
      bmap_size = struct.pack('<I', 0x8000) # 4k granularity, 0x8000 is for 64MB image
      pload_len = struct.pack('<I', self.pbc_comp_payload)
      rsvd0     = b'\x00'*100
      erase_bitmap = bytes(self.pbc_erase_bitmap)
      comp_bitmap  = bytes(self.pbc_comp_bitmap)
      self.pbc_header = pbc_tag + pbc_ver + page_size + patt_size + \
                      patt_comp + bmap_size + pload_len + rsvd0 + erase_bitmap + comp_bitmap
      with open("ifwi_pbc.bin", "wb+") as pbf:
        pbf.write(self.pbc_header)

      f4='unsigned_update_capsule.bin'
      f1='signed_pfm.bin'
      f2='ifwi_pbc.bin'
      f3='ifwi_compressed.bin'
      with open(f4, 'wb') as fd4, open(f1, 'rb') as fd1, open(f2, 'rb') as fd2, open(f3, 'rb') as fd3:
        fd4.write(fd1.read())
        fd4.write(fd2.read())
        fd4.write(fd3.read())

      obj1 = sign.Signing(f4, self.upd_pc_type, self.csk_id, self.rk, self.csk)
      obj1.set_signed_image(self.signed_upd_image)
      obj1.sign()


  def build_new_pfr_ifwi(self):
    """ build new PFR IFWI capsule """
    self.new_ifwi = os.path.splitext(self.ifwi_image)[0]+'_pfr.bin'
    f1=self.ifwi_image
    f2=self.new_ifwi
    self.get_unsigned_pfm()
    self.update_unsigned_pfm()
    self.sign_pfm()
    self.build_update_capsule()
    with open(f2, 'wb') as fd2, open(f1, 'rb') as fd1, open(self.signed_pfm_image, 'rb') as fd3, open(self.signed_upd_image, 'rb') as fd4:
      fd2.write(fd1.read())
      fd2.seek(self.pfm_start)
      fd2.write(fd3.read())
      fd2.seek(self.rcv_start)
      fd2.write(fd4.read())
    self.remove_temp_files()

  def remove_temp_files(self):
    """ delete temporary files generated in this working folder """
    # copy signed_update_capsule and rename it
    self.update_capsule = os.path.splitext(self.ifwi_image)[0]+'_update_capsule.bin'
    shutil.move('signed_update_capsule.bin', self.update_capsule)
    #self.ifwi_image = self.ifwi_image1.strip('_1.bin') + '_128MB.bin'
    lst=list(pathlib.Path(os.getcwd()).rglob('temp*.bin'))
    rmvlist=['ifwi_pbc.bin', 'ifwi_compressed.bin', 'unsigned_update_capsule.bin', 'signed_pfm.bin', self.ifwi_image]
    for f in lst+rmvlist:
      os.remove(f)


def main(args):
  parser = argparse.ArgumentParser(description='PFR IFWI module analysis')
  parser.add_argument('-show_prov', action='store_true', help='show provision information from BIOS')
  parser.add_argument('-i', '--input_image', metavar="[input image]",   dest='input_img', help='input ifwi pfr image file')
  parser.add_argument('-l', '--logfile',     metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")
  parser.add_argument('-p', '--platform',    metavar="[platform]",      dest='platform', default='bhs', help="reference platform: bhs, egs")

  subparser = parser.add_subparsers(dest='image')
  mifwi = subparser.add_parser('oneimage')
  mifwi.add_argument('-i', '--first_image', metavar="[IBL_1 image]", dest='image1',    help='first ibl image *_ibl_1.bin')
  mifwi.add_argument('-p', '--platform',    metavar="[platform]",    dest='platform',  default='bhs', help="this is only for BHS platform")

  #subparser = parser.add_subparsers(dest='image')
  upcap = subparser.add_parser('updatecap')
  upcap.add_argument('-i', '--ifwi_image', metavar="[IFWI image]", dest='image1',    help='for BHS, this is either 128MB image or the first ibl image *_ibl_1.bin, for EGS, it is the 64MB pfr ifwi image')
  upcap.add_argument('-p', '--platform',   metavar="[platform]",   dest='platform', default='bhs', help="generate update capsule from single ifwi image")
  upcap.add_argument('-o', '--output capsule',  metavar="[update capsule filename]",   dest='fname', default=None, help="output update capsule filename")

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
    logging.basicConfig(level=logging.DEBUG, handlers= [logging.StreamHandler()])

  if args.show_prov:
    print("-- show provision")
    ifwiobj = IFWI(args.input_img)
    ifwiobj.show()
    Agent(args.input_img).show()

  if args.image == 'oneimage':
    image1 = args.image1
    if image1.endswith('_1.bin') and os.stat(image1).st_size == 64*1024*1024:
      image2 = args.image1.split('_1')[0]+'_2.bin'
      msg = "-- build 1x128MB PFR flash from:\n -- {} and \n -- {}".format(image1, image2)
      logger.info(msg)
      ifwiobj = BHS_IFWI(image1, image2)
      ifwiobj.combine_ifwi()
    elif os.stat(image1).st_size == 128*1024*1024:
      # already is 1x128MB flash
      msg = "-- build 1x128MB PFR flash from: \n -- {}".format(image1)
      logger.info(msg)
      ifwiobj = BHS_IFWI(image1)

    ifwiobj.build_new_pfr_ifwi()

  if args.image == 'updatecap':
    print(args)
    if args.platform == "bhs":
      image1 = args.image1
      print('image1={}'.format(image1))
      if image1.endswith('_1.bin') and os.stat(image1).st_size == 64*1024*1024:
        image2 = args.image1.split('_1')[0]+'_2.bin'
        msg = "-- build 1x128MB PFR flash from:\n -- {} and \n -- {}".format(image1, image2)
        logger.info(msg)
        ifwiobj = BHS_IFWI(image1, image2)
        ifwiobj.combine_ifwi()
      elif os.stat(image1).st_size == 128*1024*1024:
        # already is 1x128MB flash
        msg = "-- build 1x128MB PFR flash from: \n -- {}".format(image1)
        logger.info(msg)
        ifwiobj = BHS_IFWI(image1)
      ifwiobj.build_new_pfr_ifwi()

      print(ifwiobj.ifwi_image)
      #ifwiobj.build_update_capsule()

if __name__ == '__main__':
  main(sys.argv[1:])
