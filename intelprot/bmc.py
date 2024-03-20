#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  :platform: Linux, Windows
  :synopsis: It is used for pfr BMC image generation of PFM and Capsule based in image manifest json file.

  Build BMC PFR Image
  ===================

  Use -start_build and reference design name to generate template manifest and keys used in reference design.
  Then modify the manifest file and replace key file as yours. The build image will based on the json file.

  .. warning::
     Please do not change the keyname in manifest json file.

  Build in Command line
  ---------------------

  #. create and switch to work folder
  #. run and verify python (Windows) or python3 (Linux) is in your execution path
  #. run below commands, modify the reference manifest as your need.

  Execution in command prompt::

    >python -m intelprot.bmc -start_build -r <refernence_platform>
    >python -m intelprot.bmc -m <manifest_json>


  .. note::
     Please do not change the manifest file keyname when modify the json file.

  Example build eaglestream BMC PFR image::

    # generate reference manifest and keys to work folder
    >cd C:\\shuang4\\Work\\temp\\testbmc
    >python -m intelprot.bmc -start_build -r eaglestream
    # modify the json file and keys, include 128M BMC active "mtd_firmware", run below command to create bmc pfr image
    >python -m intelprot.bmc -m eaglestream/egs_pfr_bmc_manifest.json


  Build in Python console or add to script
  ----------------------------------------

  Code block::

    >>>import os
    >>>os.chdir(<work_folder_path>)
    >>>from intelprot import bmc
    >>>mybmc = bmc.BMC_Build(<reference platform name>)
    >>>mybmc.start_build()  # only need for template manifest json file and keys
    # after modify json file and keys to your files
    >>>mybmc.set_manifest(<pfr_bmc_manifest>)
    >>>mybmc.build_image()

  example::

    >>>import os
    >>>os.chdir(r'C:\shuang4\Work\\temp\\testbmc')
    >>>from intelprot import bmc
    >>>egsbmc=bmc.BMC_Build('eaglestream')
    >>>egsbmc.start_build()
    # modify the manifest json file and replace key files
    >>>egsbmc.set_manifest(r'eaglestram\egs_pfr_bmc_manifest.json')
    >>>egsbmc.build_image()

"""
import binascii, struct, codecs, base64, hashlib, sys, os, shutil

from shutil import copyfile
from array import array
from binascii import unhexlify
from hashlib import sha384, sha256, sha512
from collections import OrderedDict

import argparse, json, urllib3, requests, pathlib
from datetime import datetime
import re, sys, time

#import redfish
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from intelprot import keys, sign, utility

import logging
logger = logging.getLogger(__name__)
import platform, subprocess

_BMC_ACT_PFM   = 0x0080000
_BMC_STAGING   = 0x4A00000
_BMC_RCV_START = 0x2a00000
_PCH_STAGING   = 0x6A00000
_CPLD_STAGING  = 0x7A00000
_EGS_AFM_ACTIVE    = 0x7E00000
_EGS_AFM_RECOVERY  = 0x7E20000
_BHS_AFM_ACTIVE    = 0x7E80000
_BHS_AFM_RECOVERY  = 0x7EA0000
_BHS_AFM_STAG      = 0x7E00000

_CPLD_RECOVERY = 0x7F00000
_PCTYPE_BMC_PFM = 0x3   # pc type used to sign bmc pfm
_PCTYPE_BMC_CAP = 0x4   # pc type used to sign bmc capsule

PFM_TAG = 0x02B3CE1D
PFM_SPI = 0x1  # SPI rule Type
PFM_I2C = 0x2  # I2C rule type
SHA256  = 0x1  # hash256 present
SHA384  = 0x2  # hash384 present
PFM_DEF_SIZE      = 32 # 32 bytes of PFM header
PFM_I2C_BMAP_SIZE = 32 # I2C BITMAP size in bytes
PAGE_SIZE         = 0x1000 # page size 4096B (4 KB)


def load_afm_capsule(bmc_pfr_image, afm_active, afm_recovery, plat='egs'):
  """ load AFM capsule to PFR bmc image

  :param bmc_pfr_image: file name of pfr bmc image
  :param afm_active: afm active capsule
  :param afm_recovery: afm recovery capsule
  :param plat: platform name bhs or egs

  """
  if plat =='egs':
    afm_act_offset = _EGS_AFM_ACTIVE
    afm_rec_offset = _EGS_AFM_RECOVERY
  elif plat == 'bhs':
    afm_act_offset = _BHS_AFM_ACTIVE
    afm_rec_offset = _BHS_AFM_RECOVERY

  out_image = os.path.splitext(bmc_pfr_image)[0]+"_afm.bin"
  with open(out_image, 'wb') as fout, open(bmc_pfr_image, 'rb') as f1:
    fout.write(f1.read())
    with open(afm_active, 'rb') as f2, open(afm_recovery, 'rb') as f3:
      fout.seek(afm_act_offset)
      fout.write(f2.read())
      fout.seek(afm_rec_offset)
      fout.write(f3.read())


class PFR_BMC(object):
  """ class of pfr bmc 128MB binary image operation

  :param fbin: pfr bmc binary image

  """
  def __init__(self, fbin):
    self.fname = fbin
    self.bmc_pfm_offset   = _BMC_ACT_PFM
    self.bmc_recv_offset  = _BMC_RCV_START
    self.bmc_stag_offset  = _BMC_STAGING
    self.pch_stag_offset  = _PCH_STAGING
    self.cpld_stag_offset = _CPLD_STAGING
    self.afm_active_offset= _EGS_AFM_ACTIVE
    self.afm_recv_offset  = _EGS_AFM_RECOVERY
    self.get_pfm_len()

  def set_pfm_offset(self, act_pfm):
    """ set bmc pfm offset

    :param act_pfm: bmc pfm offset

    """
    self.bmc_pfm_offset = act_pfm

  def set_prov_offset(self, act_pfm, rcv_offset, bmc_stag, pch_stag, cpld_stag):
    """ set provision offsets

    :param act_pfm: active image pfm offset
    :param rcv_offset: recover offset
    :param bmc_stag: bmc staging offset
    :param pch_stag: bmc staging offset
    :param cpld_stag: cpld staging offset

    """
    self.bmc_pfm_offset = act_pfm
    self.bmc_rcv_offset = rcv_offset
    self.bmc_stag_offset  = bmc_stag
    self.pch_stag_offset  = pch_stag
    self.cpld_stag_offset = cpld_stag

  def load_manifest(self, fname_bmc_manifest):
    """ load pfr bmc manifest json file

    :param fname_bmc_manifest: file name of bmc image manifest json file

    """
    with open(fname_bmc_manifest, 'r') as f:
      self.bmc_manifest=json.load(f)

  def load_staging_image(self, capsule_image, type='pch', fsta = None):
    """ load capsule image to BMC flash staging area, default type is pch

    :param capsule_image: file name of signed update capsule image
    :param type: type of signed capsule_image 'pch'/'bmc'/'cpld', default is 'pch'

    """
    fcap=capsule_image
    if fsta == None:
      fsta=os.path.splitext(self.fname)[0]+"_%s_capsule.bin"%type
    shutil.copy(self.fname, fsta)
    with open(fcap, 'rb') as f1:
      outb=f1.read()
    with open(fsta, 'r+b') as f2:
      if type.lower() == 'pch':  f2.seek(self.pch_stag_offset)
      if type.lower() == 'bmc':  f2.seek(self.bmc_stag_offset)
      if type.lower() == 'cpld': f2.seek(self.cpld_stag_offset)
      f2.write(outb)

  def load_cpld_recovery(self, cpld_capsule, frcv=None, offset=None):
    """ load CPLD recovery image

    :param cpld_capsule: CPLD recovery capsule image
    :param frcv: output image = default is <bmc_image>_cpld_rcvy.bin (use default)
    :param offset: CPLD recovery offset address, default is 0x7F00000 (if no change of CPLD code)

    """
    if cpld_capsule == None:
      print("-- Error: need cpld recovery capsule image !")
      return -1
    else:
      fcap = cpld_capsule
    if offset == None:
      offset = _CPLD_RECOVERY
    if frcv == None:
      frcv = os.path.splitext(self.fname)[0]+"_cpld_rcvy.bin"
    shutil.copy(self.fname, frcv)
    with open(fcap, 'rb') as f1:
      outb = f1.read()
    with open(frcv, 'r+b') as f2:
      f2.seek(offset)
      f2.write(outb)

  def get_pfm_len(self):
    """get pfm length """
    with open(self.fname, 'rb') as f:
      f.seek(self.bmc_pfm_offset+0x400+28) # to read pfm_len
      self.active_pfm_len = int.from_bytes(f.read(4), 'little')
      f.seek(self.bmc_recv_offset+0x800+28)
      self.recv_pfm_len = int.from_bytes(f.read(4), 'little')
      f.seek(self.bmc_stag_offset+0x800+28)
      self.stag_pfm_len = int.from_bytes(f.read(4), 'little')

  def show_pfm(self):
    """ display pfm in the update capsule """
    self.pfm.show()

  def show(self):
    """ display update capsule information """
    logger.info('SVN: {:d}'.format(self.svn))
    logger.info('BKC: {:d}'.format(self.bkc))
    logger.info('PFM Revision: {:d}.{:d}'.format(self.pfm_major, self.pfm_minor))
    logger.info('OEM: 0x{:s}'.format(self.oem.hex()))
    logger.info('PFM Length: 0x{:x}'.format(self.pfm_len))
    self.show_pfm()

  def get_svn(self):
    """ return capsule SVN value """
    return self.svn

  def get_bkc(self):
    """ return capsule BKC revision"""
    return self.bkc

  def get_pfm_rev(self):
    """ return capsule PFM revision in (major, minor) format """
    return (self.pfm_major, self.pfm_minor)

  def get_build_num(self):
    """ return capsule build number"""
    return int(self.oem[0].hex(), 16)

  def get_oem(self):
    """ return capsule OEM bytes in hex string """
    return self.oem.hex()


class pfr_bmc_image(object):
  """ class to build BMC pfr image including PFM, and capsule from its manifest json file

  :param manifest: image manifest JSON file, include all required information. It is generated from reference json file

  """
  def __init__(self, manifest):
    with open(manifest, 'r') as fd:
      self.manifest    = json.load(fd)

    self.dict_build_image = self.manifest['build_image']
    self.dict_spi_parts   = self.manifest['image-parts']
    self.dict_i2c_rules   = self.manifest['i2c-rules']

    for k in ['csk_id', 'build_major', 'build_minor', 'build_num', 'svn', 'bkc_version']:
      self.dict_build_image[k] = int(self.dict_build_image[k], 16)

    self.pfr_bmc_image_size = 0
    for d in self.dict_spi_parts:
      d['offset'] = int(d['offset'], 16)
      d['size'] = int(d['size'], 16)
      if d['offset'] > self.pfr_bmc_image_size:
        self.pfr_bmc_image_size = d['offset'] + d['size']
    print('self.pfr_bmc_image_size = 0x{:08x}'.format(self.pfr_bmc_image_size))

    for d in self.dict_i2c_rules:
      d['address'] = int(d['address'], 16)
      d['cmd_bitmap'] = bytearray(PFM_I2C_BMAP_SIZE)
      for c in d['cmd-allowlist']:
        if c == "all":
          for i in range(PFM_I2C_BMAP_SIZE):
            d['cmd_bitmap'][i] = 0xff
            break
        else:
          idx = int(c,16) // 8 # index in the 32 bytes of allow list i2c cmds
          bit = int(c,16) % 8 # bit position to set
          d['cmd_bitmap'][idx] |= (1 << bit)

    self.platform_name = self.manifest['build_image']['platform_name']
    self.firmware_file = self.manifest['build_image']['mtd_firmware']
    #self.csk_prv = self.manifest['build_image']['csk_private_key']
    #self.rk_prv  = self.manifest['build_image']['root_private_key']
    self.csk_prv = os.path.join(os.path.dirname(manifest), self.manifest['build_image']['csk_private_key'])
    self.rk_prv  = os.path.join(os.path.dirname(manifest), self.manifest['build_image']['root_private_key'])

    self.pfr_ver = 3 if keys.get_curve(self.csk_prv) == 'NIST384p' else 2

    self.page_size = PAGE_SIZE
    self.empty = b'\xff' * self.page_size

    if self.pfr_ver == 2:
      self.hash_func = hashlib.sha256    # for PFR 2.0, use sha256 algorithm
    elif self.pfr_ver == 3:
      self.hash_func = hashlib.sha384    # for PFR 3.0, use sha384 algorithm

    # hash, erase and compression bit maps for 128MB
    self.pbc_erase_bitmap = bytearray(int(self.pfr_bmc_image_size/(PAGE_SIZE*8))) # (FlashSize)/(4K*8)
    self.pbc_comp_bitmap  = bytearray(int(self.pfr_bmc_image_size/(PAGE_SIZE*8))) # (FlashSize)/(4K*8)
    self.pbc_comp_payload = 0

  def build_pfm(self):
    """ build PFM based on rules defined in manifest file

    """
    # calculate and add hash_data
    self.pfm_header = b''
    self.pfm_size = 0

    print(self.dict_build_image)

    self.pfm_header += struct.pack('<IBBBB4sI12s', PFM_TAG, self.dict_build_image['svn'], self.dict_build_image['bkc_version'], \
                      self.dict_build_image['build_major'], self.dict_build_image['build_minor'], \
                      b'\xff'*4, self.dict_build_image['build_num'], b'\xff'*12)
    self.pfm_body = b''
    with open(self.firmware_file, 'rb') as f:
      for p in self.dict_spi_parts:
        start_addr = p['offset']
        area_size  = p['size']
        if p['pfm'] == 1:
          if self.pfr_ver == 0x2 and p['hash'] != 0: p['hash'] = 1
          if self.pfr_ver == 0x3 and p['hash'] != 0: p['hash'] = 2
          self.pfm_body += struct.pack('<BBH4sII', PFM_SPI, p['prot_mask'], p['hash'], b'\xff'*4, start_addr, (start_addr+area_size))
          if p['hash'] != 0:
            f.seek(start_addr)
            bdata = f.read(area_size)
            p['hash_data'] = self.hash_func(bdata).hexdigest()
            print(p['hash_data'])
          else:
            p['hash_data'] = ''
          self.pfm_body += bytes.fromhex(p['hash_data'])

    # add i2c-rules
    bdata_i2c = b''
    for d in self.dict_i2c_rules:
       bdata_i2c += struct.pack('<B4sBBB32s', PFM_I2C, b'\xff'*4, d['bus-id'], d['rule-id'], d['address'], d['cmd_bitmap'])

    #print(bdata_i2c.hex())
    self.pfm_body += bdata_i2c
    self.pfm_size = PFM_DEF_SIZE + len(self.pfm_body)

    # PFM should be 128bytes aligned, find the padding bytes
    padding_bytes = 0
    if (self.pfm_size % 128) != 0:
      padding_bytes = 128 - (self.pfm_size % 128)
    self.pfm_size += padding_bytes
    self.pfm_header += struct.pack('<I', self.pfm_size)
    with open("%s-pfm.bin" % self.platform_name, "wb+") as f:
      f.write(self.pfm_header)
      f.write(self.pfm_body)
      f.write(b'\xff' * padding_bytes)


  def build_update_capsule(self):
    """ build unsigned bmc update capsule using PBC algorithm
    """
    # find skip ranges in page # in 'pfm' and 'rc-image' area
    # The pages to be skipped for HASH and PBC
    # Pages: 0x80 to 0x9f - starting PFM region until end of pfm
    # Pages: 0x2a00 to 0x7FFF - starting RC-image until end of flash
    # in reference design: EXCLUDE_PAGES =[[0x80, 0x9f],[0x2a00,0x7fff]]
    for d in self.dict_spi_parts:
      if d['name']=='pfm':
        idx = d['index']
        pfm_st = d['offset']
        pfm_end= d['offset'] + d['size']
      if d['name']=='rc-image':
        idx = d['index']
        rcimg_st = d['offset']
        rcimg_end= d['offset'] + d['size']

    self.pfr_pfm_offset = pfm_st
    self.pfr_capsule_offset = rcimg_st
    exclude_pages =[[pfm_st//0x1000, (pfm_end-0x1000)//0x1000],[rcimg_st//0x1000, (rcimg_end-0x1000)//0x1000]]
    comp_payload = b''   # compression payload
    with open("%s-bmc_compressed.bin" % self.platform_name, "wb+") as upd:
      with open(self.firmware_file, "rb") as f:
        # process all spi image parts
        for p in self.dict_spi_parts:
          image_name = p['name']
          start_addr = p['offset']
          size = p['size']
          pfm_prot_mask = p['prot_mask']  # pfm protection mask
          pfm_flag = p['pfm']             # pfm needed?
          hash_flag = p['hash']           # to be hashed?
          compress = p['compress']        # compress flag
          index = p['index']              # image part index
          # 1 page is 4KB, page number of address 0x80000 is 0x80
          page = start_addr >> 12         # one page is 0x1000, page number is address right-shift 12 bits

          #print("--page: {}, start_addr = 0x{:x}, p = {}".format(page, start_addr, p))
          f.seek(start_addr)
          skip = False

          for chunk in iter(lambda: f.read(self.page_size), b''):
            chunk_len = len(chunk)
            if chunk_len != self.page_size:
              chunk = b''.join([chunk, b'\xff' * (self.page_size - chunk_len)])

            for p in exclude_pages:
              if (page >= p[0]) and (page <= p[1]):
                skip = True
                break

            if (not skip) and (compress == 1):
              self.pbc_erase_bitmap[page >> 3] |= 1 << (7- (page % 8)) # Big endian bit map
              # add to the pbc map
              if chunk != self.empty:
                upd.write(chunk)  # write to file
                self.pbc_comp_bitmap[page >> 3] |= 1 << (7- (page % 8)) # Big Endian bit map
                self.pbc_comp_payload += chunk_len # compressed payload length in bytes
            page += 1
            if (page * self.page_size) >= (size + start_addr):
              break

      # pbc header
      pbc_tag = struct.pack('<I', 0x5f504243)
      pbc_ver = struct.pack('<I', 0x2)
      page_size = struct.pack('<I', 0x1000)  # page size 4*1024 = 0x1000
      patt_size = struct.pack('<I', 0x1)
      patt_comp = struct.pack('<I', 0xFF)
      bmap_size = struct.pack('<I', int(self.pfr_bmc_image_size/PAGE_SIZE)) # 4k granularity, 0x8000 is 128MB, 0x10000 is for 256MB
      pload_len = struct.pack('<I', self.pbc_comp_payload)
      rsvd0     = b'\x00'*100
      erase_bitmap = bytes(self.pbc_erase_bitmap)
      comp_bitmap  = bytes(self.pbc_comp_bitmap)
      self.pbc_header = pbc_tag + pbc_ver + page_size + patt_size + \
                      patt_comp + bmap_size + pload_len + rsvd0 + erase_bitmap + comp_bitmap
      with open("%s-pbc.bin" % self.platform_name, "wb+") as pbf:
        pbf.write(self.pbc_header)


  def build_pfr_image(self):
    """ build bmc pfr image """
    print("\n-- 1. build pfm and update capsule\n")
    self.build_pfm()                 # build_pfm
    self.build_update_capsule()      # build_update_capsule

    print("\n-- 2. signPFM\n")
    spfm = sign.Signing("{}-pfm.bin".format(self.platform_name), _PCTYPE_BMC_PFM, self.dict_build_image['csk_id'], self.rk_prv, self.csk_prv)
    spfm.set_signed_image("%s-pfm_signed.bin"%(self.platform_name))
    spfm.sign()

    print ("\n-- 3. Add the signed PFM to rom image\n")
    fname_a = "%s-pfm_signed.bin"%(self.platform_name)
    fname_o = "%s-image-pfm_signed.bin"%(self.platform_name)

    print('pfr_pfm_offset = 0x%x'%self.pfr_pfm_offset)
    with open(self.firmware_file, 'rb') as fin, open(fname_o, 'wb') as fout:
      fout.write(fin.read())
    utility.bind_file_at_addr(fname_a, fname_o, self.pfr_pfm_offset)

    #  Create unsigned BMC update capsule - append with 1. pfm_signed, 2. pbc, 3. bmc compressed;
    print ("\n-- 4. Create unsigned BMC update capsule \n")
    f1 = "%s-pfm_signed.bin"%(self.platform_name)
    f2 = "%s-pbc.bin"%(self.platform_name)
    f3 = "%s-bmc_compressed.bin"%(self.platform_name)
    f4 = "%s-bmc_unsigned_cap.bin"%(self.platform_name)

    with open(f4, 'wb') as fd4, open(f1, 'rb') as fd1, open(f2, 'rb') as fd2, open(f3, 'rb') as fd3:
      fd4.write(fd1.read())
      fd4.write(fd2.read())
      fd4.write(fd3.read())

    print("-- sign update capsule")
    scap = sign.Signing("{}-bmc_unsigned_cap.bin".format(self.platform_name), _PCTYPE_BMC_CAP,  self.dict_build_image['csk_id'], self.rk_prv, self.csk_prv)
    scap.set_signed_image("%s-bmc_signed_cap.bin"%(self.platform_name))
    scap.sign()

    # 6) Add the signed bmc update capsule to full rom image @ rc-image offset
    print ("\n-- 6. Add the signed bmc update capsule to full rom image @ rc-image offset, defined in json file (default 0x2a00000) \n")
    fname_a   = "%s-bmc_signed_cap.bin"%(self.platform_name)
    fname_o   = "%s-pfr-image-bmc-final.bin"%(self.platform_name)
    fname_src = "%s-image-pfm_signed.bin"%(self.platform_name)

    shutil.copyfile(fname_src, fname_o)
    print('pfr_capsule_offset = 0x%x'%self.pfr_capsule_offset)
    utility.bind_file_at_addr(fname_a, fname_o, self.pfr_capsule_offset)
    self.move_temp_file()

  def move_temp_file(self):
    """ Move output files and temporary files to Output and Temp subfolder.
        Create subfolder if not exists
    """
    print("\n-- move temporary file")
    pathlib.Path(os.path.join(os.getcwd(), 'Output')).mkdir(parents=True, exist_ok=True)
    pathlib.Path(os.path.join(os.getcwd(), 'Temp')).mkdir(parents=True, exist_ok=True)

    lst_temp_file = ["pfm.bin", "bmc_compressed.bin", "pbc.bin", "pfm_signed.bin", "bmc_unsigned_cap.bin"]
    lst_out_file = ["bmc_signed_cap.bin", "pfr-image-bmc-final.bin"]
    lst_del_file = ["{}-image-pfm_signed.bin".format(self.platform_name)]
    for f in lst_temp_file:
      src_file = "%s-%s"%(self.platform_name, f)
      dst_file = os.path.join(os.getcwd(), 'Temp', src_file)
      shutil.move(src_file, dst_file)
    for f in lst_out_file:
      src_file = "%s-%s"%(self.platform_name, f)
      dst_file = os.path.join(os.getcwd(), 'Output', src_file)
      shutil.move(src_file, dst_file)
    for f in lst_del_file:
      os.remove(f)



# reference design namme and pfr bmc manifest file
_DICT_REF_MANIFEST = {
  'whitley'    : 'whitley_pfr_bmc_manifest.json',
  'idaville'   : 'idaville_pfr_bmc_manifest.json',
  'eaglestream': 'egs_pfr_bmc_manifest.json',
  'birchstream': 'bhs_pfr_bmc_manifest.json',
}

_list_reference_project = ['idaville', 'whitley', 'eaglestream', 'egs', 'birchstream', 'bhs']


class BMC_Build(object):
  """ build PFR BMC image, this is a wrap class for commandline options

  """
  def __init__(self, reference_platform):
    self.reference = reference_platform
    self.dict_manifest = _DICT_REF_MANIFEST

  def start_build(self):
    """ Copy manifest json file and keys to a subdirectory inside work folder.
        subfolder is names as the reference platform
        User can modify the json file for customize needs
        The 128MB or 256MB mtd_image should be saved in the work folder
    """
    refplat = self.reference
    if refplat not in _list_reference_project:
      logger.error("-- wrong reference name!")
      return
    refjson = self.dict_manifest[refplat]
    print("-- self.reference = {}".format(self.reference))
    pathlib.Path(os.path.join(os.getcwd(), refplat)).mkdir(parents=True, exist_ok=True)
    lst_keys = ('key_root_prv.pem', 'key_csk_prv.pem')
    for f in lst_keys:
      src_f = os.path.join(os.path.dirname(__file__), 'keys', refplat, f)
      dst_f = os.path.join(os.getcwd(), refplat, f)
      shutil.copyfile(src_f, dst_f)
    src_json_file = os.path.join(os.path.dirname(__file__), 'json', 'bmc', refjson)
    dst_json_file = os.path.join(os.getcwd(), refplat, refjson)
    shutil.copyfile(src_json_file, dst_json_file)

  def set_manifest(self, manifest):
    print('-- set manifest')
    self.manifest_f = manifest #os.path.join(os.getcwd(), self.reference, self.dict_manifest[self.reference])

  def build_image(self):
    """ build image """
    print("-- self.reference = {}".format(self.reference))

    if self.reference.startswith('bhs') or self.reference.startswith('birch'):
      # build image for BHS platform
      mybmc=BHS_PFR_BMC_AFM(self.manifest_f)
      mybmc.build_pfr_image()
    else:
      mybmc = pfr_bmc_image(self.manifest_f)
      mybmc.build_pfr_image()


class BHS_PFR_BMC_AFM(object):
  """
    class to add AFM and update PFM with AFM

  """
  def __init__(self, manifest):
    with open(manifest, 'r') as fd:
      self.manifest    = json.load(fd)

    self.afm_header  = self.manifest["build_image"]["afm_header"]
    self.afm_active_capsule  = self.manifest["build_image"]["afm_active_capsule"]

    self.dict_build_image = self.manifest['build_image']
    self.dict_spi_parts   = self.manifest['image-parts']
    self.dict_i2c_rules   = self.manifest['i2c-rules']

    for k in ['csk_id', 'build_major', 'build_minor', 'build_num', 'svn', 'bkc_version']:
      self.dict_build_image[k] = int(self.dict_build_image[k], 16)

    self.pfr_bmc_image_size = 0
    for d in self.dict_spi_parts:
      d['offset'] = int(d['offset'], 16)
      d['size'] = int(d['size'], 16)
      if d['offset'] > self.pfr_bmc_image_size:
        self.pfr_bmc_image_size = d['offset'] + d['size']
    print('self.pfr_bmc_image_size = 0x{:08x}'.format(self.pfr_bmc_image_size))

    for d in self.dict_i2c_rules:
      d['address'] = int(d['address'], 16)
      d['cmd_bitmap'] = bytearray(PFM_I2C_BMAP_SIZE)
      for c in d['cmd-allowlist']:
        if c == "all":
          for i in range(PFM_I2C_BMAP_SIZE):
            d['cmd_bitmap'][i] = 0xff
            break
        else:
          idx = int(c,16) // 8 # index in the 32 bytes of allow list i2c cmds
          bit = int(c,16) % 8 # bit position to set
          d['cmd_bitmap'][idx] |= (1 << bit)

    self.platform_name = self.manifest['build_image']['platform_name']
    self.firmware_file = self.manifest['build_image']['mtd_firmware']
    #self.csk_prv = self.manifest['build_image']['csk_private_key']
    #self.rk_prv  = self.manifest['build_image']['root_private_key']
    self.csk_prv = os.path.join(os.path.dirname(manifest), self.manifest['build_image']['csk_private_key'])
    self.rk_prv  = os.path.join(os.path.dirname(manifest), self.manifest['build_image']['root_private_key'])

    self.pfr_ver = 4

    self.page_size = PAGE_SIZE
    self.empty = b'\xff' * self.page_size

    self.hash_func = hashlib.sha384    # for PFR 4.0, use sha384 algorithm

    # hash, erase and compression bit maps for 128MB
    self.pbc_erase_bitmap = bytearray(int(self.pfr_bmc_image_size/(PAGE_SIZE*8))) # (FlashSize)/(4K*8)
    self.pbc_comp_bitmap  = bytearray(int(self.pfr_bmc_image_size/(PAGE_SIZE*8))) # (FlashSize)/(4K*8)
    self.pbc_comp_payload = 0

  def build_pfm(self):
    """ build PFM based on rules defined in manifest file

    """
    # calculate and add hash_data
    self.pfm_header = b''
    self.pfm_region_size = 0

    print(self.dict_build_image)

    self.pfm_header += struct.pack('<IBBBB4sI12s', PFM_TAG, self.dict_build_image['svn'], self.dict_build_image['bkc_version'], \
                      self.dict_build_image['build_major'], self.dict_build_image['build_minor'], \
                      b'\xff'*4, self.dict_build_image['build_num'], b'\xff'*12)
    self.pfm_body = b''
    with open(self.firmware_file, 'rb') as f:
      #print(self.dict_spi_parts)
      for p in self.dict_spi_parts:
        #print("name={}, p['offset']={}".format(p['name'], p['offset']))
        start_addr = p['offset']
        area_size  = p['size']
        if p['name'] == 'pfm':
          self.pfm_offset = p['offset']
          self.pfm_region_size = p['size']
        if p['pfm'] == 1:
          if p['hash'] != 0: p['hash'] = 2
          self.pfm_body += struct.pack('<BBH4sII', PFM_SPI, p['prot_mask'], p['hash'], b'\xff'*3 + b'\x00', start_addr, (start_addr+area_size))

          if p['hash'] != 0:
            f.seek(start_addr)
            bdata = f.read(area_size)
            p['hash_data'] = self.hash_func(bdata).hexdigest()
            print(p['hash_data'])
          else:
            p['hash_data'] = ''
          self.pfm_body += bytes.fromhex(p['hash_data'])

    # add i2c-rules
    bdata_i2c = b''
    for d in self.dict_i2c_rules:
       bdata_i2c += struct.pack('<B4sBBB32s', PFM_I2C, b'\xff'*4, d['bus-id'], d['rule-id'], d['address'], d['cmd_bitmap'])
    #print(bdata_i2c.hex())
    self.pfm_body += bdata_i2c

    # add AFM header in pfm sign area
    bdata_afm_header = b''
    with open(self.afm_header, 'rb') as f:
      bdata_afm_header = f.read()
    self.afm_addr = struct.unpack('<I', bdata_afm_header[-4:])[0]

    self.pfm_body += bdata_afm_header
    self.pfm_size = PFM_DEF_SIZE + len(self.pfm_body)

    # PFM should be 128bytes aligned, find the padding bytes
    padding_bytes = 0
    if (self.pfm_size % 128) != 0:
      padding_bytes = 128 - (self.pfm_size % 128)
    self.pfm_size += padding_bytes
    self.pfm_header += struct.pack('<I', self.pfm_size)
    self.pfm_unsigned = "{}-pfm.bin".format(self.platform_name)
    with open(self.pfm_unsigned, "wb+") as f:
      f.write(self.pfm_header)
      f.write(self.pfm_body)
      f.write(b'\xff' * padding_bytes)

  def add_active_afm(self):
    """ add active afm capsule to pfm area after signed pfm, also check AFM address is 4K aligned and 8K maximum"""
    self.firmware_image_afm_in_pfm = os.path.splitext(self.firmware_file)[0]+'_afm.bin'
    self.pfm_signed = "%s-pfm_signed.bin"%(self.platform_name)
    self.pfm_region = "pfm_region_afm.bin"
    pfm_signed_size = os.stat(self.pfm_signed).st_size
    print("pfm_signed_size: {}, afm_addr: {}".format(hex(pfm_signed_size), hex(self.afm_addr)))
    if pfm_signed_size < 0x1000:
      padding_size_1 = self.afm_addr - self.pfm_offset - pfm_signed_size
    else:
      logger.critical('--Error: AFM address wrong')
      STOP
    read_afm_capsule_size = self.pfm_region_size - pfm_signed_size - padding_size_1
    print('read_afm_capsule_size={}, pfm_region_size={}-pfm_signed_size={}-padding_size_1{}'.format(read_afm_capsule_size, self.pfm_region_size, pfm_signed_size, padding_size_1))
    with open(self.pfm_signed, 'rb') as f1, open(self.afm_active_capsule, 'rb') as f2, open(self.pfm_region, 'wb') as f3:
      f3.write(f1.read())
      f3.write(b'\xff'*padding_size_1)
      f3.write(f2.read(read_afm_capsule_size))
    # update mtd file to build bmc recovery capsule
    with open(self.firmware_file, 'rb') as f1, open(self.pfm_region, 'rb') as f2, \
         open(self.firmware_image_afm_in_pfm, 'wb') as f3:
      f3.write(f1.read(self.pfm_offset))
      f3.write(f2.read())
      f1.seek(self.pfm_offset + self.pfm_region_size)
      f3.write(f1.read())

  def build_update_capsule(self):
    """ build unsigned bmc update capsule using PBC algorithm
    """
    # find skip ranges in page # in 'pfm' and 'rc-image' area
    # The pages to be skipped for HASH and PBC
    # Pages: 0x80 to 0x9f - starting PFM region until end of pfm
    # Pages: 0x2a00 to 0x7FFF - starting RC-image until end of flash
    # in reference design: EXCLUDE_PAGES =[[0x80, 0x9f],[0x2a00,0x7fff]]
    for d in self.dict_spi_parts:
      if d['name']=='pfm':
        idx = d['index']
        pfm_st = d['offset']
        pfm_end= d['offset'] + d['size']
      if d['name']=='rc-image':
        idx = d['index']
        rcimg_st = d['offset']
        rcimg_end= d['offset'] + d['size']

    self.pfr_pfm_offset = pfm_st
    self.pfr_capsule_offset = rcimg_st
    exclude_pages =[[pfm_st//0x1000, (pfm_end-0x1000)//0x1000],[rcimg_st//0x1000, (rcimg_end-0x1000)//0x1000]]
    comp_payload = b''   # compression payload
    with open("%s-bmc_compressed.bin" % self.platform_name, "wb+") as upd:
      # use update pfm area mtd file, include afm in bmc recovery capsule
      with open(self.firmware_image_afm_in_pfm, "rb") as f:
        # process all spi image parts
        for p in self.dict_spi_parts:
          image_name = p['name']
          start_addr = p['offset']
          size = p['size']
          pfm_prot_mask = p['prot_mask']  # pfm protection mask
          pfm_flag = p['pfm']             # pfm needed?
          hash_flag = p['hash']           # to be hashed?
          compress = p['compress']        # compress flag
          index = p['index']              # image part index
          # 1 page is 4KB, page number of address 0x80000 is 0x80
          page = start_addr >> 12         # one page is 0x1000, page number is address right-shift 12 bits

          #print("--page: {}, start_addr = 0x{:x}, p = {}".format(page, start_addr, p))
          f.seek(start_addr)
          skip = False

          for chunk in iter(lambda: f.read(self.page_size), b''):
            chunk_len = len(chunk)
            if chunk_len != self.page_size:
              chunk = b''.join([chunk, b'\xff' * (self.page_size - chunk_len)])

            for p in exclude_pages:
              if (page >= p[0]) and (page <= p[1]):
                skip = True
                break

            if (not skip) and (compress == 1):
              self.pbc_erase_bitmap[page >> 3] |= 1 << (7- (page % 8)) # Big endian bit map
              # add to the pbc map
              if chunk != self.empty:
                upd.write(chunk)  # write to file
                self.pbc_comp_bitmap[page >> 3] |= 1 << (7- (page % 8)) # Big Endian bit map
                self.pbc_comp_payload += chunk_len # compressed payload length in bytes
            page += 1
            if (page * self.page_size) >= (size + start_addr):
              break

      # pbc header
      pbc_tag = struct.pack('<I', 0x5f504243)
      pbc_ver = struct.pack('<I', 0x2)
      page_size = struct.pack('<I', 0x1000)  # page size 4*1024 = 0x1000
      patt_size = struct.pack('<I', 0x1)
      patt_comp = struct.pack('<I', 0xFF)
      bmap_size = struct.pack('<I', int(self.pfr_bmc_image_size/PAGE_SIZE)) # 4k granularity, 0x8000 is 128MB, 0x10000 is for 256MB
      pload_len = struct.pack('<I', self.pbc_comp_payload)
      rsvd0     = b'\x00'*100
      erase_bitmap = bytes(self.pbc_erase_bitmap)
      comp_bitmap  = bytes(self.pbc_comp_bitmap)
      self.pbc_header = pbc_tag + pbc_ver + page_size + patt_size + \
                      patt_comp + bmap_size + pload_len + rsvd0 + erase_bitmap + comp_bitmap
      with open("%s-pbc.bin" % self.platform_name, "wb+") as pbf:
        pbf.write(self.pbc_header)

  def build_pfm_afm_in_update_capsule(self):
    """ build PFM area inside recovery update capsule

    It includes signed-PFM (with AFM address definition) and signed-afm defined in afm address header.
    """
    # create "pfm_afm_in_update_cap.bin" file included in recovery capsule
    self.pfm_afm_in_update_cap = "{}-pfm_afm_in_update_cap.bin".format(self.platform_name)
    if os.stat(self.pfm_unsigned).st_size < 0x1000:
      read_afm_size = os.stat(self.afm_active_capsule).st_size
      padding_size  = (self.afm_addr - self.pfm_offset) - (self.pfm_size + 0x400)
    with open(self.pfm_afm_in_update_cap, 'wb') as f1, \
         open(self.pfm_signed, 'rb') as f2, open(self.afm_active_capsule, 'rb') as f3:
      f1.write(f2.read())
      f1.write(b'\xff'*padding_size)  # padd 0xFF until afm address
      f1.write(f3.read(read_afm_size))

  def build_pfr_image(self):
    """ build bmc pfr image """
    print("\n-- 1. build pfm \n")
    self.build_pfm()                 # build_pfm

    print("\n-- 2. signPFM\n")
    self.pfm_signed = "{}-pfm_signed.bin".format(self.platform_name)

    print(self.pfm_unsigned, self.pfm_signed)

    spfm = sign.Signing(self.pfm_unsigned, _PCTYPE_BMC_PFM, self.dict_build_image['csk_id'], self.rk_prv, self.csk_prv)
    spfm.set_signed_image(self.pfm_signed)
    spfm.sign()

    print("\n-- 3. add afm_capsule to pfm area and update mtd_file to build update capsule\n")
    self.add_active_afm()

    print("\n-- 4. build_update_capsule\n")
    # update mtd_firmware for update capsule
    self.build_update_capsule()      # build_update_capsule


    print ("\n-- 5. add the signed PFM to rom image\n")
    #fname_a = "%s-image-pfm_signed.bin"%(self.platform_name)
    fname_o = "%s-image-pfm_signed.bin"%(self.platform_name)

    #print('pfr_pfm_offset = 0x%x'%self.pfr_pfm_offset)
    with open(self.firmware_image_afm_in_pfm, 'rb') as fin, open(fname_o, 'wb') as fout:
      fout.write(fin.read())
    utility.bind_file_at_addr(self.pfm_region, fname_o, self.pfm_offset)

    #  Create unsigned BMC update capsule - append with 1. pfm_signed_afm, 2. pbc, 3. bmc compressed;
    print ("\n-- 6. Create unsigned BMC update capsule \n")
    self.build_pfm_afm_in_update_capsule()
    f1 = self.pfm_afm_in_update_cap      # self.pfm_region
    f2 = "%s-pbc.bin"%(self.platform_name)
    f3 = "%s-bmc_compressed.bin"%(self.platform_name)
    f4 = "%s-bmc_unsigned_cap.bin"%(self.platform_name)

    with open(f4, 'wb') as fd4, open(f1, 'rb') as fd1, open(f2, 'rb') as fd2, open(f3, 'rb') as fd3:
      fd4.write(fd1.read())
      fd4.write(fd2.read())
      fd4.write(fd3.read())

    print("-- sign update capsule")
    scap = sign.Signing("{}-bmc_unsigned_cap.bin".format(self.platform_name), _PCTYPE_BMC_CAP,  self.dict_build_image['csk_id'], self.rk_prv, self.csk_prv)
    scap.set_signed_image("%s-bmc_signed_cap.bin"%(self.platform_name))
    scap.sign()

    # 6) Add the signed bmc update capsule to full rom image @ rc-image offset
    print ("\n-- 6. Add the signed bmc update capsule to full rom image @ rc-image offset, defined in json file (default 0x2f00000) \n")
    fname_a   = "%s-bmc_signed_cap.bin"%(self.platform_name)
    fname_o   = "%s-pfr-image-bmc-final_afm.bin"%(self.platform_name)
    fname_src = "%s-image-pfm_signed.bin"%(self.platform_name)

    shutil.copyfile(fname_src, fname_o)
    print('pfr_capsule_offset = 0x%x'%self.pfr_capsule_offset)
    utility.bind_file_at_addr(fname_a, fname_o, self.pfr_capsule_offset)

    #fname_o_1   = "%s-pfr-image-bmc-final_afm_1.bin"%(self.platform_name)
    #with open(fname_o_1, 'wb') as f1, open(fname_o, 'rb') as f2, open(fname_a, 'rb') as f3:
    #  f1.write(f2.read(self.pfr_capsule_offset))
    #  f1.write(f3.read())
    #  f2.seek(self.pfr_capsule_offset+os.stat(fname_a).st_size)
    #  f1.write(f2.read())

    self.move_temp_file()

  def move_temp_file(self):
    """ Move output files and temporary files to Output and Temp subfolder.
        Create subfolder if not exists
    """
    print("\n-- move temporary file")
    pathlib.Path(os.path.join(os.getcwd(), 'Output')).mkdir(parents=True, exist_ok=True)
    pathlib.Path(os.path.join(os.getcwd(), 'Temp')).mkdir(parents=True, exist_ok=True)

    lst_temp_file = ["pfm.bin", "bmc_compressed.bin", "pbc.bin", "pfm_signed.bin", "bmc_unsigned_cap.bin", "pfm_afm_in_update_cap.bin"]
    lst_out_file = ["bmc_signed_cap.bin", "pfr-image-bmc-final_afm.bin"]
    lst_del_file = ["{}-image-pfm_signed.bin".format(self.platform_name), self.firmware_image_afm_in_pfm]
    for f in lst_temp_file:
      src_file = "%s-%s"%(self.platform_name, f)
      dst_file = os.path.join(os.getcwd(), 'Temp', src_file)
      shutil.move(src_file, dst_file)

    src_file = 'pfm_region_afm.bin'
    dst_file = os.path.join(os.getcwd(), 'Temp', src_file)
    shutil.move(src_file, dst_file)

    for f in lst_out_file:
      src_file = "%s-%s"%(self.platform_name, f)
      dst_file = os.path.join(os.getcwd(), 'Output', src_file)
      shutil.move(src_file, dst_file)
    for f in lst_del_file:
      os.remove(f)


class BMC_OOB_Mailbox(object):
  """ class of BMC OOB access to CPLD Mailbox

     After login as root in BMC console, type "i2cdump -y 4 0x38" to check if it returns valid values.

     Console OOB command:
       ipmitool raw 0x3e 0x84 0x0 0x7f 0  # read mailbox 0x0--0x7F, format: raw 0x3e 0x84 <start_addr> <end_addr> 0
       ipmitool raw 0x3e 0x84 0x08 48  1  # read root key hash
       ipmitool raw 0x3e 0x84 0x0C 12  1  # read IFWI offset 12 bytes
       ipmitool raw 0x3e 0x84 0x0D 12  1  # read BMC offset 12 bytes
       ipmitool raw 0x3e 0x84 0x13 96  1  # read deviceID public key 96 bytes

  """
  def __init__(self, bmc_ip, username='debuguser', passwd='0penBmc1'):
    self.bmc_ip = bmc_ip
    self.user_name = username
    self.passwd = passwd
    self.mailbox_json = os.path.join(os.path.dirname(__file__), r'json\cpld_mailbox.json')
    if platform.system() == 'Windows':
      self.ipmitool = os.path.join(os.path.dirname(__file__), r'ipmitool\ipmitool.exe')
    elif platform.system() == 'Linux':
      self.ipmitool = 'ipmitool'
    self.dict_mbox = sign.ConfigDict()  # dictionary of CPLD mailbox
    self.dict_prov = sign.ConfigDict()  # dictionary of CPLD provisioning data
    #print(self.ipmitool)

  def read_mailbox(self):
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x0 0x7f 0".format(self.ipmitool, self.bmc_ip, \
              self.user_name, self.passwd)
    result = subprocess.getoutput(cmdline).split('\n')
    result = ''.join(result)
    #print(result)
    idx=result.index('de')
    result=result[idx:]   # get content from first identifier 'de'
    lst_cpld_mailbox = result.split(' ')
    self.lst_cpld_mailbox = lst_cpld_mailbox
    return lst_cpld_mailbox

  def read_root_keyhash(self):
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x08 48 1".format(self.ipmitool, \
               self.bmc_ip, self.user_name, self.passwd)
    result = subprocess.getoutput(cmdline).split('\n')
    result = ''.join(result).split(' ')
    result = ''.join([x for x in result if x])
    self.dict_prov['rk_hash384'] = result
    return result

  def read_ifwi_offset(self):
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x0C 12 1".format(self.ipmitool, \
               self.bmc_ip, self.user_name, self.passwd)
    # return below two lines. Ignore the first line, process the last line
    # IANA PEN registry open failed: No such file or directory
    #  00 00 fe 03 00 00 00 06 00 00 00 04
    result = subprocess.getoutput(cmdline).split('\n')[-1]
    #print("1-result={}".format(result))
    result = ''.join(result).split(' ')
    result = [x for x in result if x]
    a, r, s=result[0:4], result[4:8], result[8:12]
    a.reverse(), r.reverse(), s.reverse()
    actv, recv, stag = '0x'+''.join(a), '0x'+''.join(r), '0x'+''.join(s)
    self.dict_prov['ifwi_act'] = actv
    self.dict_prov['ifwi_rcv'] = recv
    self.dict_prov['ifwi_stg'] = stag
    return result

  def read_bmc_offset(self):
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x0D 12 1".format(self.ipmitool, \
               self.bmc_ip, self.user_name, self.passwd)
    result = subprocess.getoutput(cmdline).split('\n')[-1] # get last line of return
    result = ''.join(result).split(' ')
    result = [x for x in result if x]
    a, r, s=result[0:4], result[4:8], result[8:12]
    a.reverse(), r.reverse(), s.reverse()
    actv, recv, stag = '0x'+''.join(a), '0x'+''.join(r), '0x'+''.join(s)
    self.dict_prov['bmc_act'] = actv
    self.dict_prov['bmc_rcv'] = recv
    self.dict_prov['bmc_stg'] = stag
    return result

  def read_deviceId_pubkey(self):
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x13 96 1".format(self.ipmitool, \
               self.bmc_ip, self.user_name, self.passwd)
    result = subprocess.getoutput(cmdline).split('\n')[-1] # get last line of return
    result = ''.join(result).split(' ')
    result = [x for x in result if x]
    self.dict_prov['DevIDPub0_X'] = ''.join(result[:48])
    self.dict_prov['DevIDPub0_Y'] = ''.join(result[48:])
    return result

  def read_fifo(self):
    """ read fifo """
    self.read_root_keyhash()
    self.read_ifwi_offset()
    self.read_bmc_offset()
    self.read_deviceId_pubkey()

  def show(self):
    """ display information """
    msg = "{:13s} = {:10s}, {:13s} = {:10s}, {:13s} = {:10s}".format('ifwi_active', self.dict_prov['ifwi_act'],\
    'ifwi_recovery', self.dict_prov['ifwi_rcv'], 'ifwi_stagging', self.dict_prov['ifwi_stg'])
    logger.info(msg)

    msg = "{:13s} = {:10s}, {:13s} = {:10s}, {:13s} = {:10s}".format('bmc_active', self.dict_prov['bmc_act'],\
    'bmc_recovery', self.dict_prov['bmc_rcv'], 'bmc_stagging', self.dict_prov['bmc_stg'])
    logger.info(msg)

    msg = "{} = {}\n{} = {}".format('DevIDPub0_X', self.dict_prov['DevIDPub0_X'], 'DevIDPub0_Y', self.dict_prov['DevIDPub0_Y'])
    logger.info(msg)

    #print(self.lst_cpld_mailbox)


class Updater:
    def __init__(self, args):
        self.address = args.bmc_ip #address
        self.timeout = args.timeout
        self.nowait = args.nowait
        self.insecure = args.insecure
        self.file = args.file
        self.evts_prior = 0
        self.sess = requests.session()
        self.auth = {'UserName':args.username, 'Password':args.password}
        self.sess.verify = not self.insecure
        self.logs_found = 0
        self.sess_path = None
        self.rqargs = {'timeout': args.timeout}

    def __del__(self):
        self.logout()

    def login(self):
        try:
            self.get('/redfish/v1')
        except requests.exceptions.SSLError:
            print('Remote Host "{}" has an invalid or self-signed certificate.'.format(self.address))
            ignore = input('Ignore the apparent danger and proceed? Y/[N]: ')
            self.sess.verify = ignore not in ('Y', 'y')
            if self.sess.verify:
                print('Way to play it safe. No MITM attacks today!')
                sys.exit(0)
        slogin = self.post('/redfish/v1/SessionService/Sessions', json=self.auth)
        self.rqargs['headers'] = {'X-Auth-Token': slogin.headers['X-Auth-Token']}
        self.sess_path = slogin.json()['@odata.id']

    def logout(self):
        if self.sess_path is not None:
            try:
                self.delete(self.sess_path, timeout=3)
            except requests.exceptions.Timeout:
                pass

    def get(self, path, **kwargs):
        kwargs = { **kwargs, **self.rqargs }
        uri = 'https://{}{}'.format(self.address, path)
        print(uri)
        print(kwargs)
        rsp = self.sess.get(uri, **kwargs)
        rsp.raise_for_status()
        return rsp

    def post(self, path, **kwargs):
        kwargs = { **kwargs, **self.rqargs }
        uri = 'https://{}{}'.format(self.address, path)
        rsp = self.sess.post(uri, **kwargs)
        rsp.raise_for_status()
        return rsp

    def delete(self, path, **kwargs):
        kwargs = { **kwargs, **self.rqargs }
        uri = 'https://{}{}'.format(self.address, path)
        rsp = self.sess.delete(uri, **kwargs)
        rsp.raise_for_status()
        return rsp

    def watch_task(self, task_id):
        i = 0
        prev_state = ''
        task_state = ''
        while True:
            if task_state == "Stopping": break

            task_uri = '/redfish/v1/TaskService/Tasks/{}'.format(task_id)
            try:
                progress = self.get(task_uri)
            except requests.exceptions.Timeout:
                now = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
                if prev_state == 'Stopping' and self.logs_found >= 2:
                    print('')
                    print('{}: FW update successful. BMC is restarting'.format(now))
                else:
                    print('')
                    print('{}: Timed out {}s: {}'.format(now, self.timeout,
                                                         task_uri))
                sys.exit(0)

            now = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            task_state = progress.json()["TaskState"]
            if task_state == "Exception":
                print('')
                print('{}: FW update failed'.format(now))
                return
            if task_state == "Completed":
                print('')
                print('{}: FW update successful'.format(now))
                return
            if task_state == "Stopping" and prev_state != task_state:
                print('-- task_state={}, prev_state={} ...'.format(task_state, prev_state))
                print('')
                print('{}: FW update finishing'.format(now))
                break
            if task_state not in ("Running", "Stopping"):
                print('')
                print('{}: Task state: {}'.format(now, task_state))
            sys.stdout.write('\rUpdating FW{}'.format('.'*(i%4)+' '*(4-(i%4))))
            sys.stdout.flush()
            i += 1
            time.sleep(1)
            if task_state != "Stopping":
                if self.check_redfish_logs() != 0:
                    return
            prev_state = task_state
        print('')
        print('-- Done watch Task-ID')

    def check_redfish_logs(self):
        # grab the event log to provide extra info
        # print("-- enter check_redfish_logs ...")
        evt_uri = '/redfish/v1/Systems/system/LogServices/EventLog/Entries'
        if self.evts_prior > 0:
            evt_uri += '?$skip={}'.format(self.evts_prior)
        try:
            evts = self.get(evt_uri)
        except requests.exceptions.Timeout:
            now = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            if self.logs_found >= 2:
                print('')
                print('{}: FW update successful. BMC is restarting'.format(now))
            else:
                print('')
                print('{}: Timed out {}s: {}'.format(now, self.timeout, evt_uri))
            sys.exit(0)

        # print("-- 1. finished first check_redfish_logs ...")
        evts = evts.json()
        for evt in evts['Members']:
            if evt['MessageId'][0:26] == 'OpenBMC.0.1.FirmwareUpdate':
                print('')
                print('{}: {}'.format(evt['Created'], evt['Message']))
                self.logs_found += 1

        # print("-- 2. finished second check_redfish_logs ...")
        self.evts_prior = evts['Members@odata.count']
        #print("-- exit check_redfish_logs ...")
        return 0

    def update(self):
        # check event log first
        evt_uri = '/redfish/v1/Systems/system/LogServices/EventLog/Entries'
        evts_prior = self.get(evt_uri)
        self.evts_prior = evts_prior.json()['Members@odata.count']

        print('{}: Checking for in-flight updates...'.format(
            datetime.now().strftime("%m/%d/%Y %H:%M:%S")))

        # check for current updates
        progress = self.get('/redfish/v1/TaskService/Tasks')
        for m in progress.json()["Members"]:
            task_id = re.sub(r'/redfish/v1/TaskService/Tasks/([0-9]+)', r'\1',
                             m["@odata.id"])
            task = self.get('/redfish/v1/TaskService/Tasks/{}'.format(task_id))
            tjson = task.json()
            if tjson['Payload']['TargetUri'] == '/redfish/v1/UpdateService':
                if tjson['TaskState'] == 'Completed' or \
                        tjson['TaskState'] == 'Exception':
                    continue

                print('Found in-flight update task {}'.format(task_id))
                if self.nowait:
                    rc = 1
                else:
                    rc = 0
                    self.watch_task(task_id)
                sys.exit(rc)

        data = None
        with open(self.file, 'rb') as file:
            data = file.read()

        resp = self.post('/redfish/v1/UpdateService', data=data)

        if resp.status_code == 202:
            print('{}: FW file transferred to {}.'.format(
                datetime.now().strftime("%m/%d/%Y %H:%M:%S"), self.address))
            if self.nowait:
                sys.exit(0)
            next_path = resp.json()["@odata.id"]
            task_id = re.sub(r'/redfish/v1/TaskService/Tasks/([0-9]+)', r'\1',
                             next_path)
            self.watch_task(task_id)
            #print("-- finished watch_task for status_code={}".format(resp.status_code))

        self.check_redfish_logs()



class Redfish_Update:
  """ class for redfish out-of-band staging update

  This is the class to do BMC OOB update via staging.

  :param args: argument namespace, from argsparse.Namespace()

  :param bmc_ip: IP address of BMC
  :param username: username of BMC user account
  :param password: password of BMC user account
  :param file: unzipped file name of binary image with full path
  :param insecure: insecure, default False
  :param timeout: time to wait for a response from the BMC, default is 60s
  :param nowait: transfer the file and exit. Don't wait for status

  """
  def __init__(self, args):
    self.address = args.bmc_ip
    self.timeout = args.timeout
    self.nowait = args.nowait
    self.insecure = args.insecure
    self.file = args.file
    self.evts_prior = 0
    self.sess = requests.session()
    self.auth = {'UserName':args.username, 'Password':args.password}
    self.sess.verify = not self.insecure
    self.logs_found = 0
    self.sess_path = None
    self.rqargs = {'timeout': args.timeout}

  def __del__(self):
    self.logout()

  def login(self):
    """ log in user with password """
    try:
      self.get('/redfish/v1')
    except requests.exceptions.SSLError:
      print('Remote Host "{}" has an invalid or self-signed certificate.'.format(self.address))
      ignore = input('Ignore the apparent danger and proceed? Y/[N]: ')
      self.sess.verify = ignore not in ('Y', 'y')
      if self.sess.verify:
        print('Way to play it safe. No MITM attacks today!')
        sys.exit(0)
    slogin = self.post('/redfish/v1/SessionService/Sessions', json=self.auth)
    self.rqargs['headers'] = {'X-Auth-Token': slogin.headers['X-Auth-Token']}
    self.sess_path = slogin.json()['@odata.id']

  def logout(self):
    if self.sess_path is not None:
      try:
        self.delete(self.sess_path, timeout=3)
      except requests.exceptions.Timeout:
        pass

  def get(self, path, **kwargs):
    kwargs = { **kwargs, **self.rqargs }
    uri = 'https://{}{}'.format(self.address, path)
    #print(uri)
    #print(kwargs)
    rsp = self.sess.get(uri, **kwargs)
    rsp.raise_for_status()
    return rsp

  def post(self, path, **kwargs):
    kwargs = { **kwargs, **self.rqargs }
    uri = 'https://{}{}'.format(self.address, path)
    rsp = self.sess.post(uri, **kwargs)
    rsp.raise_for_status()
    return rsp

  def delete(self, path, **kwargs):
    kwargs = { **kwargs, **self.rqargs }
    uri = 'https://{}{}'.format(self.address, path)
    rsp = self.sess.delete(uri, **kwargs)
    rsp.raise_for_status()
    return rsp

  def watch_task(self, task_id):
    """ watch on-going task status

    :param task_id: ID of the task

    """
    i = 0
    prev_state = ''
    task_state = ''
    while True:
      if task_state == "Stopping": break
      task_uri = '/redfish/v1/TaskService/Tasks/{}'.format(task_id)
      try:
        progress = self.get(task_uri)
      except requests.exceptions.Timeout:
        now = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        if prev_state == 'Stopping' and self.logs_found >= 2:
            print('')
            print('{}: FW update successful. BMC is restarting'.format(now))
        else:
            print('')
            print('{}: Timed out {}s: {}'.format(now, self.timeout,
                                                 task_uri))
        sys.exit(0)

      now = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
      task_state = progress.json()["TaskState"]
      if task_state == "Exception":
        print('')
        print('{}: FW update failed'.format(now))
        return
      if task_state == "Completed":
        print('')
        print('{}: FW update successful'.format(now))
        return
      if task_state == "Stopping" and prev_state != task_state:
        print('-- task_state={}, prev_state={} ...'.format(task_state, prev_state))
        print('')
        print('{}: FW update finishing'.format(now))
        break
      if task_state not in ("Running", "Stopping"):
        print('')
        print('{}: Task state: {}'.format(now, task_state))
      sys.stdout.write('\rUpdating FW{}'.format('.'*(i%4)+' '*(4-(i%4))))
      sys.stdout.flush()
      i += 1
      time.sleep(1)
      if task_state != "Stopping":
        if self.check_redfish_logs() != 0:
          return
      prev_state = task_state
    print('')
    print('-- Done watch Task-ID')

  def check_redfish_logs(self):
    # grab the event log to provide extra info
    #print("-- enter check_redfish_logs ...")
    evt_uri = '/redfish/v1/Systems/system/LogServices/EventLog/Entries'
    if self.evts_prior > 0:
      evt_uri += '?$skip={}'.format(self.evts_prior)
    try:
      evts = self.get(evt_uri)
    except requests.exceptions.Timeout:
      now = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
      if self.logs_found >= 2:
          print('')
          print('{}: FW update successful. BMC is restarting'.format(now))
      else:
          print('')
          print('{}: Timed out {}s: {}'.format(now, self.timeout, evt_uri))
      sys.exit(0)

    #print("-- 1. finished first check_redfish_logs ...")
    evts = evts.json()
    for evt in evts['Members']:
      if evt['MessageId'][0:26] == 'OpenBMC.0.1.FirmwareUpdate':
        print('')
        print('{}: {}'.format(evt['Created'], evt['Message']))
        self.logs_found += 1
    #print("-- 2. finished second check_redfish_logs ...")
    self.evts_prior = evts['Members@odata.count']
    #print("-- exit check_redfish_logs ...")
    return 0

  def update(self):
    # check event log first
    #print('-- entered update ..')
    evt_uri = '/redfish/v1/Systems/system/LogServices/EventLog/Entries'
    evts_prior = self.get(evt_uri)
    self.evts_prior = evts_prior.json()['Members@odata.count']

    print('{}: Checking for in-flight updates...'.format(
      datetime.now().strftime("%m/%d/%Y %H:%M:%S")))

    # check for current updates
    progress = self.get('/redfish/v1/TaskService/Tasks')
    for m in progress.json()["Members"]:
      task_id = re.sub(r'/redfish/v1/TaskService/Tasks/([0-9]+)', r'\1',
                         m["@odata.id"])
      task = self.get('/redfish/v1/TaskService/Tasks/{}'.format(task_id))
      tjson = task.json()
      if tjson['Payload']['TargetUri'] == '/redfish/v1/UpdateService':
        if tjson['TaskState'] == 'Completed' or \
                tjson['TaskState'] == 'Exception':
          continue

        print('Found in-flight update task {}'.format(task_id))
        if self.nowait:
          rc = 1
        else:
          rc = 0
          self.watch_task(task_id)
        sys.exit(rc)

    data = None
    with open(self.file, 'rb') as file:
        data = file.read()

    resp = self.post('/redfish/v1/UpdateService', data=data)

    if resp.status_code == 202:
      print('{}: FW file transferred to {}.'.format(
          datetime.now().strftime("%m/%d/%Y %H:%M:%S"), self.address))
      if self.nowait:
          sys.exit(0)
      next_path = resp.json()["@odata.id"]
      task_id = re.sub(r'/redfish/v1/TaskService/Tasks/([0-9]+)', r'\1',
                       next_path)
      self.watch_task(task_id)
      #print("-- finished watch_task for status_code={}".format(resp.status_code))

    self.check_redfish_logs()

def main(args):
  """ bmc module command line interface
  """
  parser = argparse.ArgumentParser(description="-- BMC module command line utility")
  parser.add_argument('-start_build', action='store_true', help="start BMC build: generate manifest reference file and keys to work folder. Also add -r reference project name")
  parser.add_argument('-r', '--reference', metavar="[reference platform]", dest='reference', help='reference design name: eaglestream, whitley, idaville. It is valid only with -start_build')
  parser.add_argument('-m', '--manifest', metavar="[manifest json file]",  dest='manifest', default=None,  help='manifest json file name')
  parser.add_argument('-l', '--logfile',  metavar="[logfile]", dest='logfile', default=None, help='Logfile')

  subparser = parser.add_subparsers(dest='action')
  # build pfr bmc image
  cmdbuild = subparser.add_parser('build', description="build BMC PFR image from manifest json file")
  cmdbuild.add_argument('-start_build', action='store_true', help="start BMC build: generate manifest reference file and keys to work folder. Also add -r reference project name")
  cmdbuild.add_argument('-r', '--reference', metavar="[reference platform]", dest='reference', help='reference design name: eaglestream, whitley, idaville. It is valid only with -start_build')
  cmdbuild.add_argument('-m', '--manifest', metavar="[manifest json file]",  dest='manifest', default=None,  help='manifest json file name')

  # read cpld mailbox
  cmdmbx = subparser.add_parser('mailbox', description="read PFR mailbox registers via out-of-band interface")
  cmdmbx.add_argument('-i', '--bmc_ip',   metavar="[BMC IP address]", dest='bmc_ip',   help='BMC IP address')
  cmdmbx.add_argument('-u', '--username', metavar="[username]",       dest='username', default='debuguser', help='BMC OOB user username')
  cmdmbx.add_argument('-p', '--password', metavar="[password]",       dest='password', default='0penBmc1',  help='BMC OOB user password')
  cmdmbx.add_argument('-l', '--logfile',  metavar="[logfile]",        dest='logfile',  help='Logfile')

  # redfish update
  cmdredfish = subparser.add_parser('update', description="redfish update utility")
  cmdredfish.add_argument('-i', '--bmc_ip',   dest='bmc_ip',   help='BMC IP address')
  cmdredfish.add_argument('-u', '--username', default ='debuguser', dest='username', help='BMC username, default is debuguser')
  cmdredfish.add_argument('-p', '--password', default ='0penBmc1',  dest='password', help='BMC password, default is 0penBmc1')
  cmdredfish.add_argument('-I', '--insecure', default=True, dest='insecure', action='store_true')
  cmdredfish.add_argument('-t', '--timeout',  default=60, type=int, dest='timeout',
                                help="Time to wait for a response from the BMC")
  cmdredfish.add_argument('-w', '--nowait',   default=False, dest='nowait',
                        action='store_true',
                        help="Transfer the file and exit. Don't wait for status")
  cmdredfish.add_argument('-f', '--file',     dest='file',     help='File name of Update capsule')
  cmdredfish.add_argument('-l', '--logfile',  dest='logfile',  help='Logfile')

  args = parser.parse_args(args)

  #print('args:\n', args)
  if args.logfile != None:
    logging.basicConfig(level=logging.DEBUG,
                    handlers= [
                      logging.FileHandler(args.logfile, mode='w'),
                      logging.StreamHandler()
                    ]
                  )
  else:
    logging.basicConfig(level=logging.DEBUG, handlers= [ logging.StreamHandler()])

  #if args.action == 'build':
  if (args.start_build == True) and (args.reference not in _list_reference_project):
    logger.error("-- add reference name: {}".format(_list_reference_project))
    return
  if (args.start_build == True) and (args.reference in _list_reference_project):
    if args.reference == "egs": args.reference = 'eaglestream'
    if args.reference == "bhs-ap": args.reference = 'birchstream'
    if args.reference == "bhs-sp": args.reference = 'birchstream'
    if args.reference == "bhs": args.reference = 'birchstream'
    print("-- generated pfr_bmc_manifest.json reference file for platform {}".format(args.reference))
    mybmc= BMC_Build(args.reference)
    mybmc.start_build()
    return
  if (args.manifest != None) and (args.start_build is False):
    print("-- build bmc image using manifest file {}".format(args.manifest))
    mybmc= BMC_Build(args.reference)
    mybmc.set_manifest(args.manifest)
    mybmc.build_image()
    return

  if args.action == 'mailbox':
    #print(args)
    oob=BMC_OOB_Mailbox(args.bmc_ip, args.username, args.password)
    oob.read_fifo()
    oob.read_mailbox()
    utility.decode_mailbox(oob.lst_cpld_mailbox)
    oob.show()

  if args.action == 'update':
    print('Do update using redfish')
    #print(args)
    logging.getLogger("urllib3").propagate = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    updater = Redfish_Update(args)
    updater.login()
    updater.update()

if __name__ == '__main__':
  main(sys.argv[1:])
