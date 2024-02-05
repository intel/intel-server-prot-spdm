#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
   :platform: Unix, Windows
   :synopsis: Parse PFR PFM, display and customize PFM.

   PFM module is used to check PFM rules for verification and also for PFM customization

"""
import os, sys, binascii, struct, codecs, base64, hashlib, string, argparse, io, re
from mmap import ACCESS_READ, mmap
from functools import partial
from collections import OrderedDict
import tabulate
from intelprot import utility

import logging
logger = logging.getLogger(__name__)

MAX_LOOP = 2000

PFM_HEAD_FMT  = '<IBBHI16sI'
PFM_HEAD_SIZE = 0x20

PFM_MAGIC        = 0x02B3CE1D
FVM_MAGIC        = 0xA8E7C2D4
AFM_MAGIC        = 0x8883CE1D
PFM_SPI_REG_DEF  = 0x1
PFM_SMB_RUL_DEF  = 0x2
PFM_FVM_SPI_DEF  = 0x3
PFM_AFM_SPI_DEF  = 0x5 # BHS AFM inside PFM SPI definition

PFM_HEAD_FMT, PFM_HEAD_KEY = '<IBBHI16sI', ('tag', 'svn', 'bkc_rev', 'pfm_rev', 'rsvd1', 'oem_data', 'length')
PFM_BODY_SPI_FMT, PFM_BODY_SPI_KEY = '<BBHIII',   ('type', 'mask', 'hash_alg', 'rsvd1', 'reg_start', 'reg_end')
PFM_BODY_SMB_FMT, PFM_BODY_SMB_KEY = '<BIBBB32s', ('type', 'rsvd1', 'bus_id', 'rule_id', 'smb_addr', 'smb_passlist')
PFM_BODY_FVM_FMT, PFM_BODY_FVM_KEY = '<BH5sI',    ('type', 'fv_type', 'rsvd1', 'fvm_addr')
PFM_BODY_AFM_FMT, PFM_BODY_AFM_KEY = '<BBH16sI8sH14sII',  ('type', 'addr', 'rsvd1','uuid', 'platform_id', 'platform_model', 'platform_version', 'rsvd2','afm_length', 'afm_addr')  

FVM_HEAD_FMT, FVM_HEAD_KEY = '<IBBHHH16sI', ('tag', 'svn', 'rsvd1', 'fvm_rev', 'rsvd2', 'fv_type', 'oem_data', 'length')
FVM_BODY_SPI_FMT, FVM_BODY_SPI_KEY = '<BBHIII',   ('type', 'mask', 'hash_alg', 'rsvd1', 'reg_start', 'reg_end')
FVM_BODY_CAP_FMT, FVM_BODY_CAP_KEY = '<BHBHIII26s20s',   ('type', 'rsvd1', 'rev', 'size', 'seamless_pkg_ver', 'seamless_layout_id', 'seamless_post_act', 'rsvd2', 'seamless_fw_disc')

dict_FV_TYPE = { \
  0x0:'bios', \
  0x1: 'me/sps', \
  0x2: 'microcode 1', \
  0x3: 'microcode 2', \
  0x4: 'microcode 3', \
  0x5: 'microcode 4', \
  0x6: 'microcode 5', \
  0x7: 'microcode 6', \
  0x8: 'microcode 7', \
  0x9: 'microcode 8', \
  0xa: 'sps oper 1', \
  0xb: 'microcode 9', \
  0xc: 'ucode utility 1', \
  0xd: 'ucode utility 2' \
  }


# for nested dictionary
class ConfigDict(OrderedDict):
  """ define an ordered dictionary """
  def __missing__(self, key):
    val = self[key] = ConfigDict()
    return val

class PFM(object):
  """ PFM class for PFM decode analysis of PFM image file or binary data

  :param image_bdata:  unsigned pfm image file or data bytes
  :param logfile: logfile, optional, default is None, only display in screen.

  """
  def __init__(self, image_bdata):
    st_tag = PFM_MAGIC
    st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')

    if isinstance(image_bdata, str):
      if os.path.isfile(image_bdata):
        with open(image_bdata, 'rb') as f:
          self.bdata = f.read()
    elif isinstance(image_bdata, (bytes, bytearray)):
      self.bdata = image_bdata
    else:
      logger.critical("Error: wrong argment {}, eith binary file or binary data".format(image_bdata))

    self.no_pfm_tag = False
    #print(len(self.bdata), st_tag)
    lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), self.bdata)]
    print(lst_addr)
    if len(lst_addr) == 0:
      self.no_pfm_tag = True
      logger.critical('-- NO PFM TAG found')
      return
    pfm_start = int(lst_addr[0], 0)
    #print('pfm_start=0x{:08x}'.format(pfm_start))

    pfm_length= struct.unpack('<I', self.bdata[pfm_start+0x1c:pfm_start+0x20])[0]
    #print('-- pfm_length: 0x{:04x}'.format(pfm_length))

    self.pfm_bdata = self.bdata[pfm_start:pfm_start+pfm_length]

    self.pfm_dict = ConfigDict()  # empty dictionary

    lst_temp = struct.unpack(PFM_HEAD_FMT, self.pfm_bdata[0:32])
    for (k, v) in zip(PFM_HEAD_KEY, lst_temp):
      self.pfm_dict[k] = v

    total_size = self.pfm_dict['length']
    #print("-- Total_size: {}".format(total_size))
    count = 0x20
    spi_idx, smb_idx, fvm_idx = 0, 0, 0
    loop_cnt = 0
    while (count < total_size) & (loop_cnt < MAX_LOOP):
      pfm_def_type = int(struct.unpack("<B", self.pfm_bdata[count:count+1])[0])
      #print('**** pfm_def_type: {}', pfm_def_type)
      if pfm_def_type == 0x1:
        lst_temp = struct.unpack(PFM_BODY_SPI_FMT, self.pfm_bdata[count:count+16])
        #print("lst_temp: {}".format(lst_temp))
        for (k, v) in zip(PFM_BODY_SPI_KEY, lst_temp):
          self.pfm_dict['spi']['{}'.format(spi_idx)][k] = v
          #print("k:{}, v:{}".format(k, v))

        hash_info = self.pfm_dict['spi']['{}'.format(spi_idx)]['hash_alg']
        #print('-- hash_info = {}'.format(hash_info))
        count += 0x10
        if hash_info == 0:
          self.pfm_dict['spi']['{}'.format(spi_idx)]['hash_data'] = ''
        if hash_info == 1:
          self.pfm_dict['spi']['{}'.format(spi_idx)]['hash_data'] = struct.unpack('32s', self.pfm_bdata[count:count+32])[0].hex()
          count += 32
        if hash_info == 2:
          self.pfm_dict['spi']['{}'.format(spi_idx)]['hash_data'] = struct.unpack('48s', self.pfm_bdata[count:count+48])[0].hex()
          count += 48
        spi_idx += 1
      if pfm_def_type == 0x2:
        lst_temp = struct.unpack(PFM_BODY_SMB_FMT, self.pfm_bdata[count:count+40])
        for (k, v) in zip(PFM_BODY_SMB_KEY, lst_temp):
          self.pfm_dict['smb']['{}'.format(smb_idx)][k] = v
        smb_passlist = self.pfm_dict['smb']['{}'.format(smb_idx)]['smb_passlist']
        self.pfm_dict['smb']['{}'.format(smb_idx)]['smb_passlist'] = smb_passlist.hex()
        count+= 40
        smb_idx += 1
      if pfm_def_type == 0x3:
        lst_temp = struct.unpack(PFM_BODY_FVM_FMT, self.pfm_bdata[count:count+12])
        for (k, v) in zip(PFM_BODY_FVM_KEY, lst_temp):
          self.pfm_dict['fvm']['{}'.format(fvm_idx)][k] = v
        count += 12
        fvm_idx += 1
      #print("-- count: {}".format(count))
      loop_cnt += 1

    self.spi_cnt = spi_idx
    self.smb_cnt = smb_idx
    self.fvm_cnt = fvm_idx
    # process FVM data
    #print('fvm_idx={}'.format(fvm_idx))
    for i in range(0, fvm_idx):
      #print("\nfvm_idx: {} ".format(i))
      #print(self.pfm_dict['fvm']['{}'.format(i)])
      fvm_dict = self.pfm_dict['fvm']['{}'.format(i)]
      fvm_addr = fvm_dict['fvm_addr'] - (fvm_dict['fvm_addr'] & 0xFFFF0000) #0x3FE0000 #(pfm_start-0x400) #PFR_PFM_OFFSET
      #print(hex(fvm_dict['fvm_addr']))
      #print('fvm_addr={:x}'.format(fvm_addr))
      fvm_len  = struct.unpack('<I', self.bdata[fvm_addr:(fvm_addr+4)])[0]
      fvm_dict['bdata'] = self.bdata[fvm_addr: (fvm_addr+fvm_len)]

      st_tag = FVM_MAGIC
      st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
      lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), fvm_dict['bdata'])]
      #print("lst_addr = ", lst_addr)
      if len(lst_addr) == 0:
        break
      fvm_start = int(lst_addr[0], 0)
      addr_offset = fvm_start
      fvm_head_s = struct.calcsize(FVM_HEAD_FMT)
      lst_temp = struct.unpack(FVM_HEAD_FMT, fvm_dict['bdata'][addr_offset:addr_offset+fvm_head_s])

      for (k, v) in zip(FVM_HEAD_KEY, lst_temp):
        fvm_dict['head'][k] = v

      addr_offset += fvm_head_s
      fvm_spi_def = struct.unpack('<B', fvm_dict['bdata'][addr_offset:(addr_offset+1)])[0]
      fvm_spi_idx = 0
      while fvm_spi_def == 0x01:
        fvm_spi_s = struct.calcsize(FVM_BODY_SPI_FMT)
        lst_temp = struct.unpack(FVM_BODY_SPI_FMT, fvm_dict['bdata'][addr_offset:(addr_offset+fvm_spi_s)])
        addr_offset += fvm_spi_s

        for (k, v) in zip(FVM_BODY_SPI_KEY, lst_temp):
          fvm_dict['spi']['{:d}'.format(fvm_spi_idx)][k] = v
        if fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_alg'] == 0x00:
          fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_data'] = ""
        if fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_alg'] == 0x01:
          fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_data'] = struct.unpack('32s', fvm_dict['bdata'][addr_offset:(addr_offset+32)])[0].hex()
          addr_offset += 32
        if fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_alg'] == 0x02:
          fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_data'] = struct.unpack('48s', fvm_dict['bdata'][addr_offset:(addr_offset+48)])[0].hex()
          addr_offset += 48
        fvm_spi_def = struct.unpack('<B', fvm_dict['bdata'][addr_offset:(addr_offset+1)])[0]
        fvm_spi_idx += 1
        fvm_dict['spi']['count'] = fvm_spi_idx

      fvm_cap_s = struct.calcsize(FVM_BODY_CAP_FMT)
      lst_temp = struct.unpack(FVM_BODY_CAP_FMT, fvm_dict['bdata'][addr_offset:(addr_offset + fvm_cap_s)])
      for (k, v) in zip(FVM_BODY_CAP_KEY, lst_temp):
        fvm_dict['cap'][k] = v

      #print("FVM Index = {}".format(i))
      #for k in fvm_dict:
        #print(k, fvm_dict[k])

    #print("fvm_spi_reg {}: 0x{:08X} - 0x{:08X}".format(i, fvm_dict['spi']['reg_start'], fvm_dict['spi']['reg_end']))

    """
    for i in range(0, spi_idx):
      print("\nspi_idx: {} ".format(i))
      print(self.pfm_dict['spi']['{}'.format(i)])
      for k in self.pfm_dict['spi']['{}'.format(i)]:
        print(k, self.pfm_dict['spi']['{}'.format(i)][k])

    for i in range(0, fvm_idx):
      print("\nfvm_idx: {} ".format(i))
      print(self.pfm_dict['fvm']['{}'.format(i)])
      for k in self.pfm_dict['fvm']['{}'.format(i)]:
        print(k, self.pfm_dict['fvm']['{}'.format(i)][k])
    """
    #for i in range(0, spi_idx):
    #  print("spi_reg {}: 0x{:08X} - 0x{:08X}".format(i, self.pfm_dict['spi']['{}'.format(i)]['reg_start'], self.pfm_dict['spi']['{}'.format(i)]['reg_end']))


  def show(self, fmt='orgtbl'):
    """ display PFM data structure
    """
    if self.no_pfm_tag: return
    self.show_pfm_head(fmt)
    self.show_spi(fmt)
    self.show_smb(fmt)
    self.show_fvm(fmt)

  def show_pfm_head(self, fmt='orgtbl'):
    """ display PFM head """
    if self.no_pfm_tag: return
    pfm_header= ['PFM TAG', 'SVN','BKC Version', "PFM Version", "OEM Bytes", "PFM Length"]
    lst_key = ('tag', 'svn', 'bkc_rev', 'pfm_rev', 'oem_data', 'length')
    lst_v = []
    for k in lst_key:
      lst_v.append(self.pfm_dict[k])

    msg ="-- PFM Header: \n"
    lst = [("0x{:08X}".format(lst_v[0]), "0x{:02X}".format(lst_v[1]), "0x{:02X}".format(lst_v[2]), "0x{:04X}".format(lst_v[3]), "{:s}".format(lst_v[4].hex()), "0x{:08X}".format(lst_v[5]))]
    msg += tabulate.tabulate(lst, pfm_header, tablefmt=fmt)
    logger.info(msg)

  def show_spi(self, fmt='orgtbl'):
    """ show spi region """
    if self.no_pfm_tag: return
    spi_header_fvm = ['Type', 'Mask', 'Hash_Info','START', 'END', 'FV_Type', 'Hash Data']
    spi_header = ['Type', 'Mask', 'Hash_Info','START', 'END', 'Hash Data']
    spi_lst = []

    lst_key = ('type', 'mask', 'hash_alg', 'reg_start', 'reg_end', 'hash_data')
    for i in range(0, self.spi_cnt):
      lst = []
      dic = self.pfm_dict['spi']['{:d}'.format(i)]
      for k in lst_key:
        lst.append(dic[k])
      lst.append("--")
      spi_lst.append(lst)

    for i in range(0, self.fvm_cnt):
      fv_type = dict_FV_TYPE[self.pfm_dict['fvm']['{:d}'.format(i)]['head']['fv_type']]
      spi_cnt = self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['count']
      for idx in range(0, spi_cnt):
        lst = []
        for k in lst_key:
          lst.append(self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['{:d}'.format(idx)][k])
        lst.append(fv_type)
        spi_lst.append(lst)
    msg = "\n--SPI regions:\n"
    if self.fvm_cnt == 0:
      lst = []
      [lst.append(("0x%X"%i[0], "0x%02X"%(i[1]), i[2], "0x%08X"%(i[3]), "0x%08X"%(i[4]), i[5])) for i in spi_lst]
      msg += tabulate.tabulate(lst, spi_header, tablefmt=fmt)
    if self.fvm_cnt > 0:
      lst = []
      [lst.append(("0x%X"%i[0], "0x%02X"%(i[1]), i[2], "0x%08X"%(i[3]), "0x%08X"%(i[4]), i[6], i[5])) for i in spi_lst]
      msg += tabulate.tabulate(lst, spi_header_fvm, tablefmt=fmt)
    self.show_spi_lst = lst
    logger.info(msg)


  def show_smb(self, fmt='orgtbl'):
    """ display SMBus rules """
    if self.no_pfm_tag: return
    smb_header = ['Type', 'Bus_ID', 'Rule_ID', 'Address', "Passlist_Bitmap"]
    smb_lst = []
    if self.smb_cnt == 0: return
    lst_key = ('type', 'bus_id', 'rule_id', 'smb_addr', 'smb_passlist')
    for smb_idx in range(0, self.smb_cnt):
      dic = self.pfm_dict['smb']['{}'.format(smb_idx)]
      lst = []
      for k in lst_key:
        lst.append(dic[k])
      #print(lst)
      smb_lst.append(("0x%X"%lst[0], "0x%02X"%(lst[1]), "0x%02X"%(lst[2]), "0x%02X"%(lst[3]), lst[4]))
    msg = "\n--SMBus rules:\n"
    msg += tabulate.tabulate(smb_lst, smb_header, tablefmt=fmt)
    logger.info(msg)


  def process_fvm(self):
    """ process FVM for display FVM in the pfr image """
    if self.no_pfm_tag: return
    if self.fvm_cnt == 0: return

    fvm_header = ('INDEX', 'FVM_ADDR', 'FV_TYPE', 'SVN', 'FVM_REV', 'START', 'END', 'HASH_DATA')
    """
    for i in range(0, self.fvm_cnt):
      lst_key = ('tag', 'svn', 'fvm_rev', 'fv_type', 'length')
      lst = []
      dic = self.pfm_dict['fvm']['{:d}'.format(i)]['head']
      for k in lst_key:
        lst.append(dic[k])

      lst = [("0x%08X"%lst[0], "0x%02X"%(lst[1]), "0x%04X"%(lst[2]), "0x%04X"%(lst[3]), "0x%08X"%(lst[4]))]
      msg = tabulate.tabulate(lst, headers=['TAG', 'SVN', 'FVM_REV','FV_TYPE', "LENGTH"], tablefmt=fmt)
      print("\n--FVM: {}\n".format(i)+msg)

      lst_key = ('type', 'mask', 'hash_alg', 'reg_start', 'reg_end', 'hash_data')
      lst_v = []
      spi_cnt = self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['count']
      #print('\nspi_cnt: {}\n'.format(spi_cnt))
      for idx in range(0, spi_cnt):
        lst = []
        #print(self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['{:d}'.format(idx)])
        for k in lst_key:
          lst.append(self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['{:d}'.format(idx)][k])
        lst_v.append(lst)

      lst = []
      [lst.append(("0x%X"%i[0], "0x%02X"%(i[1]), i[2], "0x%08X"%(i[3]), "0x%08X"%(i[4]), i[5])) for i in lst_v]
      msg = tabulate.tabulate(lst, headers=['Type', 'Mask', 'Hash','START', "END", 'Hash Data'], tablefmt=fmt)
      print('\n'+msg)

      lst_key = ('type', 'rev', 'size', 'seamless_pkg_ver', 'seamless_layout_id', 'seamless_post_act', 'seamless_fw_disc')
      lst = []
      dic = self.pfm_dict['fvm']['{:d}'.format(i)]['cap']
      for k in lst_key:
        lst.append(dic[k])

      lst = [("0x%02X"%lst[0], "0x%02X"%(lst[1]), "0x%04X"%(lst[2]), "%s"%(lst[3]), "%s"%(lst[4]), "%s"%(lst[5]), "%s"%(lst[6].hex()))]
      msg = tabulate.tabulate(lst, headers=['FVM Cap', 'Rev', 'Size','Seamless_pkg_ver', 'Seamless_layout_id','Seamless_post_act', 'Seamless_fw_disc'], tablefmt=fmt)
      logger.info('\n'+msg)
    """
    lst_v = []
    for i in range(0, self.fvm_cnt):
      lst = [i]
      dic_head = self.pfm_dict['fvm']['{:d}'.format(i)]['head']
      dic_body = self.pfm_dict['fvm']['{:d}'.format(i)]
      lst.append('0x{:08X}'.format(dic_body['fvm_addr']))
      lst.append(dic_head['fv_type'])
      lst.append(dic_head['svn'])
      lst.append(dic_head['fvm_rev'])

      spi_cnt = dic_body['spi']['count']
      for idx in range(0, spi_cnt):
        lst1 = []
        dic = self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['{:d}'.format(idx)]
        #print('0x{:08X} -- 0x{:08X}'.format(dic['reg_start'], dic['reg_end']))
        lst1.append('0x{:08x}'.format(dic['reg_start']))
        lst1.append('0x{:08x}'.format(dic['reg_end']))
        lst1.append('{}'.format(dic['hash_data']))
        #print(lst1)
        lst_v.append(lst+lst1)

    self.fvm_header = fvm_header
    self.fvm_value  = lst_v


  def show_fvm(self, fmt='orgtbl'):
    """ display FVM in the pfr image """
    self.process_fvm()
    if (self.no_pfm_tag) or (self.fvm_cnt == 0): return
    msg = tabulate.tabulate(self.fvm_value, self.fvm_header, tablefmt=fmt)
    logger.info('\n'+msg)


class BHS_PFM(object):
  """
      PFM class for BHS PFR 4.0 PFM with AFM
      Decode analysis of PFM from a PFR image file or from PFM area binary data

  :param image_bdata:  unsigned pfm image file or data bytes
  :param logfile: logfile, optional, default is None, only display in screen.

  """
  def __init__(self, image_bdata):
    st_tag = PFM_MAGIC
    st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')

    if isinstance(image_bdata, str):
      if os.path.isfile(image_bdata):
        with open(image_bdata, 'rb') as f:
          self.bdata = f.read()
    elif isinstance(image_bdata, (bytes, bytearray)):
      self.bdata = image_bdata
    else:
      logger.critical("Error: wrong argment {}, eith binary file or binary data".format(image_bdata))

    self.no_pfm_tag = False
    #print(len(self.bdata), st_tag)
    lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), self.bdata)]
    print(lst_addr)
    if len(lst_addr) == 0:
      self.no_pfm_tag = True
      logger.critical('-- ERROR: NO PFM TAG found !')
      return
    pfm_start = int(lst_addr[0], 0)
    #print('pfm_start=0x{:08x}'.format(pfm_start))

    pfm_length= struct.unpack('<I', self.bdata[pfm_start+0x1c:pfm_start+0x20])[0]
    #print('-- pfm_length: 0x{:04x}'.format(pfm_length))

    self.pfm_bdata = self.bdata[pfm_start:pfm_start+pfm_length]
    self.pfm_dict = ConfigDict()  # empty dictionary
    lst_temp = struct.unpack(PFM_HEAD_FMT, self.pfm_bdata[0:32])
    for (k, v) in zip(PFM_HEAD_KEY, lst_temp):
      self.pfm_dict[k] = v

    total_size = self.pfm_dict['length']
    #print("-- Total_size: {}".format(total_size))
    count = 0x20
    spi_idx, smb_idx, fvm_idx = 0, 0, 0
    loop_cnt = 0
    while (count < total_size) & (loop_cnt < MAX_LOOP):
      pfm_def_type = int(struct.unpack("<B", self.pfm_bdata[count:count+1])[0])
      #print('**** pfm_def_type: {}', pfm_def_type)

      if pfm_def_type == PFM_SPI_REG_DEF: #0x1:
        lst_temp = struct.unpack(PFM_BODY_SPI_FMT, self.pfm_bdata[count:count+16])
        #print("lst_temp: {}".format(lst_temp))
        for (k, v) in zip(PFM_BODY_SPI_KEY, lst_temp):
          self.pfm_dict['spi']['{}'.format(spi_idx)][k] = v
          #print("k:{}, v:{}".format(k, v))

        hash_info = self.pfm_dict['spi']['{}'.format(spi_idx)]['hash_alg']
        #print('-- hash_info = {}'.format(hash_info))
        count += 0x10
        if hash_info == 0:
          self.pfm_dict['spi']['{}'.format(spi_idx)]['hash_data'] = ''
        if hash_info == 2:
          self.pfm_dict['spi']['{}'.format(spi_idx)]['hash_data'] = struct.unpack('48s', self.pfm_bdata[count:count+48])[0].hex()
          count += 48
        spi_idx += 1
      if pfm_def_type == PFM_SMB_RUL_DEF: #0x2:
        lst_temp = struct.unpack(PFM_BODY_SMB_FMT, self.pfm_bdata[count:count+40])
        for (k, v) in zip(PFM_BODY_SMB_KEY, lst_temp):
          self.pfm_dict['smb']['{}'.format(smb_idx)][k] = v
        smb_passlist = self.pfm_dict['smb']['{}'.format(smb_idx)]['smb_passlist']
        self.pfm_dict['smb']['{}'.format(smb_idx)]['smb_passlist'] = smb_passlist.hex()
        count+= 40
        smb_idx += 1
      if pfm_def_type == PFM_FVM_SPI_DEF: #0x3:
        lst_temp = struct.unpack(PFM_BODY_FVM_FMT, self.pfm_bdata[count:count+12])
        for (k, v) in zip(PFM_BODY_FVM_KEY, lst_temp):
          self.pfm_dict['fvm']['{}'.format(fvm_idx)][k] = v
        count += 12
        fvm_idx += 1
      if pfm_def_type == PFM_AFM_SPI_DEF: #0x5:
        lst_temp = struct.unpack(PFM_BODY_AFM_FMT, self.pfm_bdata[count:count+12])
        for (k, v) in zip(PFM_BODY_AFM_KEY, lst_temp):
          self.pfm_dict['fvm']['{}'.format(fvm_idx)][k] = v
        count += 12
        fvm_idx += 1
      #print("-- count: {}".format(count))
      loop_cnt += 1

    self.spi_cnt = spi_idx
    self.smb_cnt = smb_idx
    self.fvm_cnt = fvm_idx
    # process FVM data
    #print('fvm_idx={}'.format(fvm_idx))
    for i in range(0, fvm_idx):
      #print("\nfvm_idx: {} ".format(i))
      #print(self.pfm_dict['fvm']['{}'.format(i)])
      fvm_dict = self.pfm_dict['fvm']['{}'.format(i)]
      fvm_addr = fvm_dict['fvm_addr'] - (fvm_dict['fvm_addr'] & 0xFFFF0000) #0x3FE0000 #(pfm_start-0x400) #PFR_PFM_OFFSET
      #print(hex(fvm_dict['fvm_addr']))
      #print('fvm_addr={:x}'.format(fvm_addr))
      fvm_len  = struct.unpack('<I', self.bdata[fvm_addr:(fvm_addr+4)])[0]
      fvm_dict['bdata'] = self.bdata[fvm_addr: (fvm_addr+fvm_len)]

      st_tag = FVM_MAGIC
      st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
      lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), fvm_dict['bdata'])]
      #print("lst_addr = ", lst_addr)
      if len(lst_addr) == 0:
        break
      fvm_start = int(lst_addr[0], 0)
      addr_offset = fvm_start
      fvm_head_s = struct.calcsize(FVM_HEAD_FMT)
      lst_temp = struct.unpack(FVM_HEAD_FMT, fvm_dict['bdata'][addr_offset:addr_offset+fvm_head_s])

      for (k, v) in zip(FVM_HEAD_KEY, lst_temp):
        fvm_dict['head'][k] = v

      addr_offset += fvm_head_s
      fvm_spi_def = struct.unpack('<B', fvm_dict['bdata'][addr_offset:(addr_offset+1)])[0]
      fvm_spi_idx = 0
      while fvm_spi_def == 0x01:
        fvm_spi_s = struct.calcsize(FVM_BODY_SPI_FMT)
        lst_temp = struct.unpack(FVM_BODY_SPI_FMT, fvm_dict['bdata'][addr_offset:(addr_offset+fvm_spi_s)])
        addr_offset += fvm_spi_s

        for (k, v) in zip(FVM_BODY_SPI_KEY, lst_temp):
          fvm_dict['spi']['{:d}'.format(fvm_spi_idx)][k] = v
        if fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_alg'] == 0x00:
          fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_data'] = ""
        if fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_alg'] == 0x01:
          fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_data'] = struct.unpack('32s', fvm_dict['bdata'][addr_offset:(addr_offset+32)])[0].hex()
          addr_offset += 32
        if fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_alg'] == 0x02:
          fvm_dict['spi']['{:d}'.format(fvm_spi_idx)]['hash_data'] = struct.unpack('48s', fvm_dict['bdata'][addr_offset:(addr_offset+48)])[0].hex()
          addr_offset += 48
        fvm_spi_def = struct.unpack('<B', fvm_dict['bdata'][addr_offset:(addr_offset+1)])[0]
        fvm_spi_idx += 1
        fvm_dict['spi']['count'] = fvm_spi_idx

      fvm_cap_s = struct.calcsize(FVM_BODY_CAP_FMT)
      lst_temp = struct.unpack(FVM_BODY_CAP_FMT, fvm_dict['bdata'][addr_offset:(addr_offset + fvm_cap_s)])
      for (k, v) in zip(FVM_BODY_CAP_KEY, lst_temp):
        fvm_dict['cap'][k] = v


  def show(self, fmt='orgtbl'):
    """ display PFM data structure
    """
    if self.no_pfm_tag: return
    self.show_pfm_head(fmt)
    self.show_spi(fmt)
    self.show_smb(fmt)
    self.show_fvm(fmt)

  def show_pfm_head(self, fmt='orgtbl'):
    """ display PFM head """
    if self.no_pfm_tag: return
    pfm_header= ['PFM TAG', 'SVN','BKC Version', "PFM Version", "OEM Bytes", "PFM Length"]
    lst_key = ('tag', 'svn', 'bkc_rev', 'pfm_rev', 'oem_data', 'length')
    lst_v = []
    for k in lst_key:
      lst_v.append(self.pfm_dict[k])

    msg ="-- PFM Header: \n"
    lst = [("0x{:08X}".format(lst_v[0]), "0x{:02X}".format(lst_v[1]), "0x{:02X}".format(lst_v[2]), "0x{:04X}".format(lst_v[3]), "{:s}".format(lst_v[4].hex()), "0x{:08X}".format(lst_v[5]))]
    msg += tabulate.tabulate(lst, pfm_header, tablefmt=fmt)
    logger.info(msg)

  def show_spi(self, fmt='orgtbl'):
    """ show spi region """
    if self.no_pfm_tag: return
    spi_header_fvm = ['Type', 'Mask', 'Hash_Info','START', 'END', 'FV_Type', 'Hash Data']
    spi_header = ['Type', 'Mask', 'Hash_Info','START', 'END', 'Hash Data']
    spi_lst = []

    lst_key = ('type', 'mask', 'hash_alg', 'reg_start', 'reg_end', 'hash_data')
    for i in range(0, self.spi_cnt):
      lst = []
      dic = self.pfm_dict['spi']['{:d}'.format(i)]
      for k in lst_key:
        lst.append(dic[k])
      lst.append("--")
      spi_lst.append(lst)

    for i in range(0, self.fvm_cnt):
      fv_type = dict_FV_TYPE[self.pfm_dict['fvm']['{:d}'.format(i)]['head']['fv_type']]
      spi_cnt = self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['count']
      for idx in range(0, spi_cnt):
        lst = []
        for k in lst_key:
          lst.append(self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['{:d}'.format(idx)][k])
        lst.append(fv_type)
        spi_lst.append(lst)
    msg = "\n--SPI regions:\n"
    if self.fvm_cnt == 0:
      lst = []
      [lst.append(("0x%X"%i[0], "0x%02X"%(i[1]), i[2], "0x%08X"%(i[3]), "0x%08X"%(i[4]), i[5])) for i in spi_lst]
      msg += tabulate.tabulate(lst, spi_header, tablefmt=fmt)
    if self.fvm_cnt > 0:
      lst = []
      [lst.append(("0x%X"%i[0], "0x%02X"%(i[1]), i[2], "0x%08X"%(i[3]), "0x%08X"%(i[4]), i[6], i[5])) for i in spi_lst]
      msg += tabulate.tabulate(lst, spi_header_fvm, tablefmt=fmt)
    self.show_spi_lst = lst
    logger.info(msg)


  def show_smb(self, fmt='orgtbl'):
    """ display SMBus rules """
    if self.no_pfm_tag: return
    smb_header = ['Type', 'Bus_ID', 'Rule_ID', 'Address', "Passlist_Bitmap"]
    smb_lst = []
    if self.smb_cnt == 0: return
    lst_key = ('type', 'bus_id', 'rule_id', 'smb_addr', 'smb_passlist')
    for smb_idx in range(0, self.smb_cnt):
      dic = self.pfm_dict['smb']['{}'.format(smb_idx)]
      lst = []
      for k in lst_key:
        lst.append(dic[k])
      #print(lst)
      smb_lst.append(("0x%X"%lst[0], "0x%02X"%(lst[1]), "0x%02X"%(lst[2]), "0x%02X"%(lst[3]), lst[4]))
    msg = "\n--SMBus rules:\n"
    msg += tabulate.tabulate(smb_lst, smb_header, tablefmt=fmt)
    logger.info(msg)


  def process_fvm(self):
    """ process FVM for display FVM in the pfr image """
    if self.no_pfm_tag: return
    if self.fvm_cnt == 0: return

    fvm_header = ('INDEX', 'FVM_ADDR', 'FV_TYPE', 'SVN', 'FVM_REV', 'START', 'END', 'HASH_DATA')

    lst_v = []
    for i in range(0, self.fvm_cnt):
      lst = [i]
      dic_head = self.pfm_dict['fvm']['{:d}'.format(i)]['head']
      dic_body = self.pfm_dict['fvm']['{:d}'.format(i)]
      lst.append('0x{:08X}'.format(dic_body['fvm_addr']))
      lst.append(dic_head['fv_type'])
      lst.append(dic_head['svn'])
      lst.append(dic_head['fvm_rev'])

      spi_cnt = dic_body['spi']['count']
      for idx in range(0, spi_cnt):
        lst1 = []
        dic = self.pfm_dict['fvm']['{:d}'.format(i)]['spi']['{:d}'.format(idx)]
        #print('0x{:08X} -- 0x{:08X}'.format(dic['reg_start'], dic['reg_end']))
        lst1.append('0x{:08x}'.format(dic['reg_start']))
        lst1.append('0x{:08x}'.format(dic['reg_end']))
        lst1.append('{}'.format(dic['hash_data']))
        #print(lst1)
        lst_v.append(lst+lst1)

    self.fvm_header = fvm_header
    self.fvm_value  = lst_v


  def show_fvm(self, fmt='orgtbl'):
    """ display FVM in the pfr image """
    self.process_fvm()
    if (self.no_pfm_tag) or (self.fvm_cnt == 0): return
    msg = tabulate.tabulate(self.fvm_value, self.fvm_header, tablefmt=fmt)
    logger.info('\n'+msg)



def main(args):
  """ verify PFR image or stgaing capsure"""
  parser = argparse.ArgumentParser(description="-- PFR PFM analysis module")
  parser.add_argument('-i', '--fname_bdata',   metavar="[Input bin file or data bytes]", dest='input_bin', help='PFR image file or binary data containing PFM')
  parser.add_argument('-log', '--logfile', metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")
  args = parser.parse_args(args)
  #print(args)
  if args.logfile != None:
    logging.basicConfig(level=logging.DEBUG,
                    handlers= [
                      logging.FileHandler(args.logfile, mode='w'),
                      logging.StreamHandler()
                    ]
                  )
  else:
    logging.basicConfig(level=logging.DEBUG, handlers= [ logging.StreamHandler()])

  mypfm = PFM(args.input_bin)
  mypfm.show()

if __name__ == '__main__':
  main(sys.argv[1:])

