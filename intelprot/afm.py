#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    CPU AFM anaysis and process module
"""
import os, sys, binascii, struct, codecs, base64, hashlib, string, argparse, io, re
from collections import OrderedDict
import tabulate
import logging
logger = logging.getLogger(__name__)
from intelprot import utility

_PFM_MAGIC_TAG = 0x02b3ce1d
#_AFM_MAGIC_TAG = 0x8883ce1d

_FIT_TAG = b'_FIT_'

RSVD_FF         = b'\xFF'  # reserved byte 0xff
RSVD_00         = b'\x00'  # reserved byte 0x00
BLOCK_SIGN_SIZE = 0x400    # block sign size

# Index_Type, Description, Value_Type
lst_AFM_Measurements = ( \
    ('0x1','SOC Boot Time FW', '0x01'),
    ('0x2','Platform Strap Configuration', '0x02'),
    ('0x3','FIT Record 4', '0x03'),
    ('0x4','uCode FIT Patch', '0x81'),
    ('0x5', 'Startup ACM', '0x81'),
    ('0x8', 'Boot Policy Manifest', '0x81'),
    ('0x7', 'BIOS PFR Hash', '0x03'),
    ('0xff','TCBInfo', '0x84')
)

SPI_ADDR_PFM = 0x1
SPI_ADDR_FVM = 0x3
SPI_ADDR_AFM = 0x5

# for nested dictionary
class ConfigDict(OrderedDict):
    """ define an ordered dictionary """
    def __missing__(self, key):
        val = self[key] = ConfigDict()
        return val

class cls_BHS_IFWI_FLASH(object):
    """ class for BHS IFWI operation """
    FL_FORMAT, FL_STRUCT = "<16sIIII16sI12sII8sI36sIII", ('rsvd0', \
            'flsig', 'flmap0', 'flmap1', 'rsvd1', \
            'rsvd2', 'flcomp', 'rsvd3', \
            'flreg0_desc', 'flreg1_bios', 'rsvd', 'flreg4_pdr', 'rsvd2', 'flreg14_pfr', 'flreg15_imd', 'fmstr1')
    FLVALSIG = 0x0FF0A55A

    FDBAR, FCBA, FRBA, FMBA, SSBA = 0x0, 0x30, 0x40, 0x80, 0x100
    FLMAP_FORMAT, FLMAP_STRUCT = "<IIII", ('flsig', 'flmap0', 'flmap1', 'rsvd')
    FLCOM_FORMAT, FLCOM_STRUCT = "<I", ('flcomp')
    FLREG_FORMAT, FLREG_STRUCT = "<II8sI36sII", ('flreg0_desc', 'flreg1_bios', 'rsvd', 'flreg4_pdr', 'rsvd2', 'flreg14_pfr', 'flreg15_imd')

    def __init__(self, bin_image):
        self.img = bin_image

    def decomp(self):
        with open(self.img, 'rb') as f:
            self.desc_bdata = f.read(0x1000)
        self.dict_flash_desc= ConfigDict()
        self.s0=struct.calcsize(self.FL_FORMAT)
        lst_temp = struct.unpack(self.FL_FORMAT, self.desc_bdata[0:self.s0])
        for (k, v) in zip(self.FL_STRUCT, lst_temp):
            self.dict_flash_desc[k] = v
        ### TBC ###
        # find FIT table addr


class cls_FIT_Table(cls_BHS_IFWI_FLASH):
    """ class for FIT table processing """
    FIT_HEAD = b'_FIT_   '
    FIT4_TAG = b'\x00\x00\x00BTGC'
    FIT4_LEN_OFFSET = 20
    def __init__(self, bin_image):
        self.img = bin_image
        cls_BHS_IFWI_FLASH.__init__(self, bin_image)
        self.decomp()
        self.fit4_offset, self.fit_offset = [], []
        with open(self.img, 'rb') as f:
            self.fit4_offset = [(hex(m.start(0))) for m in re.finditer(re.escape(self.FIT4_TAG), f.read())][0]
            f.seek(0)
            self.fit_offset = [(hex(m.start(0))) for m in re.finditer(re.escape(self.FIT_HEAD), f.read())][0]
            self.fit_offset = int(self.fit_offset, 0)
            self.fit4_offset = int(self.fit4_offset, 0) - 0x11
            f.seek(self.fit_offset + len(self.FIT_HEAD))
            self.fit_size = int.from_bytes(f.read(3), 'little')
            f.seek(self.fit_offset)
            self.fit_bdata = f.read(self.fit_size * 16)

        print(hex(self.fit4_offset))
        print(hex(self.fit_offset))

    def process_fit_entries(self):
        """ process FIT table entries """
        self.fit_ver  = int.from_bytes(self.fit_bdata[12:13], 'little')
        self.fit_type = self.fit_bdata[14] & 0x7F
        self.fit_cv   = (self.fit_bdata[14] & 0x80) >>7
        self.fit_cksum= self.fit_bdata[15]
        FIT_ENTRY_STUCT = ('addr', 'rsvd', 'version', 'type', 'checksum')
        self.lst_fit_entry = []
        dict_temp = ConfigDict()
        for i in range(1, self.fit_size):
            lst_temp = struct.unpack("<Q4sHBB", self.fit_bdata[i*16:(i+1)*16])
            for (k, v) in zip(FIT_ENTRY_STUCT, lst_temp):
                if k == 'addr': dict_temp[k] = hex(v)
                else: dict_temp[k] = v
            print('-- FIT Type: {}, {}'.format(dict_temp['type'], dict_temp))
            self.lst_fit_entry.append(dict_temp)

        for i in range(0, self.fit_size):
            print("{}: {}".format(i, self.lst_fit_entry[i]))


class cls_CPU_ID(object):
    """ class for cpu id operation """
    # constants
    MODEL_FUSE_GNR = 0xD
    MODEL_FUSE_GNRD= 0xE
    MODEL_FUSE_SRF = 0xF
    CPU_ID_TAG     = b'cpu_id'

    def __init__(self, binary_image):
        self.image=binary_image

    def get_cpuid(self):
        """ extract list of cpu id """
        with open(self.image, 'rb') as f:
            self.bdata= f.read()
        self.lst_cpuid_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(self.CPU_ID_TAG), self.bdata)]
        #print('-- lst_cpuid_addr: {}'.format(self.lst_cpuid_addr))
        self.lst_cpuid=[]
        for i in self.lst_cpuid_addr:
            i = int(i, 0)
            s = self.bdata[i+len(self.CPU_ID_TAG)]
            cpuid = int.from_bytes(self.bdata[(i+len(self.CPU_ID_TAG)+1):(i+len(self.CPU_ID_TAG)+1+s)], 'little')
            #print(cpuid, hex(cpuid))
            self.lst_cpuid.append(hex(cpuid))

    def get_cpu_model(self):
        """ get CPU model the image supported """
        self.cpu_model = None
        self.lst_cpu_model = []
        self.get_cpuid()
        for cpuid in self.lst_cpuid:
            m=(int(cpuid, 16) & 0x00F0)>>4
            self.lst_cpu_model.append(m)
            if m == self.MODEL_FUSE_GNR:  self.cpu_model = 'GNR'
            if m == self.MODEL_FUSE_GNRD: self.cpu_model = 'GNRD'
            if m == self.MODEL_FUSE_SRF:  self.cpu_model = 'SRF'
        #print(self.lst_cpu_model)
        #print(self.cpu_model)
        if self.cpu_model not in ['GNR', 'GNRD', 'SRF']:
            sys.exit("-- Error: unable find CPU model !")
        

class IFWI_PFM_SPI(object):
    """ class process SPI rules in PFM
        SPI_Type = 0x1, 0x3, 0x5

    """
    def __init__(self, pfm_bdata):
        self.bdata = pfm_bdata
        self.pfm_header   = self.bdata[0:32]
        self.pfm_spi_data = self.bdata[32:]
        addr = 0
        while (self.pfm_spi_data[addr]) != SPI_ADDR_AFM:
            # static with sha384 hash presented
            if (self.pfm_spi_data[addr] == SPI_ADDR_PFM):
                if (self.pfm_spi_data[addr+1] & 0x03 == 0x01) and (self.pfm_spi_data[addr+2] == 0x02):
                    addr += 0x40
                if (self.pfm_spi_data[addr+1] & 0x03 == 0x00) or (self.pfm_spi_data[addr+1] & 0x03 == 0x03):
                    addr += 0x10
            if (self.pfm_spi_data[addr] == SPI_ADDR_FVM):
                addr += 0x0C
        self.afm_addr = addr
        self.afm_bdata = self.pfm_spi_data[addr:addr+56]


class CPU_AFM(object):
    """
    class for analysis Birch Stream CPU AFM from ifwi image
    """
    # constants definition inside class, don't change it
    OFFSET_P = 0x52  # offset of SIZE_OF_PUBKEY
    OFFSET_C = 0x5A  # offset of SIZE_OF_TCBINFO + P
    BHS_AFM_HEAD_ADDR_FORMAT = "<BBH16sI8sH14sII"
    BHS_AFM_HEAD_ADDR_STRUCT = ('afm_spi_type', 'device_addr', 'rsvd1','uuid','platform_id', 'platform_model', 'platform_version', 'rsvd2', 'afm_length', 'afm_addr')

    BHS_AFM_BLK_0_FORMAT = "<III4s32s48s32s"
    BHS_AFM_BLK_0_STRUCT = ('bk0_magic_tag', 'pc_len', 'pc_type', 'rsvd1', 'hash256', 'hash384', 'rsvd2')

    BHS_AFM_BLK_1_FORMAT = "<I12sIIII48s48s20sIIII48s48s20sI48s48sII48s48s"
    BHS_AFM_BLK_1_STRUCT = ('bk1_magic_tag', 'blk1_rsvd1', \
        'blk1_root_magic', 'blk1_root_curve', 'blk1_root_permission', 'blk1_root_keyid', 'blk1_root_pubX', 'blk1_root_pubY', 'blk1_root_rsvd', \
        'blk1_csk_magic', 'blk1_csk_curve', 'blk1_csk_permission', 'blk1_csk_keyid', 'blk1_csk_pubX', 'blk1_csk_pubY', 'blk1_csk_rsvd', 'blk1_csk_sig_magic', 'blk1_csk_sigR', 'blk1_csk_sigS', \
        'blk1_blk0_magic', 'blk1_blk0_sig_magic', 'blk1_blk0_sigR', 'blk1_blk0_sigS')

    BHS_AFM_CPU_SRF_FORMAT = "<16sI8sH16sBBBHBBBHIHH18sH{x}s{y}sIHH{c}sB3sB3sBBH48sB3sBBH48sB3sBBH48sB3sBBH48sB3sBBH48sB3sBBH48sB3sBBH48sB3sBBH{c}s"
    BHS_AFM_CPU_SRF_STRUCT = ('uuid', 'platform_id', 'platform_model', 'platform_version', 'rsvd1', 'bus_id', 'device_addr', 'bind_spec', 'bind_spec_version', 'policy', \
        'svn', 'rsvd2', 'afm_version', 'curve_magic', 'plat_manu_string', 'plat_manu_model', 'rsvd3', 'size_pub_key', 'pub_key_X', 'pub_key_Y', 'pub_key_exp', 'rsvd4', \
        'size_of_dice_tcbinfo', 'dice_tcbinfo', 'total_num_meas', 'rsvd5',\
        'num_meas_index0', 'rsvd6',  'meas_value_index_0', 'meas_value_type_0', 'meas_value_size_0', 'meas_value_0', \
        'num_meas_index1', 'rsvd7',  'meas_value_index_1', 'meas_value_type_1', 'meas_value_size_1', 'meas_value_1', \
        'num_meas_index2', 'rsvd8',  'meas_value_index_2', 'meas_value_type_2', 'meas_value_size_2', 'meas_value_2', \
        'num_meas_index3', 'rsvd8',  'meas_value_index_3', 'meas_value_type_3', 'meas_value_size_3', 'meas_value_3', \
        'num_meas_index4', 'rsvd10', 'meas_value_index_4', 'meas_value_type_4', 'meas_value_size_4', 'meas_value_4', \
        'num_meas_index5', 'rsvd11', 'meas_value_index_5', 'meas_value_type_5', 'meas_value_size_5', 'meas_value_5', \
        'num_meas_index6', 'rsvd12', 'meas_value_index_6', 'meas_value_type_6', 'meas_value_size_6', 'meas_value_6', \
        'num_meas_index7', 'rsvd13', 'meas_value_index_7', 'meas_value_type_7', 'meas_value_size_7', 'meas_value_7')

    BHS_AFM_CPU_GNR_FORMAT = "<16sI8sH16sBBBHBBBHIHH18sH{x}s{y}sIHH{c}sB3sB3sBBH48sB3sBBH48sB3sBBH48sB3sBBH32sB3sBBH32sB3sBBH48sB3sBBH48sB3sBBH{c}s"
    BHS_AFM_CPU_GNR_STRUCT = ('uuid', 'platform_id', 'platform_model', 'platform_version', 'rsvd1', 'bus_id', 'device_addr', 'bind_spec', 'bind_spec_version', 'policy', \
        'svn', 'rsvd2', 'afm_version', 'curve_magic', 'plat_manu_string', 'plat_manu_model', 'rsvd3', 'size_pub_key', 'pub_key_X', 'pub_key_Y', 'pub_key_exp', 'rsvd4', \
        'size_of_dice_tcbinfo', 'dice_tcbinfo', 'total_num_meas', 'rsvd5',\
        'num_meas_index0', 'rsvd6',  'meas_value_index_0', 'meas_value_type_0', 'meas_value_size_0', 'meas_value_0', \
        'num_meas_index1', 'rsvd7',  'meas_value_index_1', 'meas_value_type_1', 'meas_value_size_1', 'meas_value_1', \
        'num_meas_index2', 'rsvd8',  'meas_value_index_2', 'meas_value_type_2', 'meas_value_size_2', 'meas_value_2', \
        'num_meas_index3', 'rsvd8',  'meas_value_index_3', 'meas_value_type_3', 'meas_value_size_3', 'meas_value_3', \
        'num_meas_index4', 'rsvd10', 'meas_value_index_4', 'meas_value_type_4', 'meas_value_size_4', 'meas_value_4', \
        'num_meas_index5', 'rsvd11', 'meas_value_index_5', 'meas_value_type_5', 'meas_value_size_5', 'meas_value_5', \
        'num_meas_index6', 'rsvd12', 'meas_value_index_6', 'meas_value_type_6', 'meas_value_size_6', 'meas_value_6', \
        'num_meas_index7', 'rsvd13', 'meas_value_index_7', 'meas_value_type_7', 'meas_value_size_7', 'meas_value_7')

    def __init__(self, bin_image, pltfrm='pfr4', verbose=False):
        """ constructor

        :param pltfrm, PFR platform, default is 'pfr4' - BHS or KVL platform.
        :param bin_image, fisrt 64MB image or 128MB image

        """
        self.img = bin_image  # use the full 128MB image in case PFM is stored in the second half of IFWI image        
        obj = cls_CPU_ID(self.img)
        self.extract_afm()
        obj.get_cpu_model()
        self.cpu_model = obj.cpu_model
        if self.cpu_model == 'GNR' or self.cpu_model == 'GNRD':
            self._AFM_CPU_FORMAT = self.BHS_AFM_CPU_GNR_FORMAT.format(x=self.size_pubx, y=self.size_puby, c=self.C)
            self._AFM_CPU_STRUCT = self.BHS_AFM_CPU_GNR_STRUCT
        if self.cpu_model == 'SRF':
            self._AFM_CPU_FORMAT = self.BHS_AFM_CPU_SRF_FORMAT.format(x=self.size_pubx, y=self.size_puby, c=self.C)
            self._AFM_CPU_STRUCT = self.BHS_AFM_CPU_SRF_STRUCT
        self.lst_cpuid = obj.lst_cpuid
        #print(self.lst_cpuid)
        #print("-- self._AFM_CPU_FORMAT={}".format(self._AFM_CPU_FORMAT))

    def extract_afm(self):
        """ Extract AFM from PFM """
        st_tag = _PFM_MAGIC_TAG
        st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
        with open(self.img, 'rb') as f:
            self.bdata = f.read()

        lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), self.bdata)]
        #print("-- lst_addr={}, len(lst_addr)={}".format(lst_addr, len(lst_addr)))

        pfm_start = int(lst_addr[0], 0)
        #print('pfm_start=0x{:08x}'.format(pfm_start))

        pfm_len = struct.unpack('<I', self.bdata[pfm_start+0x1c:pfm_start+0x20])[0]
        self.pfm_bdata = self.bdata[pfm_start:pfm_start+pfm_len]
        self.pfmobj = IFWI_PFM_SPI(self.pfm_bdata)

        #print("-- afm_addr=0x{:x}".format(self.pfmobj.afm_addr))
        #print(self.pfmobj.afm_bdata.hex())

        lst_afm_head = struct.unpack(self.BHS_AFM_HEAD_ADDR_FORMAT, self.pfmobj.afm_bdata)
        #print("-- lst_afm_head={}".format(lst_afm_head))

        self.dict_afm_head = ConfigDict()
        for (key, val) in zip(self.BHS_AFM_HEAD_ADDR_STRUCT, lst_afm_head):
            self.dict_afm_head[key]=val
        #print(self.dict_afm_head)
        self.afm_len  = self.dict_afm_head['afm_length']
        self.afm_addr = self.dict_afm_head['afm_addr']
        self.img_size=os.path.getsize(self.img)
        print("-- afm_adr = 0x{:x}, afm_length = 0x{:x}, img_size = 0x{:x}".format(self.afm_addr, self.afm_len, self.img_size))

        if (self.afm_addr > self.img_size):
            # second half of ifwi image
            logger.error("-- Please use the 1x128M IFWI !")
            sys.exit("-- Error out: wrong input image, use the 128MB image !")
            offset_p = (self.afm_addr - self.img_size) + BLOCK_SIGN_SIZE + self.OFFSET_P
        else:
            offset_p = self.afm_addr + BLOCK_SIGN_SIZE + self.OFFSET_P
        print("-- offset_p = 0x{:x}".format(offset_p))

        self.P = struct.unpack('<H', self.bdata[offset_p:(offset_p + 2)])[0]
        self.size_pubx = int(self.P/2)
        self.size_puby = int(self.P/2)
        if (self.afm_addr > self.img_size):
            # second half of ifwi image
            offset_c = (self.afm_addr - self.img_size) + + BLOCK_SIGN_SIZE + self.OFFSET_C + self.P
        else:
            offset_c = self.afm_addr + BLOCK_SIGN_SIZE + self.OFFSET_C + self.P
        print("-- offset_c = 0x{:x}".format(offset_c))

        self.C = struct.unpack('<H', self.bdata[offset_c:offset_c+2])[0]
        print("-- P = 0x{:x}, C = 0x{:x}, self.size_pubx={}, self.size_puby={}".format(self.P, self.C, self.size_pubx, self.size_puby) )

    def decomp_afm(self):
        """ decompose AFM capsule """
        with open(self.img, 'rb') as f:
            f.seek(self.afm_addr)
            self.afm_cap_bdata=f.read(self.afm_len)

        self.dict_afm_blk=ConfigDict()
        self.s0=struct.calcsize(self.BHS_AFM_BLK_0_FORMAT)
        #print(self.s0)
        lst_temp = struct.unpack(self.BHS_AFM_BLK_0_FORMAT, self.afm_cap_bdata[0:self.s0])
        for (k, v) in zip(self.BHS_AFM_BLK_0_STRUCT, lst_temp):
            self.dict_afm_blk[k] = v

        self.s1=struct.calcsize(self.BHS_AFM_BLK_1_FORMAT)
        #print(self.s1)
        lst_temp = struct.unpack(self.BHS_AFM_BLK_1_FORMAT, self.afm_cap_bdata[self.s0:self.s0+self.s1])
        for (k, v) in zip(self.BHS_AFM_BLK_1_STRUCT, lst_temp):
            self.dict_afm_blk[k] = v
        """
        for k in self.dict_afm_blk:
            if isinstance(self.dict_afm_blk[k], int):
                print('-- {} = 0x{:x}'.format(k, self.dict_afm_blk[k]))
            elif isinstance(self.dict_afm_blk[k], bytes):
                print('-- {} = {}'.format(k, self.dict_afm_blk[k].hex()))
            else:
                print('-- {} = {}'.format(k, self.dict_afm_blk[k]))
        """
        self.dict_cpu_afm = ConfigDict()
        self.size_cpu_afm = struct.calcsize(self._AFM_CPU_FORMAT)
        #print('\n-- self.size_cpu_afm={}'.format(self.size_cpu_afm))
        #print('-- bdata: self.afm_cap_bdata[1024:(1024+self.size_cpu_afm)] \n = {}'.format(self.afm_cap_bdata[1024:(1024+self.size_cpu_afm)].hex()))

        lst_temp = struct.unpack(self._AFM_CPU_FORMAT, self.afm_cap_bdata[1024:(1024+self.size_cpu_afm)])
        #print("-- lst_temp={}".format(lst_temp))

        for (k, v) in zip(self._AFM_CPU_STRUCT, lst_temp):
            if isinstance(v, int):   v = hex(v)
            if isinstance(v, bytes): v = v.hex()
            self.dict_cpu_afm[k] = v

        #for k in self.dict_cpu_afm:
        #    print('-- {} = {}'.format(k, self.dict_cpu_afm[k]))
        #print('-- root certificate hexstr : {}'.format(self.dict_cpu_afm['certificate'].hex()))

    def get_fit_entry(self):
        """ get FIT entry addr
            FIT1_OFFSET = 0x260B580
        """
        st_tag = _FIT_TAG
        #st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
        with open(self.img, 'rb') as f:
            self.bdata = f.read()
        lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), self.bdata)]
        print(lst_addr)

    def show(self):
        """ show afm """
        self.decomp_afm()
        lst_key=('policy', 'pub_key_X', 'pub_key_Y', 'size_of_dice_tcbinfo', 'dice_tcbinfo', 'total_num_meas')
        msg  = '\n**** decomp AFM ****\n'
        msg += '-- {:20s}: {:50s} \n'.format('CPU Model', self.cpu_model)
        msg += '-- {:20s}: {:50s} \n'.format('CPU ID', self.lst_cpuid[0])        
        for k in lst_key:
            if k == 'dice_tcbinfo':
                v1=self.dict_cpu_afm[k][0:100]
                v2=self.dict_cpu_afm[k][100:200]
                v3=self.dict_cpu_afm[k][200:]
                msg += '-- {:20s}: {:50s} \n'.format(k, v1)
                msg += '   {:20s}: {:50s} \n'.format(' ', v2)
                msg += '   {:20s}: {:50s} \n'.format(' ', v3)
            else:
                msg += '-- {:20s}: {:50s} \n'.format(k, self.dict_cpu_afm[k])
        logging.basicConfig(level=logging.DEBUG, handlers= [logging.StreamHandler()])
        logger.info(msg)
        self.show_meas()

    def show_meas(self):
        """ show measurements """
        self.dict_AFM_Meas = ConfigDict()
        for lst in lst_AFM_Measurements:
            self.dict_AFM_Meas[lst[0]]=lst[1]

        lst_meas_head  = ['Index', 'Description', 'Type', 'Size', 'Value']
        lst_meas_data  = []
        total_meas = self.dict_cpu_afm['total_num_meas']
        for idx in range(0, int(total_meas, 0)):
            m_idx  = self.dict_cpu_afm['meas_value_index_{}'.format(idx)]
            m_desp = self.dict_AFM_Meas['{}'.format(m_idx)]
            v_type = self.dict_cpu_afm['meas_value_type_{}'.format(idx)]
            v_size = self.dict_cpu_afm['meas_value_size_{}'.format(idx)]
            m_val  = self.dict_cpu_afm['meas_value_{}'.format(idx)]
            #if len(m_val) > 96:
            lst_meas_data.append([m_idx, m_desp, v_type, v_size, m_val])
        msg = "-- CPU AFM Measuments: \n"
        msg += tabulate.tabulate(lst_meas_data, lst_meas_head, tablefmt='orgtbl', maxcolwidths=[5, 35, 5, 5, 96])
        #print(msg)
        logging.basicConfig(level=logging.DEBUG, handlers= [logging.StreamHandler()])
        logger.info(msg)


def main(args):
    """ verify PFR image for CPU attestation """
    parser = argparse.ArgumentParser(description="-- PFR AFM analysis module")
    parser.add_argument('-i', '--fname_bdata',   metavar="[Input bin file or data bytes]", dest='input_bin', help='PFR image file or binary data containing AFM')
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

    myafm = CPU_AFM(args.input_bin)
    myafm.show()

if __name__ == '__main__':
    main(sys.argv[1:])
