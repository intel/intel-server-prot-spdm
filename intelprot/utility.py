#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

   PFR binary image parsing utility functions

"""
from __future__ import print_function
from __future__ import division

import os, sys, platform, re, json, difflib, urllib3, requests
import binascii, struct, codecs, base64, hashlib
from functools import partial
import subprocess, argparse
import logging
logger = logging.getLogger(__name__)

BUFSIZE = 0x1000
CPLD_MAILBOX_JSON = os.path.join(os.path.dirname(__file__), r'json\cpld_mailbox.json')
if platform.system() == 'Windows':
    IPMITOOL = os.path.join(os.path.dirname(__file__), r'ipmitool\ipmitool.exe')
elif platform.system() == 'Linux':
    IPMITOOL = 'ipmitool'

def get_hash256(fname_or_bdata, start_addr=None, end_addr=None):
    """ calculate SHA 256

    It calculates hash256 32 bytes either from a binary file or from binary data in bytes/bytearray
    If fname_or_bdata is a file, default from offset 0 to the end of file.
    Input start, end address if only calculate hash from partial data from the binary file.

    :param fname_or_bdata: file name of the binary image with path, or binary data read from a binary file
    :param start_addr: start address, optional.
      It is needed if fname_or_bdata is a file and not start from the begining of the file
    :param end_addr: end address, optional.
      It is needed if fname_por_bdata is a file, and not to the end of the file

    :returns hash256: hex string of digest

    """
    if isinstance(fname_or_bdata, (bytes, bytearray)):
        # bytes or bytearray
        bdata = fname_or_bdata
    elif os.path.exists(fname_or_bdata):
        start_addr = 0 if (start_addr is None) else start_addr
        end_addr = os.stat(fname_or_bdata).st_size if (end_addr is None) else end_addr
        with open(fname_or_bdata, 'rb') as f:
            f.seek(start_addr)
            bdata=f.read(end_addr - start_addr)
    else:
        logger.error("File {} does not exist!".format(fname_or_bdata))
        return -1
    hash256=hashlib.sha256(bdata).hexdigest()
    return hash256


def get_hash384(fname_or_bdata, start_addr=None, end_addr=None):
    """ calculate SHA 384

    It calculates hash384 48 bytes either from a binary file or from binary data in bytes/bytearray
    If fname_or_bdata is a file, default from offset 0 to the end of file.
    Input start, end address if only calculate hash from partial data from the binary file.

    :param fname_or_bdata: file name of the binary image with path, or binary data read from a binary file
    :param start_addr: start address, optional.
        It is needed if fname_or_bdata is a file and not start from the begining of the file
    :param end_addr: end address, optional.
        It is needed if fname_por_bdata is a file, and not to the end of the file

    :returns hash384: hex string of digest

    """
    if isinstance(fname_or_bdata, (bytes, bytearray)):
        # bytes or bytearray
        bdata = fname_or_bdata
    elif os.path.exists(fname_or_bdata):
        start_addr = 0 if (start_addr is None) else start_addr
        end_addr = os.stat(fname_or_bdata).st_size if (end_addr is None) else end_addr
        with open(fname_or_bdata, 'rb') as f:
            f.seek(start_addr)
            bdata=f.read(end_addr - start_addr)
    else:
        logger.error("File {} does not exist!".format(fname_or_bdata))
        return -1
    hash384=hashlib.sha384(bdata).hexdigest()
    return hash384

def get_measure_hash384(bdata):
    """ get measurement hash384 using big endian

    :param bdata: binary data read from a binary file

    :returns meas_hash384: hex string of digest in BigEndian format for measurement
    """
    hash384=hashlib.sha384(bdata).hexdigest()
    b1=bytearray.fromhex(hash384)
    b1.reverse()
    meas_hash384 = b1.hex()
    return meas_hash384

def get_measure_hash256(bdata):
    """ get measurement hash256 using big endian

    :param bdata: binary data read from a binary file

    :returns meas_hash256: hex string of digest in BigEndian format for measurement
    """
    hash256=hashlib.sha256(bdata).hexdigest()
    b1=bytearray.fromhex(hash256)
    b1.reverse()
    meas_hash256 = b1.hex()
    return meas_hash256

def bin_compare_bytes(f1, f2, st_addr, size_bytes):
    """compare two binary files from start addr

    :param f1: first file to compare.
    :param f2: second file to compare.
    :param st_addr: start address to compare
    :param size_bytes: size of bytes to compare.
    :returns rtn: True/False
    """
    rtn = True
    with open(f1, 'rb') as fp1, open(f2, 'rb') as fp2:
        fp1.seek(st_addr), fp2.seek(st_addr)
        total, bufsize = 0, 16
        while total < size_bytes:
            temp1, temp2 =fp1.read(bufsize), fp2.read(bufsize)
            total += 16
            if temp1 != temp2:
                print("index: 0x%x"%(st_addr+total))
                print("%-30s"%f1, binascii.hexlify(temp1))
                print("%-30s"%f2, binascii.hexlify(temp2))
                rtn=False
    return rtn


def bin_compare_region(fn1, start1, end1, fn2, start2, end2):
    """compare region from two files

    :param fn1: the first file to compare.
    :param start1: start address of the file fn1.
    :param end1: end address of file fn1
    :param fn2: the second file to compare.
    :param start2: start address of the file fn2.
    :param end2: end address of file fn2.
    :returns rtn: True/False.
    """
    rtn = True
    s1, s2 = (end1-start1), (end2-start2)
    size_bytes = s1
    if s1 > s2: size_bytes = s2
    with open(fn1, 'rb') as f1, open(fn2, 'rb') as f2:
        f1.seek(start1)
        f2.seek(start2)
        total, bufsize = 0, 16
        while total < size_bytes:
            temp1, temp2 =f1.read(bufsize), f2.read(bufsize)
            total += 16
            if temp1 != temp2:
                print("index: 0x%x, 0x%x"%(start1+total, start2+total))
                print("%-30s"%fn1, binascii.hexlify(temp1))
                print("%-30s"%fn2, binascii.hexlify(temp2))
                rtn=False
    return rtn


def bin_compare(f1, f2):
    """ compare two binary files

    :param f1: filename of the first image.
    :param f2: filename of the second image
    :returns rtn: True/False of compare results. True: f1 and f2 are exactly same.
    """
    with open(f1, 'rb') as fp1, open(f2, 'rb') as fp2:
        b1 = b2 = True
        while b1 or b2:
            b1, b2 = fp1.read(BUFSIZE), fp2.read(BUFSIZE)
            if b1 != b2: return False
        return True

def bin_hexdump(fbin, st_addr=None, end_addr=None, fout=None):
    """ dump binary file as hex string and save to a file

    This function dump partial or whole binary image to a text file.
    The text file is hex string bytes with address information.

    :param fbin: input image filename.
    :param st_addr: start address, optional. Defaul is from beginning of the image
    :param end_addr: end address, optionsl. Default is to the end of image
    :param fout: output image filename, optional. Default is fbin_<st_addr>_<end_addr>_hexdump.txt
    """
    if st_addr is None: st_addr = 0
    if end_addr is None: end_addr = os.stat(fbin).st_size
    addr = st_addr
    if fout is None:
        fout = os.path.splitext(fbin)[0]+'_0x%x_0x%x_hexdump.txt'%(st_addr, end_addr)
    with open(fbin, 'rb') as f1, open(fout, 'w') as f2:
        f1.seek(st_addr)
        for bdata in iter(partial(f1.read, 16), b''):
            f2.write("0x%08X | "%addr)
            for i in range(len(bdata)):
                f2.write(" %02x"%bdata[i])
            f2.write("\n")
            addr += 16
            if addr >= end_addr: break

def bin_decomp(fbin, st_addr, end_addr, fout=None):
    """ decompost a region from a binary file

    decompost a region from start to end address from a binary file and write the region content to a file
    the output file name is optional. The default output file name is input file name with address range

    :param fbin: filename of a binary file
    :param st_addr: start address of the region
    :param end_addr: end address of the region
    :param fout: output image file name

    :returns None
    """
    if fout == None:
        fout = os.path.splitext(fbin)[0]+'_from_0x%0x_to_0x%0x'%(st_addr, end_addr)+'.bin'
    with open(fbin, 'rb') as f1, open(fout, 'wb+') as f2:
        f1.seek(st_addr)
        f2.write(f1.read(end_addr-st_addr))

def bin_search_tag(fbin, st_tag):
    """search a tag from a binary file

    The st_tag is either a double word little endian integer or bytes/bytearray format

    :param fbin: input filename
    :param dw_tag: double word tag, example 0x02B3CE1D
    :returns lst_addr: list of addresses of all occurances of the tag
    """
    if not isinstance(st_tag, (bytes, bytearray)):
        st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
    with open(fbin, 'rb') as f:
        lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), f.read())]
    return lst_addr

def bin_search_bytes(fbin, st_tag, relative_offset, size_of_bytes):
    """search bytes from a binary file relative to a start tag

    This function search a binary file and return the interested bytes relative to the start tag location
    It is useful to find a varibale number of bytes relative to a known tag.

    :param fbin: input filename
    :param st_tag: start of a tagflag. st_tag is wither bytes or integer, example b'__PFRS__', b'__KEYM__' or 0x02B3CE1D, 0xB6EAFD19
    :param relative_offset: relative offset in bytes to the st_tag
    :param size_of_bytes: size of return bytes
    :returns rtn_bytes: return bytes of size size_of_bytes

    example::

      ##. find 32 bytes of data that is relative 16 bytes after integer tag 0xB6EAFD19 from a_file
      >>>pfr_utility.bin_search_bytes(a_file, 0xB6EAFD19, 16, 32)
      ##. find 32 bytes of data that is 80 bytes after tag b'__KEYM__'
      >>>pfr_utility.bin_search_bytes(a_file, b'__KEYM__', 80, 32)

    """
    if not isinstance(st_tag, (bytes, bytearray)):
        st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
    with open(fbin, 'rb') as f:
        lst_idx = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), f.read())]
        #print(lst_idx)
        idx = int(lst_idx[-1], 0)
        f.seek(0)
        f.seek(idx + relative_offset)
        rtn_bytes = f.read(size_of_bytes)
    return rtn_bytes


def insert_bytes(fbin, st_addr, new_bytes, fout=None):
    """insert bytes to an image from a start address

    This function insert bytes to an image

    :param fbin: input binary filename
    :param st_addr: start offset of the file
    :param new_bytes: bytes or bytearray to be inserted
    :param fout: output image filename, optional. Default is fbin_insert.bin
    """
    if fout is None:
        fout = os.path.splitext(fbin)[0]+"_insert.bin"
    with open(fbin, 'rb') as f1, open(fout, 'wb') as f2:
        f1.seek(0)
        f2.write(f1.read(st_addr))
        f2.write(new_bytes)
        f2.write(f1.read())

def replace_bytes(fbin, start_addr, new_bytes, fout=None):
    """replace bytes from a start address for a binary image

    This function is replace variable number of bytes of a binary image and save it as a new image

    :param fbin: input image file
    :param start_addr: start address to replace
    :param new_bytes: new bytes to replace from an image
    :param fout: output image filename, optional. Default is fbin_replaced.bin
    """
    if fout is None:
        fout = os.path.splitext(fbin)[0]+"_replaced.bin"
    with open(fbin, 'rb') as f1, open(fout, 'wb') as f2:
        f1.seek(0)
        f2.write(f1.read(start_addr))
        f2.write(new_bytes)
        f1.seek(start_addr + len(new_bytes))
        f2.write(f1.read())

def integrate_capsule(fbin, fcap, st_addr, fout=None):
    """integrate capsule to a pfr image

    This function integrate a capsule image to a pfr image.
    A new image file will be generated at the same folder of input image. The content from st_addr will be replaced with capsule image

    :param fbin: input pfr image
    :param fcap: signed capsule image to be added
    :param st_addr: start address to integrate
    :param fout: output filename, optional. default is fbin file name path with "_with_cap".bin

    """
    if fout is None:
        fout = os.path.splitext(fbin)[0] + '_with_capsule.bin'
    with open(fout, 'wb') as f1, open(fbin, 'rb') as f2, open(fcap, 'rb') as f3:
        f1.write(f2.read(st_addr))
        f1.write(f3.read())
        f2.seek(st_addr+ os.stat(fcap).st_size)
        f1.write(f2.read())

def bind_file_at_addr(inf_n, outf_n, offset_addr):
    """ combine two binary file together, read inf_n and write it to outf_n at offset_addr in bytes

    :param inf_n: input file name
    :param outf_n: output file name
    :param offset_addr: offset address

    """
    with open(outf_n, "r+b") as ofd, open(inf_n, 'rb') as ifd:
        ofd.seek(offset_addr)
        ofd.write(ifd.read())

def extract_bin_from_file(inf_n, outf_n, offset_addr, extract_size):
    """ extract part of bin from a bin file from offset_addr

    :param inf_n: input file name
    :param outf_n: output file name
    :param offset_addr: offset address
    :param extract_size: size in bytes

    """
    with open(outf_n, "wb") as ofd, open(inf_n, 'rb') as ifd:
        ifd.seek(offset_addr)
        ofd.write(ifd.read(extract_size))

def erase_bin_from_file(inf_n, offset_addr, erase_size):
    """ erase an area from a bin file from offset_addr

    :param inf_n: input file name
    :param offset_addr: offset address
    :param erase_size: size in bytes

    """
    outf_n = os.path.splitext(inf_n)[0]+'_erased_addr_0x{:x}_size_0x{:x}.bin'.format(offset_addr, erase_size)
    with open(outf_n, "wb") as ofd, open(inf_n, 'rb') as ifd:
        ofd.write(ifd.read(offset_addr))
        ofd.write(erase_size*b'\xff')
        ifd.seek(offset_addr+erase_size)
        ofd.write(ifd.read())


def corrupt_bin_image(fbin, start_addr, end_addr, new_byte, fout=None):
    """replace bytes from a start to end address for a binary image

    This function is replace a static area of a binary image with a fix byte and save it as a new image

    :param fbin: input image file
    :param start_addr: start address to erase
    :param end_addr: end address to erase
    :param new_byte: new byte in hex format to replace the image
    :param fout: output image filename, optional. Default is fbin_corrupted.bin
    """
    if fout is None:
        fout = os.path.splitext(fbin)[0]+"_corrupted.bin"
    new_byte_array = bytes.fromhex(new_byte) * (end_addr - start_addr + 1)
    with open(fbin, 'rb') as f1, open(fout, 'wb') as f2:
        f1.seek(0)
        f2.write(f1.read(start_addr))
        f2.write(new_byte_array)
        f1.seek(end_addr + 1)
        f2.write(f1.read())

class OOB_Read_Mailbox(object):
    """ class for read mailbox operation

    :param bmc_ip_addr: BMC IP address
    :param username: BMC OOB user username, default is debuguser
    :param password: BMC OOB user password, default is 0penBmc1

    """
    def __init__(self, bmc_ip='10.19.154.207', username='debuguser', password='0penBmc1'):
        self.bmc_ip = bmc_ip
        self.username = username
        self.password = password
        self.cmd_base = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 ".format(IPMITOOL, self.bmc_ip, self.username, self.password)

    def read_mailbox(self):
        """ read mailbox register from 0 to 0x7F """
        self.mbx_cmdline = self.cmd_base +'0x0 0x7f 0x0'
        print(self.mbx_cmdline)
        result = subprocess.getoutput(self.mbx_cmdline).split('\n')
        result = ''.join(result)
        idx=result.index('de')
        result=result[idx:]   # get content from first identifier 'de'
        self.lst_cpld_mailbox = result.split(' ')

    def rk_hash(self):
        """ read root public key hash """
        self.rkhash_cmd = self.cmd_base + '0x08 48 1'
        result = subprocess.getoutput(self.rkhash_cmd).split('\n')
        result = ''.join(result).strip()
        result = [x for x in result.split(' ') if x]
        self.rk_hash = ''.join(result)

    def ifwi_offset(self):
        """ read host PFM offset provisioned in CPLD """
        self.ifwi_offset_cmd = self.cmd_base + '0x0C 0x0C 1'
        result = subprocess.getoutput(self.ifwi_offset_cmd).split('\n')
        result = ''.join(result)
        result = [x for x in result.split(' ') if x]
        bdata=bytes.fromhex(''.join(result))
        self.ifwi_offset = [hex(i) for i in struct.unpack('<III', bdata)]

    def bmc_offset(self):
        """ read BMC PFM offset provisioned in CPLD """
        self.bmc_offset_cmd = self.cmd_base + '0x0D 0x0C 1'
        result = subprocess.getoutput(self.bmc_offset_cmd).split('\n')
        result = ''.join(result)
        result = [x for x in result.split(' ') if x]
        bdata=bytes.fromhex(''.join(result))
        self.bmc_offset = [hex(i) for i in struct.unpack('<III', bdata)]

    def dev_pubkey(self):
        """ read BMC PFM offset provisioned in CPLD """
        self.devpubkey_cmd = self.cmd_base + '0x13 96 1'
        result = subprocess.getoutput(self.devpubkey_cmd).split('\n')
        result = ''.join(result)
        result = [x for x in result.split(' ') if x]
        self.dev_pubkey = (''.join(result[0:48]), ''.join(result[48:]))

    def dump(self):
        """ dump all data """
        self.rk_hash()
        self.ifwi_offset()
        self.bmc_offset()
        self.dev_pubkey()
        self.read_mailbox()

    def show(self):
        self.dump()
        print('-- IFWI PFM Offset: {}'.format(self.ifwi_offset))
        print('-- BMC  PFM Offset: {}'.format(self.bmc_offset))
        print('-- RK Hash        : {}'.format(self.rk_hash))
        print('-- DEV PubKey     : {}'.format(self.dev_pubkey))
        print('-- MailBox Regs   : {}'.format(self.lst_cpld_mailbox))


def read_mailbox(bmc_ip_addr, username, password):
    """ Read CPLD host mailbox register using BMC OOB method

    This function use below command to read CPLD mailbox register::

      bmc console: ipmitool raw 0x3e 0x84 [Register Address] [No of Bytes to Read] [Register Identifier]
      remote: ipmitool -I lanplus -H <BMC_IP> -C 17 -U <username> -P <password> raw 0x3e 0x84 [Register Address] [No of Bytes to Read] [Register Identifier]

      Note: Register Identifier:0 for single byte read register
            Register Identifier:1 for FIFO read register

      #example::
      ipmitool -I lanplus -H 10.19.154.207 -C 17 -U debuguser -P 0penBmc1 raw 0x3e 0x84 0x0 0x7f 0
      ipmitool -I lanplus -H 10.19.154.207 -C 17 -U debuguser -P 0penBmc1 raw 0x3e 0x84 0x20 0x40 0
      ipmitool -I lanplus -H 10.19.154.207 -C 17 -U debuguser -P 0penBmc1 raw 0x3e 0x84 0x08 48 1

    :param bmc_ip_addr: BMC IP address
    :param username: BMC OOB user username
    :param password: BMC OOB user password

    """
    #bmc_ip_addr = '10.19.154.207'
    #username, password = 'debuguser', '0penBmc1'
    #print(IPMITOOL)
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x0 0x7f 0".format(IPMITOOL, bmc_ip_addr, username, password)
    #print(cmdline)
    result = subprocess.getoutput(cmdline).split('\n')
    result = ''.join(result)
    #print(result)
    idx=result.index('de')
    result=result[idx:]   # get content from first identifier 'de'
    lst_cpld_mailbox = result.split(' ')
    return lst_cpld_mailbox

def decode_mailbox(lst_mailbox):
    """
    decode mailbox register value
    """
    # add console display
    if not logging.getLogger().hasHandlers():
        logging.basicConfig(level=logging.DEBUG, handlers= [logging.StreamHandler()], format='%(message)s')

    lst_dec_keys_1 = ['00h','03h','05h', '07h', '08h', '0Bh', '10h','11h', '7Ah']

    lst_data = []
    [lst_data.append(int(i, 16)) for i in lst_mailbox]
    with open(CPLD_MAILBOX_JSON, 'r') as fp:
        mb = json.load(fp)
    #print("Mailbox - Name: Value")
    logger.info("{a:4s} - {b:45s}: {c}".format(a="Addr", b="Name", c="Value (hex)"))
    logger.info("--"*50)
    for k in mb:
        mb[k]['decode'] = ""
        if '-' in k:
            i, j = int(k.split('-')[0].strip('h'), 16), int(k.split('-')[1].strip('h'), 16)
            mb[k]['value'] = lst_data[i:j+1]
            #print(mb[k]['name'])
            if mb[k]['name'] == 'CPLD RoT Hash':
                temp = lst_data[i:j+1]
                rot_hash=""
                for i in temp[0:48]:
                    rot_hash += "%02x"%(i)
            mb[k]['value'] = rot_hash
        else:
            i = int(k.strip('h'), 16)
            mb[k]['value'] = lst_data[i]

    for k in lst_dec_keys_1:
        #print(k, mb[k]['value'])
        k1= '0x%02X'%(mb[k]['value'])
        mb[k]['decode']=mb[k]['value_decode'][k1]

    #decode 09h
    if mb['08h']['value'] in [1, 2]:
        k1= '0x%02X'%(mb['09h']['value'])
        mb['09h']['decode']=mb['09h']['value_decode']["0x01-0x02"][k1]
    if mb['08h']['value'] == 3:
        k1= '0x%02X'%(mb['09h']['value'])
        mb['09h']['decode']=mb['09h']['value_decode']["0x03"][k1]

    #decode 0Ah 0x22 0010,0010
    mb['0Ah']['decode'] = ""
    temp = mb['0Ah']['value']
    for i in range(0, 8):
        if temp &(1<<i) != 0:
            if mb['0Ah']['decode'] != "":
                mb['0Ah']['decode'] += ' + ' + mb['0Ah']['value_decode']['Bit[{}]'.format(i)]
            else:
                mb['0Ah']['decode'] += mb['0Ah']['value_decode']['Bit[{}]'.format(i)]
    #deocde

    # display mailbox and decode
    for k in mb:
        if mb[k]['name'] != 'CPLD RoT Hash':
            if mb[k]['decode'] != "":
                logger.info("{a:4s} - {b:45s}: {c:02x} --> {d}".format(a=k, b=mb[k]["name"], c=mb[k]["value"], d = mb[k]['decode']))
            else:
                logger.info("{a:4s} - {b:45s}: {c:02x} ".format(a=k, b=mb[k]["name"], c=mb[k]["value"]))
    logger.info("\n{a:8s} - {b:15s}: {c}".format(a="20h-5Fh", b=mb["20h-5Fh"]["name"], c=mb["20h-5Fh"]["value"]))


def read_root_public_key_hash(bmc_ip_addr, username, password):
    """ read root public key hash

    This function read root public key hash::

      bmc console: ipmitool raw 0x3e 0x84 [Register Address] [No of Bytes to Read] [Register Identifier]
      remote: ipmitool -I lanplus -H <BMC_IP> -C 17 -U <username> -P <password> raw 0x3e 0x84 [Register Address] [No of Bytes to Read] [Register Identifier]

      Note: Register Identifier:0 for single byte read register
            Register Identifier:1 for FIFO read register

      #example::
      ipmitool -I lanplus -H 10.19.154.208 -C 17 -U debuguser -P 0penBmc1 raw 0x3e 0x84 0x08 48 1

    :param bmc_ip_addr: BMC IP address
    :param username: BMC OOB user username
    :param password: BMC OOB user password

    """
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x08 48 1".format(IPMITOOL, bmc_ip_addr, username, password)
    #print(cmdline)
    result = subprocess.getoutput(cmdline).split('\n')
    result = ''.join(result).strip()
    result = [x for x in result.split(' ') if x]
    return result

def read_pch_cpu_offset(bmc_ip_addr, username, password):
    """ read pch cpu offset """
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x0C 0x0C 1".format(IPMITOOL, bmc_ip_addr, username, password)
    #print(cmdline)
    result = subprocess.getoutput(cmdline).split('\n')
    #print(result)
    result = ''.join(result)
    result = [x for x in result.split(' ') if x]
    return result

def read_bmc_offset(bmc_ip_addr, username, password):
    """ read bmc offset """
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x0D 0x0C 1".format(IPMITOOL, bmc_ip_addr, username, password)
    result = subprocess.getoutput(cmdline).split('\n')
    result = ''.join(result)
    result = [x for x in result.split(' ') if x]
    return result

def read_deviceId_pubkey(bmc_ip_addr, username, password):
    """ read deviceid public key """
    cmdline = "{} -I lanplus -H {} -C 17 -U {} -P {} raw 0x3e 0x84 0x13 96 1".format(IPMITOOL, bmc_ip_addr, username, password)
    result = subprocess.getoutput(cmdline).split('\n')
    result = ''.join(result)
    result = [x for x in result.split(' ') if x]
    return result

def main(args):
    """
      command line to read CPLD mailbox register remotely using ipmi, and decode it.

      You will need set bmc user username/password with OOB authority and also with BMC IP address.

      Read CPLD mailbox command line::

      >>python -m intelprot.utility mailbox -i <BMC_IP> -u <username> -p <password>


    """
    parser = argparse.ArgumentParser(description="-- PFR Utility")

    # read cpld mailbox
    subparser = parser.add_subparsers(dest='action')
    cmdmbx = subparser.add_parser('mailbox')
    cmdmbx.add_argument('-i', '--bmc_ip',   metavar="[BMC IP address]", dest='bmc_ip',   help='BMC IP address')
    cmdmbx.add_argument('-u', '--username', metavar="[username]",       dest='username', help='BMC OOB user username')
    cmdmbx.add_argument('-p', '--password', metavar="[password]",       dest='password', help='BMC OOB user password')
    cmdmbx.add_argument('-l', '--logfile',  metavar="[logfile]",        dest='logfile',  help='Logfile')
    # read UFM
    cmdufm = subparser.add_parser('provision')
    cmdufm.add_argument('-i', '--bmc_ip',   metavar="[BMC IP address]", dest='bmc_ip', help='BMC IP address')
    cmdufm.add_argument('-u', '--username', metavar="[username]",  dest='username', help='BMC OOB user username')
    cmdufm.add_argument('-p', '--password', metavar="[password]",  dest='password', help='BMC OOB user password')

    # hexdump area
    cmddmp = subparser.add_parser('hexdump')
    cmddmp.add_argument('-i', '--bin_image',   metavar="[Binary image]", dest='bin_image',  help='binary image file')
    cmddmp.add_argument('-s', '--start_addr',  metavar="[Start Offset]", dest='start_addr', help='start address')
    cmddmp.add_argument('-e', '--end_addr',    metavar="[End Offset]",   dest='end_addr',   help='end address')

    # bindecomp area save to a binary file
    cmdbin = subparser.add_parser('bindecomp')
    cmdbin.add_argument('-i', '--bin_image',   metavar="[Binary image]", dest='bin_image',  help='binary image file')
    cmdbin.add_argument('-s', '--start_addr',  metavar="[Start Offset]", dest='start_addr', help='start address')
    cmdbin.add_argument('-e', '--end_addr',    metavar="[End Offset]",   dest='end_addr',   help='end address')

    # calculate hash
    cmdget = subparser.add_parser('gethash')
    cmdget.add_argument('-i', '--bin_image',   metavar="[Binary image]", dest='bin_image',  help='binary image file')
    cmdget.add_argument('-s', '--start_addr',  metavar="[Start Offset]", dest='start_addr', help='start address')
    cmdget.add_argument('-e', '--end_addr',    metavar="[End Offset]",   dest='end_addr',   help='end address')
    cmdget.add_argument('-t', '--hash type',   metavar="[Hash Type hash256 or hash384]",   dest='hash_type',  default='hash384', help='hash type')

    # corrupt an area for test
    cmdget = subparser.add_parser('corrupt')
    cmdget.add_argument('-i', '--bin_image',   metavar="[Binary image]", dest='bin_image',  help='binary image file')
    cmdget.add_argument('-s', '--start_addr',  metavar="[Start Offset]", dest='start_addr', help='start address')
    cmdget.add_argument('-e', '--end_addr',    metavar="[End Offset]",   dest='end_addr',   help='end address')
    cmdget.add_argument('-d', '--data byte',   metavar="[data byte to use]",  dest='corrupt_byte',  default='0xFF', help='data byte to corrupt a static area')

    args = parser.parse_args(args)
    #print(args)
    if args.action == 'mailbox':
        lst_mailbox = read_mailbox(args.bmc_ip, args.username, args.password)

        if args.logfile != None:
            logging.basicConfig(level=logging.DEBUG,
                            handlers= [
                            logging.FileHandler(args.logfile, mode='w'),
                            logging.StreamHandler()
                          ]
                        )
        else:
            logging.basicConfig(level=logging.DEBUG, handlers= [logging.StreamHandler()])
        #print(lst_mailbox)
        decode_mailbox(lst_mailbox)

        for hdl in logger.handlers[:]:
            hdl.close()
            logger.removeHandler(hdl)

    if args.action == 'provision':
        read_root_public_key_hash(args.bmc_ip, args.username, args.password)
        read_pch_cpu_offset(args.bmc_ip, args.username, args.password)
        read_bmc_offset(args.bmc_ip, args.username, args.password)
        read_deviceId_pubkey(args.bmc_ip, args.username, args.password)

    if args.action == 'hexdump':
        # if none, dump all binary image
        if args.start_addr == None: args.start_addr = str(0)
        if args.end_addr   == None: args.end_addr   = str(os.stat(args.bin_image).st_size)
        print(args.start_addr, args.end_addr)
        bin_hexdump(args.bin_image, int(args.start_addr, 0), int(args.end_addr, 0))

    if args.action == 'bindecomp':
        # if none, dump all binary image
        if args.start_addr == None: args.start_addr = str(0)
        if args.end_addr   == None: args.end_addr   = str(os.stat(args.bin_image).st_size)
        print(args.start_addr, args.end_addr)
        bin_decomp(args.bin_image, int(args.start_addr, 0), int(args.end_addr, 0))

    if args.action == 'gethash':
        if args.hash_type == "hash384":
            hashdata = get_hash384 (args.bin_image, int(args.start_addr, 0), int(args.end_addr, 0))
            print(hashdata)

        if args.hash_type == "hash256":
            hashdata = get_hash256 (args.bin_image, int(args.start_addr, 0), int(args.end_addr, 0))
            print(hashdata)

    if args.action == 'corrupt':
        start_addr   = int(args.start_addr, 0)
        end_addr     = int(args.end_addr, 0)
        corrupt_hex  = hex(int(args.corrupt_byte, 0)).strip('0x')
        print("-- corrupted area from 0x{:x} to 0x{:x} as data {} \n".format(start_addr, end_addr, args.corrupt_byte))
        corrupt_bin_image(args.bin_image, start_addr, end_addr, corrupt_hex)

if __name__ == '__main__':
    main(sys.argv[1:])

