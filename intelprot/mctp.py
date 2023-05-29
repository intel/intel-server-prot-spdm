#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  :platform: Linux, Windows
  :synopsis: for MCTP control protocol operation

  module for MCTP packet processing

"""
from __future__ import print_function
from __future__ import division

import logging
import os, struct
from crccheck.crc import Crc8Smbus
import tabulate
from collections import OrderedDict
from array import array
import random

logger = logging.getLogger(__name__)

dict_MCTP_Ctrl_CmdCode = { \
"0x01": 'Set Endpoint ID',\
"0x02": 'Get Endpoint ID',\
"0x03": 'Get Endpoint UUID',\
"0x04": 'Get MCTP Version Support',\
"0x05": 'Get Message Type Support'}

dict_MCTP_Ctrl_Response = {\
"0x01": [0,0,1,0,0,0,0],\
"0x02": [0,0,2,0,0,0,0],\
"0x03": [0,0,3,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],\
"0x04": [0,0,4,0,1,241,242,241,0],\
"0x05": [0,0,5,0,2,0,5] }

def verify_mctp_ctrl_request(req):
  """ verify if a MCTP ctrl request is valid

  Byte1:  MsgType = 0x00
  Byte2:  InstantID
  Byte3:  Command Code
  Byte4:  Completion Code
  Byte5:  Message Data

    0, *, 1, *, *
    0, *, 2
    0, *, 3
    0, *, 4, 0
    0, *, 5

  :param req: array of MCTP control request value
  :return: True or Flase
    """

def get_mctp_ctrl_response(req):
  """ get MCTP ctrl packet response from request

  :param req: array of MCTP control request value

  0, *, 4, 0    --> 0,0,4,0,1,241,242,241,0
  0, *, 2       --> 0, 0 ,2 ,0 ,0 ,0 ,0
  0, *, 3       --> 0,0,3,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
  0, *, 1, *, * --> 0,0,1,0,0,0,0
  0, *, 5       --> 0,0,5,0,2,0,5

  """
  if req[0] == 0:
    if req[2] == 4 and req[3] == 0:
      res = (0,0,4,0,1,241,242,241,0)
    if req[2] == 2:
      res = (0, 0 ,2 ,0 ,0 ,0 ,0)
    if req[2] == 3:
      res = (0,0,3,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)
    if req[2] == 1:
      res = (0,0,1,0,0,0,0)
    if req[2] == 5:
      res = (0,0,5,0,2,0,5)
    return res
  else:
    return -1

MCTP_CTRL_MSG_TYPE = 0x00
MCTP_DEST_ADDR = 0x37
MCTP_BMC_ADDR  = 0x09

class MCTP_Bridge(object):
  """
  Class for MCTP message processing of SMBus data out of BMC MCTP bridge

  :param input_data : input data in bytearray format

  """
  def __init__(self, input_data=None):
    # req GET_MCTP_VERSION: 0F 09 13 01 00 08 C8 00 88 04 00 13
    self.mctp_dstaddr = MCTP_DEST_ADDR
    self.mctp_resp_dstaddr = MCTP_BMC_ADDR
    if input_data == None: return
    self.input_data = input_data
    self.decode_mctp()

  def decode_mctp(self):
    self.length =len(self.input_data)
    self.pec = self.input_data[-1]
    self.data_req = self.input_data[7:self.length-1]
    self.mctp_cmdcode   = self.input_data[0] # 0x0F
    self.mctp_bytecnt   = self.input_data[1] # Byte Count
    self.mctp_srcaddr   = self.input_data[2] >>1 # source slave address
    self.mctp_hdrver    = self.input_data[3]
    self.mctp_dstEID    = self.input_data[4]
    self.mctp_srcEID    = self.input_data[5]
    self.mctp_som       = (self.input_data[6] & 0x80) >> 7
    self.mctp_eom       = (self.input_data[6] & 0x40) >> 6
    self.mctp_pktseq    = (self.input_data[6] & 0x30) >> 4
    self.mctp_tagowner  = (self.input_data[6] & 0x08) >> 3
    self.mctp_msgtag    = (self.input_data[6] & 0x07)
    self.mctp_ic        = (self.input_data[7] & 0x80) >> 7
    self.mctp_msgtype   = (self.input_data[7] & 0x7F)
    self.mctp_msgReq    = (self.input_data[8] & 0x80)>>7
    self.mctp_msgDag    = (self.input_data[8] & 0x40)>>6
    self.mctp_msgInstID = self.input_data[8] & 0x1F
    self.mctp_msgCmd    = self.input_data[9]
    if (self.mctp_tagowner == 0) and (self.mctp_msgReq == 0) and (self.mctp_msgDag == 0):
      # response packet
      self.mctp_msgComp = self.input_data[10]  # completion code
    if (self.mctp_tagowner == 1) and (self.mctp_msgReq == 1) and (self.mctp_msgDag == 0):
      # request packet
      self.mctp_msgData   = self.input_data[10:self.length-1]

  def set_input_data(self, input_data):
    """ setup input_data """
    self.input_data = input_data
    self.decode_mctp()

  def gen_response(self):
    """ generate response mctp packet for SMBus transmission

    :return resp_data: response mctp packet in bytearray format

    GET_MCTP_VERSION (0x04): dest_addr=0x38 (0x70), slave_addr=0x37
      0f 09 13 01 00 08 c8 00 81 04 00 3f
    RESPONSE: dest_addr=0x09 , slave_addr=0x37
      0F 0E 6f 01 08 00 c0 00 01 04 00 01 f1 f2 f1 00 81
      0f 0e 6f 01 08 00 c0 00 01 04 00 01 f1 f2 f1 00 81

    receive- [15, 10, 19, 1, 0, 8, 200, 0, 133, 1, 0, 9, 59]
    Control command with tag owner bit set. Processing [0, 133, 1, 0, 9]
    Payload [0, 133, 1, 0, 9]. Setting instance id 5
    Writing array('B', [15, 12, 110, 1, 8, 0, 192, 0, 5, 1, 0, 0, 9, 0, 154]) to 9
    {0, 133, 1, 0, 9} --> {0, 5, 1, 0, 0, 9, 0}
     133=0x85, InstID=5
    (0, *, 1, *, EID)--> (0, 5, 1,0,0,EID,0)

    """
    if self.mctp_msgCmd == 0x04:
       # 0,0,4,0,1,f1,f2,f1,0 response to GET_MCTP_VERSION 1.2.1
       lst = [0,0,4,0,1,0xf1,0xf2,0xf1,0]
       self.mctp_resp_payload = bytes(lst)
    elif self.mctp_msgCmd == 0x01:
       # set EID
       lst = [0,0,1,0,0,0,0]
       lst[5] = self.input_data[11]
       self.mctp_resp_payload = bytes(lst)
    elif self.mctp_msgCmd == 0x02:
       # get EID
       lst = [0, 0, 2, 0, 0, 0, 0]
       self.mctp_resp_payload = bytes(lst)
    elif self.mctp_msgCmd == 0x03:
       # get Endpoint UUID - response as 0-16, doesn't matter
       lst = [0,0,3,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
       self.mctp_resp_payload = bytes(lst)
    elif self.mctp_msgCmd == 0x05:
       # get MCTP message Type Support
       lst = [0,0,5,0,2,0,5]
    
    self.mctp_resp_cpltCode = 0
    self.mctp_resp_msgReq = 0
    self.mctp_resp_msgDag = 0
    self.mctp_resp_msgInstID = self.mctp_msgInstID
    self.mctp_resp_pktseq = self.mctp_pktseq
    lst[1] = self.mctp_resp_msgInstID

    self.mctp_resp_payload = bytes(lst)

    self.mctp_resp_dstaddr = self.mctp_srcaddr
    self.mctp_resp_srcaddr = self.mctp_dstaddr
    self.mctp_resp_dstEID  = self.mctp_srcEID
    self.mctp_resp_srcEID  = self.mctp_dstEID
    self.mctp_resp_tagowner= 0

    temp1 = bytes([(self.mctp_resp_srcaddr << 1|1), 0x01, self.mctp_resp_dstEID, self.mctp_resp_srcEID])
    temp2 = (self.mctp_som << 7) | (self.mctp_eom << 6) | (self.mctp_resp_pktseq << 4) | (self.mctp_resp_tagowner << 3) | self.mctp_msgtag
    temp2 = bytes([temp2])

    st_bytes = temp1 + temp2 + self.mctp_resp_payload
    byte_cnt = len(st_bytes)
    smb_bytes=bytes([(self.mctp_resp_dstaddr<<1 | 0), 0x0F, byte_cnt]) + st_bytes
    pec = Crc8Smbus.calc(smb_bytes)
    self.mctp_resp_data = bytes([0x0F, byte_cnt]) + st_bytes + bytes([pec])
    self.mctp_resp_msgData = self.mctp_resp_payload[4:]
    self.mctp_resp_bytecnt = byte_cnt
    self.mctp_resp_pec = pec

    return self.mctp_resp_data

  def show(self, fmt='orgtbl'):
    """ decode mctp packet and display """
    lst_header = ["DstAddr", "CmdCode", "ByteCnt", "SrcSlaAddr", "DestEID", "SrcEID", "SOM|EOM|PktSeq|TO|MsgTag"]
    msg ="-- MCTP Header: \n"
    lst = [("0x{:02X}".format(self.mctp_dstaddr), "0x{:02X}".format(self.mctp_cmdcode), \
    "0x{:02X}".format(self.mctp_bytecnt), "0x{:02X}".format(self.mctp_srcaddr), \
    "0x{:02X}".format(self.mctp_dstEID), "0x{:02X}".format(self.mctp_srcEID), \
    "{}|{}|{}|{}|{}".format(self.mctp_som, self.mctp_eom, self.mctp_eom, \
    self.mctp_pktseq, self.mctp_tagowner, self.mctp_msgtag))]

    msg += tabulate.tabulate(lst, lst_header, tablefmt=fmt)
    logger.info(msg)
    msg  = "-- MsgType:{} \n".format(self.mctp_msgtype)
    logger.info(msg)
    if self.mctp_msgtype == 0x0:
      self.show_mctpctrl_msg()


  def show_mctpctrl_msg(self, fmt='orgtbl'):
    """ display MCTP control type Message decode information """
    msg = "\n"+"~"*105
    msg += "\n-- MCTPCtrlMsgCmd(0x{:02x}): \"{}\" \n".format(self.mctp_msgCmd, dict_MCTP_Ctrl_CmdCode["0x{:02x}".format(self.mctp_msgCmd)])

    lst_header = ["DstAddr", "CmdCode", "ByteCnt", "SrcSlaAddr", "DestEID", "SrcEID", "SOM|EOM|PktSeq|TO|MsgTag"]
    lst_req_data = [("0x{:02X}".format(self.mctp_dstaddr), "0x{:02X}".format(self.mctp_cmdcode), \
    "0x{:02X}".format(self.mctp_bytecnt), "0x{:02X}".format(self.mctp_srcaddr), \
    "0x{:02X}".format(self.mctp_dstEID), "0x{:02X}".format(self.mctp_srcEID), \
    "{}|{:5d}|{:6d}|{:2d}|{:6d}".format(self.mctp_som, self.mctp_eom, \
    self.mctp_pktseq, self.mctp_tagowner, self.mctp_msgtag))]

    lst_res_data = [("0x{:02X}".format(self.mctp_resp_dstaddr), "0x{:02X}".format(self.mctp_cmdcode), \
    "0x{:02X}".format(self.mctp_resp_bytecnt), "0x{:02X}".format(self.mctp_resp_srcaddr), \
    "0x{:02X}".format(self.mctp_resp_dstEID), "0x{:02X}".format(self.mctp_resp_srcEID), \
    "{}|{:5d}|{:6d}|{:2d}|{:6d}".format(self.mctp_som, self.mctp_eom, \
    self.mctp_resp_pktseq, self.mctp_resp_tagowner, self.mctp_msgtag))]

    lst_req_msgheader = ["MsgType", "Rq|D|Rsvd|InstID", "CmdCode", "MsgData"]
    lst_req_msg = [("{:X}".format(self.mctp_msgtype), "{} |{}|Rsvd|{:3d}".format(self.mctp_msgReq, self.mctp_msgDag, self.mctp_msgInstID), \
               "{:X}".format(self.mctp_msgCmd), "{}".format(list(self.mctp_msgData)))]

    lst_res_msgheader = ["MsgType", "Rq|D|Rsvd|InstID", "CmdCode", "CpltCode", "MsgData"]

    lst_res_msg = [("{:X}".format(self.mctp_msgtype), \
               "{:2d} |{}|Rsvd|{:3d}".format(self.mctp_resp_msgReq, self.mctp_resp_msgDag, self.mctp_resp_msgInstID), \
               "{:X}".format(self.mctp_msgCmd), "{:X}".format(self.mctp_resp_cpltCode), "{}".format(list(self.mctp_resp_msgData)))]

    msg += ("\n-- MctpCtrl-Request:\n")
    msg += tabulate.tabulate(lst_req_data, lst_header, tablefmt = fmt)
    msg += "\n\n"
    msg += tabulate.tabulate(lst_req_msg, lst_req_msgheader, tablefmt = fmt)

    msg += ("\n\n-- MctpCtrl-Response:\n")
    msg += tabulate.tabulate(lst_res_data, lst_header, tablefmt = fmt)
    msg += "\n\n"
    msg += tabulate.tabulate(lst_res_msg,  lst_res_msgheader, tablefmt = fmt)
    msg += ("\n"+"="*105)
    logger.info(msg)


class MyList(list):
  def __repr__(self):
    return '('+', '.join("0x%02X"%x if type(x) is int else repr(x) for x in self)+')'

lst_spdm_res = ( \
(0x05, 0x10, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10), \
(0x05, 0x10, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00), \
(0x05, 0x10, 0x63, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), \
(0x05, 0x10, 0x01, 0x00, 0x07, 0x2C, 0xA8, 0x5C, 0x4E, 0x78, 0x52, 0x26, 0x6C, 0xF0, 0x3E, 0x8C, 0x7F, 0x0F, 0xC6, 0x0A, 0xDB, 0x58, 0xF3, 0x14, 0x04, 0x71, 0xB5, 0x9B, 0x04, 0x92, 0x51, 0xAE, 0x05, 0xFC, 0xF7, 0x99, 0x88, 0x85, 0x16, 0x03, 0xFD, 0x48, 0x8C, 0x9E, 0x6E, 0x74, 0x95, 0x36, 0x7D, 0xA2, 0x2A, 0x4C, 0xC0, 0x2C, 0xA8, 0x5C, 0x4E, 0x78, 0x52, 0x26, 0x6C, 0xF0, 0x3E, 0x8C, 0x7F, 0x0F, 0xC6, 0x0A, 0xDB, 0x58, 0xF3, 0x14, 0x04, 0x71, 0xB5, 0x9B, 0x04, 0x92, 0x51, 0xAE, 0x05, 0xFC, 0xF7, 0x99, 0x88, 0x85, 0x16, 0x03, 0xFD, 0x48, 0x8C, 0x9E, 0x6E, 0x74, 0x95, 0x36, 0x7D, 0xA2, 0x2A, 0x4C, 0xC0, 0x2C, 0xA8, 0x5C, 0x4E, 0x78, 0x52, 0x26, 0x6C, 0xF0, 0x3E, 0x8C, 0x7F, 0x0F, 0xC6, 0x0A, 0xDB, 0x58, 0xF3, 0x14, 0x04, 0x71, 0xB5, 0x9B, 0x04, 0x92, 0x51, 0xAE, 0x05, 0xFC, 0xF7, 0x99, 0x88, 0x85, 0x16, 0x03, 0xFD, 0x48, 0x8C, 0x9E, 0x6E, 0x74, 0x95, 0x36, 0x7D, 0xA2, 0x2A, 0x4C, 0xC0))

class brige_smbus_data(object):
  def __init__(self, lst_spdm, mctp_header=(0x01, 0x16, 0x09, 0xc8), src_addr = 0x37, dst_addr=0x09):
    self.spdm_data = lst_spdm
    self.mctp_header = mctp_header
    self.src_addr = src_addr
    self.dst_addr = dst_addr
    self.clac_smb_data()

  def set_mctp_header(self, mctp_header):
    self.mctp_header = mctp_header
  def set_srcaddr(self, src_addr):
    self.src_addr = src_addr
  def set_dstaddr(self, dst_addr):
    self.dst_addr = dst_addr

  def clac_smb_data(self):
    temp1 = [(self.src_addr << 1 | 1)] + list(self.mctp_header + self.spdm_data)
    byte_cnt = len(temp1)
    temp = bytes([self.dst_addr << 1|0, 0x0F, byte_cnt]) + bytes(temp1)
    pec= Crc8Smbus.calc(temp)
    self.smbus_data = list(bytes([0x0F, byte_cnt]) + bytes(temp1) + bytes([pec]))
     
  
