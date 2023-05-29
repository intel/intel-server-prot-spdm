#!/usr/bin/env python3
# testprot.py
"""
:platform: Linux, Windows
:synopsis: This module is to test cpld SPDM protocol using SPDM emulator

Introduction
============
This module is used to test CPLD as SPDM-requester and responder

Run SPDM Test
=============
In default, both requester and responder are set as "spdm-emu". User select -req or -res as prot

Execution in command prompt::

  >python -m intelprot.testprot -get_setup   # get spdm_emu_execution.json file in work folder
  >python -m intelprot.testprot -s <spdm_emu_execution_json> # test with spdm-emu requester and spdm-emu responder
  >python -m intelprot.testprot -req prot -s <spdm_emu_execution_json>  # test PRoT as spdm requester, spdm-emu as spdm responder
  >python -m intelprot.testprot -res prot -s <spdm_emu_execution_json>  # test PRoT as spdm responder, spdm-emu as spdm requester


Setup execution with spdm_emu_execution.json::

  {
    "spdm_emu_responder_dir": "<path of spdm_emu responder execution file>",
    "spdm_emu_requester_dir": "<path of spdm_emu requester execution file>",
    "cmd_spdm_responder_emu": "spdm_responder_emu.exe --ver 1.0 --cap CERT,CHAL,MEAS_SIG --hash SHA_384 --meas_hash SHA_384 --asym ECDSA_P384",
    "cmd_spdm_requester_emu": "spdm_requester_emu.exe --ver 1.0 --cap CERT,CHAL --hash SHA_384 --meas_hash SHA_384 --asym ECDSA_P384",
    "delay_time": "0.32"
   }


About SPDM emulator
===================
SPDM-Emu is open source project emulating SPDM devices.
Refer spdm-emu GitHub link  `spdm-emu <https://github.com/DMTF/spdm-emu>`_. for detail.



"""
# this is to test CPLD using spdm_emu-responnder
import socket, sys, time, os, argparse, shutil
import subprocess, json, struct
from datetime import datetime

import logging
logger = logging.getLogger(__name__)
mctp_spdm_logging = False


from array import array
from intelprot import mctp_spdm, spdm, mctp

from intelprot.aardvark import smb_avark as avktool

PORT_REQUESTER = 2324
PORT_RESPONDER = 2325

CHUNK_SIZE = 4096
TIMEOUT    = 18

#define message for spdm requester
dict_spdm_req_1p0 = { \
'SPDM_GET_DIGESTS'           : 0x81,
'SPDM_GET_CERTIFICATE'       : 0x82,
'SPDM_CHALLENGE'             : 0x83,
'SPDM_GET_VERSION'           : 0x84,
'SPDM_GET_MEASUREMENTS'      : 0xE0,
'SPDM_GET_CAPABILITIES'      : 0xE1,
'SPDM_NEGOTIATE_ALGORITHMS'  : 0xE3,
'SPDM_VENDOR_DEFINED_REQUEST': 0xFE,
'SPDM_RESPOND_IF_READY'      : 0xFF}

#define message for spdm requester
dict_spdm_req_1p1 = { \
'SPDM_GET_DIGESTS'           : 0x81,
'SPDM_GET_CERTIFICATE'       : 0x82,
'SPDM_CHALLENGE'             : 0x83,
'SPDM_GET_VERSION'           : 0x84,
'SPDM_GET_MEASUREMENTS'      : 0xE0,
'SPDM_GET_CAPABILITIES'      : 0xE1,
'SPDM_NEGOTIATE_ALGORITHMS'  : 0xE3,
'SPDM_KEY_EXCHANGE'          : 0xE4,
'SPDM_FINISH'                : 0xE5,
'SPDM_PSK_EXCHANGE'          : 0xE6,
'SPDM_PSK_FINISH'            : 0xE7,
'SPDM_HEARTBEAT'             : 0xE8,
'SPDM_KEY_UPDATE'            : 0xE9,
'SPDM_GET_ENCAPSULATED_REQUEST': 0xEA,
'SPDM_DELIVER_ENCAPSULATED_RESPONSE': 0xEB,
'SPDM_END_SESSION'           : 0xEC,
'SPDM_VENDOR_DEFINED_REQUEST': 0xFE,
'SPDM_RESPOND_IF_READY'      : 0xFF}

dict_spdm_req_1p2 = { \
'GET_DIGESTS':0x81,
'GET_CERTIFICATE':0x82,
'CHALLENGE':0x83,
'GET_VERSION':0x84,
'CHUNK_SEND':0x85,
'CHUNK_GET':0x86,
'GET_MEASUREMENTS':0xE0,
'GET_CAPABILITIES':0xE1,
'GET_SUPPORTED_EVENT_GROUPS':0xE2,
'NEGOTIATE_ALGORITHMS':0xE3,
'KEY_EXCHANGE':0xE4,
'FINISH':0xE5,
'PSK_EXCHANGE':0xE6,
'PSK_FINISH':0xE7,
'HEARTBEAT':0xE8,
'KEY_UPDATE':0xE9,
'GET_ENCAPSULATED_REQUEST':0xEA,
'DELIVER_ENCAPSULATED_RESPONSE':0xEB,
'END_SESSION':0xEC,
'GET_CSR':0xED,
'SET_CERTIFICATE':0xEE,
'SUBSCRIBE_EVENT_GROUP':0xEF,
'SEND_EVENT':0xF0,
'VENDOR_DEFINED_REQUEST':0xFE,
'RESPOND_IF_READY':0xFF}

#define message for spdm responder
dict_spdm_res_1p0 = { \
'SPDM_VERSION'        : 0x04,
'SPDM_CAPABILITIES'   : 0x61,
'SPDM_DIGESTS'        : 0x01,
'SPDM_CERTIFICATE'    : 0x02,
'SPDM_CHALLENGE_AUTH' : 0x03,
'SPDM_MEASUREMENTS'   : 0x60,
'SPDM_ALGORITHMS'     : 0x63,
'SPDM_VENDOR_DEFINED_RESPONSE': 0x7E,
'SPDM_ERROR'          : 0x7F}

#define message for spdm responder
dict_spdm_res_1p1 = { \
'SPDM_DIGESTS'        : 0x01,
'SPDM_CERTIFICATE'    : 0x02,
'SPDM_CHALLENGE_AUTH' : 0x03,
'SPDM_VERSION'        : 0x04,
'SPDM_CAPABILITIES'   : 0x61,
'SPDM_MEASUREMENTS'   : 0x60,
'SPDM_ALGORITHMS'     : 0x63,
'SPDM_KEY_EXCHANGE_RSP':0x64,
'SPDM_FINISH_RSP'     :0x65,
'SPDM_PSK_EXCHANGE_RSP': 0x66,
'SPDM_PSK_FINISH_RSP' : 0x67,
'SPDM_HEARTBEAT_ACK'  : 0x68,
'SPDM_KEY_UPDATE_ACK' : 0x69,
'SPDM_ENCAPSULATED_REQUEST': 0x6A,
'SPDM_ENCAPSULATED_RESPONSE_ACK': 0x6B,
'SPDM_END_SESSION_ACK': 0x6C,
'SPDM_VENDOR_DEFINED_RESPONSE': 0x7E,
'SPDM_ERROR'          : 0x7F}

dict_spdm_res_1p2 = {
'DIGESTS':0x01,
'CERTIFICATE':0x02,
'CHALLENGE_AUTH':0x03,
'VERSION':0x04,
'CHUNK_SEND_ACK':0x05,
'CHUNK_RESPONSE':0x06,
'MEASUREMENTS':0x60,
'CAPABILITIES':0x61,
'SUPPORTED_EVENT_GROUPS':0x62,
'ALGORITHMS':0x63,
'KEY_EXCHANGE_RSP':0x64,
'FINISH_RSP':0x65,
'PSK_EXCHANGE_RSP':0x66,
'PSK_FINISH_RSP':0x67,
'HEARTBEAT_ACK':0x68,
'KEY_UPDATE_ACK':0x69,
'ENCAPSULATED_REQUEST':0x6A,
'ENCAPSULATED_RESPONSE_ACK':0x6B,
'END_SESSION_ACK':0x6C,
'CSR':0x6D,
'SET_CERTIFICATE_RSP':0x6E,
'SUBSCRIBE_EVENT_GROUP_ACK':0x6F,
'EVENT_ACK':0x70,
'VENDOR_DEFINED_RESPONSE':0x7E,
'ERROR':0x7F}

lst_req_msg = [b'Client Hello']
for k in dict_spdm_req_1p0:
  lst_req_msg.append(b'\x05\x10'+bytes.fromhex('{:02x}'.format(dict_spdm_req_1p0[k])))
for k in dict_spdm_req_1p1:
  lst_req_msg.append(b'\x05\x11'+bytes.fromhex('{:02x}'.format(dict_spdm_req_1p1[k])))
for k in dict_spdm_req_1p2:
  lst_req_msg.append(b'\x05\x12'+bytes.fromhex('{:02x}'.format(dict_spdm_req_1p2[k])))

lst_req_msg.append(b'\x00\x00\x00\x00')

tempmsg=b'\x06\xff\xff\xff\xff'
lst_req_msg.append(tempmsg)

lst_res_msg = [b'Server Hello']
for k in dict_spdm_res_1p0:
  lst_res_msg.append(b'\x05\x10'+bytes.fromhex('{:02x}'.format(dict_spdm_res_1p0[k])))
for k in dict_spdm_res_1p1:
  lst_res_msg.append(b'\x05\x11'+bytes.fromhex('{:02x}'.format(dict_spdm_res_1p1[k])))
for k in dict_spdm_res_1p2:
  lst_res_msg.append(b'\x05\x12'+bytes.fromhex('{:02x}'.format(dict_spdm_res_1p2[k])))

tempmsg=b'\x06\xff\xff\xff\xff'
lst_res_msg.append(tempmsg)


transmit_cmd  = [b'\x00\x00\x00\x01', b'\x00\x00\xde\xad', b'\x00\x00\xff\xfe']
transportType = b'\x00\x00\x00\x01'
transmit_head = [i+transportType for i in transmit_cmd]

STOP_TRANSMIT   = b'\x00\x00\xff\xfe' + b'\x00\x00\x00\x01' + b'\x00\x00\x00\x00'

STOP_COUNT = 2  # this only apply to CPLD as requester test.

LAST_MEASRECORD1 = '01014300844000'+'05'*64
LAST_MEASRECORD2 = '01018300848000'+'05'*128
LAST_MEASRECORD3 = '05018300848000'+'05'*128

def config_log(logfile):
  """ config log file include a Filehandler and a Streamhandler

  """
  logging.basicConfig(level=logging.DEBUG,
                    #format='s',
                    #format='%(asctime)s - %(levelname)s [%(filename)s]: %(name)s %(funcName)20s - Message: %(message)s',
                    #datefmt='%d.%m.%Y %H:%M:%S',
                    handlers= [
                      logging.FileHandler(logfile, mode='w'),
                      logging.StreamHandler()
                    ]
                  )

def print_lst(fh, lst, num_per_line):
  """ print long list

  :param fh: log file handler
  :param lst: long list to be print
  :param num_per_line: number of items per line
  """
  cnt = 0
  fh.write('\n    ')
  for i in lst:
    fh.write(i + ' ')
    cnt += 1
    if cnt >=num_per_line:
      fh.write('\n    ')
      cnt = 0
  fh.write('\n----\n')


class Run_SPDM_Test(object):
  """ class for spdm test execution using SPDM_EMU

  """
  def __init__(self, test_setup_json, bridge=False):
    with open(test_setup_json, 'r') as f:
      self.env = json.load(f)
    self.bridge = bridge # set MCTP Bridge option True or False
    self.bridge_up = False
    # initialize two dictionary
    self.dict_spdm_requester = {}
    self.dict_spdm_responder = {}

  def setup_test(self, requester, responder):
    """ setup requester and responder """
    #if spdmtarget.lower() not in ('cpu', 'pcieep'):
    #  logger.error("-- wrong entry of target: should be either 'cpu' or 'pcieep'")
    if requester.lower() not in ('spdm-emu', 'prot') or responder.lower() not in ('spdm-emu', 'prot'):
      logger.error("-- wrong entry of req/res: should be either 'prot' or 'spdm-emu'")
    self.req = requester.lower()
    self.res = responder.lower()
    #self.tgt = spdmtarget.lower()

    logfile = 'spdm1p0-{a}-req_{b}-res'.format(a=self.req, b=self.res)
    self.logfile = datetime.now().strftime('{}_%Y-%m-%d_%H-%M.log'.format(logfile))
    config_log(self.logfile)

    self.get_version_count = 0  # stop if GET_VERSION repeat two times

  def run_test(self):
    """ run spdm test between requester and responder
     self.req
    """
    self.run_responder()
    self.run_requester()

    self.dict_spdm_requester = {}
    self.dict_spdm_responder = {}
    self.stop_transmit = False

    while not self.stop_transmit:
      print ("-- entered loop ...")
      self.data_req = []
      self.data_res = []
      self.raw_mctp_req = array('B', [])
      self.raw_mctp_res = array('B', [])

      while not self.stop_transmit:
        self.requester_to_res()
        self.process_mctp_requester()
        print("-- self.stop_transmit: {}".format(self.stop_transmit))

        self.responder_to_req()
        self.process_mctp_responder()

        if self.get_version_count >= STOP_COUNT:
          self.stop_transmit = True

        #spdm_emu - spdm_emu
        if (self.raw_mctp_req.tobytes() == STOP_TRANSMIT):
          self.stop_transmit = True

    print("--Done: Saved data to file")

    #print(dict_spdm_requester)
    #spdm_requester = spdm.SPDM_REQUESTER(self.dict_spdm_requester)
    #if self.res == 'spdm-emu':
    #  pubkey = os.path.join(self.env['spdm_emu_dir'], 'EcP384', 'end_responder_pubkey.pem')
    #  spdm_requester.set_responder_pubkey(pubkey)
    #spdm_requester.verify_M2()
    #spdm_requester.verify_L2()
    #spdm_requester.show()

    #print(dict_spdm_responder)
    #spdm_responder = spdm.SPDM_RESPONDER(self.dict_spdm_responder)
    #spdm_responder.show()
    #self.verify_test()
    self.close_test()

  def verify_test(self):
    """ verify test
    """
    #print(dict_spdm_requester)
    #spdm_req = spdm.SPDM_REQUESTER(self.dict_spdm_requester)
    #spdm_req.set_responder_pubkey(r'C:\openspdm-master\Build\DEBUG_VS2019\X64\EcP384\end_responder_pubkey.pem')
    #spdm_req.verify_M2()
    #spdm_req.set_responder_pubkey(r'C:\openspdm-master\Build\DEBUG_VS2019\X64\EcP384\cpld_pubkey.pem')
    #spdm_req.verify_L2()
    #spdm_req.show()

    #print(dict_spdm_responder)
    #spdm_res = spdm.SPDM_RESPONDER(dict_spdm_responder)
    #spdm_res.show()
    #ipmitool -I lanplus -H 10.105.134.31 -C 17 -U debuguser -P 0penBmc1 raw 6 0x52 0x09 0x70 0x30 0x20

  def run_requester(self):
    """ run spdm requester """
    if self.req == 'spdm-emu':
      logger.info('-- run spdm-emu requester')
      req_addr = ('localhost', PORT_REQUESTER)
      print("---listen_to_requester {} port {}".format(*req_addr))
      # Create a TCP/IP socket
      self.sock_req = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

      dir = self.env['spdm_emu_dir']  # share same directory for both cases
      if self.res == 'spdm-emu':
        req_cmdline= self.env['cmd_spdm_requester_emu'] # cmd for spdm-emu as spdm.responder
      if self.res == 'prot':
        req_cmdline= self.env['cmd_spdm_requester_emu_prot_res'] # cmd for prot as spdm.responder

      self.req_rc = subprocess.run("start cmd /K " + req_cmdline, cwd = dir, shell=True, stdout=subprocess.DEVNULL)

      #print("-- bind to requester ...")
      self.sock_req.bind(req_addr)
      # Listen for incoming connections
      self.sock_req.listen()
      #print('waiting for a connection')
      self.req_conn, self.req_c_addr = self.sock_req.accept()
      print('-- connection requester done from: ', self.req_c_addr)

      logger.info('-- run_requester_dir: {}'.format(dir))
      if self.res == 'prot':
        self.hello_to_requester()

    if self.req == 'prot':
      # avk is aardvark tool object instance
      print('-- set aardvark for PRoT (FPGA or other PRoT device ...')
      if (not self.bridge):
        self.avk = avktool.mctp_avark(0x05)
      if self.bridge:
        print("-- set avk with mctp_bridge at addr 0x37")
        self.avk = avktool.mctp_avark_bridge()
        self.setup_mctp_bridge() # setup mctp_bridge


  def run_responder(self):
    """ run spdm responder """
    if self.res == 'spdm-emu':
      logger.info('-- run spdm-emu as responder')

      res_cmdline= self.env['cmd_spdm_responder_emu']
      dir = self.env['spdm_emu_dir']
      self.res_rc = subprocess.run("start cmd /K " + res_cmdline, cwd = dir, shell=True)
      time.sleep(1)
      # Create a TCP/IP socket
      self.sock_res = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # Connect the socket to the port where the server is listening
      res_server_addr = ('localhost', PORT_RESPONDER)
      print('-- connecting responder server to {} port {}'.format(*res_server_addr))
      self.sock_res.connect(res_server_addr)
      print('-- connected to responder server to {} port {}'.format(*res_server_addr))
      logger.info('-- run_responder_dir: {}'.format(dir))

      if self.req == 'prot':
        self.hello_to_responder()

    if self.res == 'prot':
      CPLD_RETRY_GET_VERSION = 3
      recv_get_version = 0

      if self.bridge:
        self.avk = avktool.mctp_avark_bridge()
        self.setup_mctp_bridge() # setup mctp_bridge
        CPLD_RETRY_GET_VERSION = 3
      else:
        self.avk = avktool.mctp_avark(0x05)
      # CPLD sends requester mctp in default... waiting for first requester MCTP
      # and continue wait for two retries of GET_VERSION
      # then wait for 'delay_time' to get ready entering responder mode
      # if not receive GET_VERSION for more than 250ms, it is in responder mode
      while (recv_get_version < CPLD_RETRY_GET_VERSION):
        cpld_s = mctp_spdm.MCTP_CPLD(self.avk.recv())
        if cpld_s.spdm_code == 0x84:
          cpld_s.show()
          recv_get_version += 1
          print('-- recv_GET_VERSION count from CPLD : {}'.format(recv_get_version))

      time.sleep(float(self.env[self.tgt]['delay_time']))


  def hello_to_responder(self):
    """ send 'Server Hello!\x00' packet to responder
        to finish first handshake to spdm-emu responder
    """
    self.sock_res.sendall(spdm.start_hello())
    logger.info('--- Hello to spdm-emu responder: {}'.format(spdm.start_hello()) )
    say_hello = True
    while say_hello:
      try:
        datachunk_s = self.sock_res.recv(CHUNK_SIZE)
      except:
        break
      if not datachunk_s:
        break  # no more data coming in, so break out of the while loop
      print("-- received from spdm_emu-responder:", datachunk_s)
      if b'Server Hello!\x00' in datachunk_s:
        say_hello = False


  def hello_to_requester(self):
    """ send 'Client Hello!\x00' packet to requester
        to finish first handshake to openspdm requester
    """
    say_hello = True
    while say_hello:
      try:
        datachunk_q = self.req_conn.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
      except:
        break
      if not datachunk_q:
        break  # no more data coming in, so break out of the while loop
      print("-- received from spdm_emu-requester:", datachunk_q)
      if b'Client Hello!\x00' in datachunk_q:
        say_hello = False

    logger.info('--- Hello to spdm_emu requester: {}'.format(spdm.server_hello()))
    self.req_conn.sendall(spdm.server_hello())


  def requester_to_res(self):
    """ SPDM.requester to SPDM.responder
     Deliver packet from requester to responder
    """
    if (self.req, self.res) == ('spdm-emu', 'spdm-emu'):
      # openspdm --> openspdm
      while True:
        try:
          datachunk_q = self.req_conn.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
        except:
          break
        if not datachunk_q:
          break # no more data coming in, so break out of the while loop
        self.sock_res.sendall(datachunk_q)
        #logger.info("-- REQ-->RES --")
        #logger.info("-- REQ-->RES datachunk: {}".format(datachunk_q.hex()))
        self.raw_mctp_req.extend(datachunk_q)  # track single mctp message
        #logger.info("**** raw_mctp_req hexstr: {}".format(self.raw_mctp_req.tobytes().hex()))
        if any(item in datachunk_q for item in lst_req_msg):
          break

    if (self.req, self.res) == ('prot', 'spdm-emu') and (not self.bridge):
      # cpld --> spdm-emu
      cpld_r = mctp_spdm.MCTP_CPLD(self.avk.recv())
      cpld_r.show()
      if cpld_r.spdm_code == dict_spdm_req_1p0['SPDM_GET_VERSION']:
        self.get_version_count += 1
        logger.info('\n--- GET_VERSION_CNT = {}'.format(self.get_version_count))
      cpld_msg = cpld_r.get_openspdm_data()
      datachunk_q = cpld_msg
      logger.info("\n-- send to spdm_emu responder message:{}".format(' '.join(['{:02x}'.format(i) for i in datachunk_q])))
      self.sock_res.sendall(datachunk_q)
      self.raw_mctp_req.extend(datachunk_q)  # track single mctp message
      self.data_req.append(self.raw_mctp_req)  # append to data_req for all message

    # BMC-Bridge case
    if (self.req, self.res) == ('prot', 'spdm-emu') and (self.bridge):
      # BMC-Bridge --> spdm-emu
      cpld_r = mctp_spdm.MCTP_BMC_Bridge(self.avk.recv())
      if cpld_r.msgcode == 0x0:
        # response MCTP control packet
        print ("--cpld_r.spdm_code: {}".format(cpld_r.spdm_code))
        resp = [0xf, 0xc, 0x6f, 0x1, 0x16, 0x9, 0xc0, 0x0, 0x1, 0x5, 0x0, 0x2, 0x0, 0x5, 0x88]
        resp = bytes(resp)
        self.avk.send(resp)

      if cpld_r.msgcode == 0x5:
        cpld_r.show()
        if cpld_r.spdm_code == dict_spdm_req_1p0['SPDM_GET_VERSION']:
          logger.info('\n--- GET_VERSION_CNT = {}'.format(self.get_version_count))

        cpld_msg = cpld_r.get_openspdm_data()
        datachunk_q = cpld_msg
        logger.info("\n-- send to spdm_emu responder message:{}".format(' '.join(['{:02x}'.format(i) for i in datachunk_q])))
        self.sock_res.sendall(datachunk_q)
        self.raw_mctp_req.extend(datachunk_q)  # track single mctp message
        self.data_req.append(self.raw_mctp_req)  # append to data_req for all message

    if (self.req, self.res) == ('spdm-emu', 'prot') and (not self.bridge):
      # spdm-emu --> cpld
      openspdm_msg_done = False
      while not openspdm_msg_done:
        try:
          datachunk_q = self.req_conn.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
          self.raw_mctp_req.extend(datachunk_q)  # add chunk to your already collected data
        except:
          break
        if not datachunk_q:
          break # no more data coming in, so break out of the while loop
        msg_bytes = self.raw_mctp_req.tobytes()
        if any(item in msg_bytes for item in lst_req_msg):
          openspdm_msg_done = True

      # send to CPLD after done
      logger.info('-- mctp_req: {}'.format(' '.join(['{:02x}'.format(i) for i in self.raw_mctp_req.tobytes()])))
      cpld_q = mctp_spdm.MCTP_SOCKET(self.raw_mctp_req.tobytes())
      cpld_q.show()

      if (self.raw_mctp_req.tobytes() == STOP_TRANSMIT):
          self.stop_transmit = True
          return

      logger.info("-- decode spdm message --")
      spdm_msg = spdm.egs_spdm(self.raw_mctp_req.tobytes())
      spdm_msg.decode_message()

      smb_data = cpld_q.get_smbus_data()
      if isinstance(smb_data, (bytes, bytearray)):
        logger.info('-- send to cpld (responder) data: {}'.format(' '.join(['{:02x}'.format(i) for i in smb_data])))
        self.avk.send(smb_data)
      elif isinstance(smb_data, list):
        for segdata in smb_data:
          logger.info("-- segdata over smbus: {}".format(' '.join(['{:02x}'.format(i) for i in segdata])))
          self.avk.send(segdata)

      # accumulate data for post process
      self.data_req.append(self.raw_mctp_req)  # append raw_mctp_res to for all

    # BMC-Bridge case
    if (self.req, self.res) == ('spdm-emu', 'prot') and (self.bridge):
      # spdm-emu --> cpld
      openspdm_msg_done = False
      while not openspdm_msg_done:
        try:
          datachunk_q = self.req_conn.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
          self.raw_mctp_req.extend(datachunk_q)  # add chunk to your already collected data
        except:
          break
        if not datachunk_q:
          break # no more data coming in, so break out of the while loop
        msg_bytes = self.raw_mctp_req.tobytes()
        if any(item in msg_bytes for item in lst_req_msg):
          openspdm_msg_done = True

      # send to CPLD after done
      logger.info('-- mctp_req: {}'.format(' '.join(['{:02x}'.format(i) for i in self.raw_mctp_req.tobytes()])))
      cpld_q = mctp_spdm.MCTP_SOCKET(self.raw_mctp_req.tobytes())
      cpld_q.show()

      if (self.raw_mctp_req.tobytes() == STOP_TRANSMIT):
          self.stop_transmit = True
          return

      logger.info("-- decode spdm message --")
      spdm_msg = spdm.egs_spdm(self.raw_mctp_req.tobytes())
      spdm_msg.decode_message()

      smb_data = cpld_q.get_smbus_data_bridge()
      if isinstance(smb_data, (bytes, bytearray)):
        logger.info('-- send to cpld (responder) data: {}'.format(' '.join(['{:02x}'.format(i) for i in smb_data])))
        self.avk.send(smb_data)
      elif isinstance(smb_data, list):
        for segdata in smb_data:
          logger.info("-- segdata over smbus: {}".format(' '.join(['{:02x}'.format(i) for i in segdata])))
          self.avk.send(segdata)

      # accumulate data for post process
      self.data_req.append(self.raw_mctp_req)  # append raw_mctp_res to for all



  def responder_to_req(self):
    """ SPDM responder to SPDM requester """
    if self.stop_transmit: return
    if (self.req, self.res) == ('spdm-emu', 'spdm-emu'):
      """ responder to requester """
      while True:
        try:
          datachunk_s = self.sock_res.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
          #print('-- datachunk_s: {}'.format(datachunk_s))
        except:
          break
        if not datachunk_s:
          break  # no more data coming in, so break out of the while loop

        self.req_conn.sendall(datachunk_s)
        #logger.info("-- RES-->REQ --")
        #logger.info("-- RES-->REQ datachunk: {}".format(datachunk_s))
        self.raw_mctp_res.extend(datachunk_s)  # add chunk to your already collected data
        #logger.info("**** raw_mctp_res hexstr: {}".format(self.raw_mctp_res.tobytes().hex()))
        # check spdm message code switch to req
        if any(item in datachunk_s for item in lst_res_msg):
          break

    if (self.req, self.res) == ('prot', 'spdm-emu'):
      # openspdm (res) --> cpld (req)
      openspdm_msg_done = False
      while (not openspdm_msg_done):
        try:
          datachunk_s = self.sock_res.recv(CHUNK_SIZE)
          self.raw_mctp_res.extend(datachunk_s)  # add chunk to your already collected data
        except:
          break
        if not datachunk_s:
          break  # no more data coming in, so break out of the while loop

        msg_bytes = self.raw_mctp_res.tobytes()
        #print('-- mctp_res:', self.raw_mctp_res.tobytes())
        if any(item in msg_bytes for item in lst_res_msg):
          openspdm_msg_done = True
          # send to CPLD after done
          logger.info('-- mctp_res: {}'.format(' '.join(['{:02x}'.format(i) for i in self.raw_mctp_res.tobytes()])))
          cpld_r = mctp_spdm.MCTP_SOCKET(self.raw_mctp_res.tobytes())
          cpld_r.show()
          logger.info("-- decode spdm message --")
          spdm_msg = spdm.egs_spdm(self.raw_mctp_res.tobytes())
          spdm_msg.decode_message()

          if not self.bridge:
            smb_data = cpld_r.get_smbus_data()
          if self.bridge:
            smb_data = cpld_r.get_smbus_data_bridge()

          if isinstance(smb_data, (bytes, bytearray)):
            logger.info('-- send to cpld (requester) data: {}'.format(' '.join(['{:02x}'.format(i) for i in smb_data])))
            self.avk.send(smb_data)
          elif isinstance(smb_data, list):
            for segdata in smb_data:
              logger.info("-- segdata over smbus: {}".format(' '.join(['{:02x}'.format(i) for i in segdata])))
              self.avk.send(segdata)

          self.data_res.append(self.raw_mctp_res)  # append raw_mctp_res to for all

    if (self.req, self.res) == ('spdm-emu', 'prot'):
      # cpld-res --> openspdm-res, need add mctp_bridge option

      print("-- recv data from CPLD...")
      spdm_emu_data = b''
      cpld_s = mctp_spdm.MCTP_CPLD(self.avk.recv())  # CPLD is responder
      #if cpld_s.is_multi_mctp():
      #  spdm_emu_data = cpld_s.data_buffer
      #  cpld_tmp = mctp_spdm.MCTP_CPLD(self.avk.recv())
      print("** cpld_s.input_data[6]={}, som={}, eom={}".format(cpld_s.input_data[6], cpld_s.som, cpld_s.eom))
      print("** cpld_s.data_buffer={}".format(cpld_s.data_buffer))
      # som=1, eom=0
      while True:
        cpld_s.som = (cpld_s.input_data[6] & 0x80) >> 7
        cpld_s.eom = (cpld_s.input_data[6] & 0x40) >> 6
        cpld_s.seq = (cpld_s.input_data[6] & 0x30) >> 4
        if cpld_s.som == 1 and cpld_s.eom == 1:
          spdm_emu_data += bytes(cpld_s.data_buffer)
          break
        if cpld_s.som == 1 and cpld_s.eom == 0:
          spdm_emu_data += bytes(cpld_s.data_buffer)
        if cpld_s.som == 0 and cpld_s.eom == 0:
          spdm_emu_data += bytes(cpld_s.data_buffer[1:])
        if cpld_s.som == 0 and cpld_s.eom == 1:
          spdm_emu_data += bytes(cpld_s.data_buffer[1:])
          break
        #print("-- spdm_emu_data={}".format(spdm_emu_data))
        cpld_s = mctp_spdm.MCTP_CPLD(self.avk.recv())
        print("-- cpld_s.input_data[6]={}, som={}, eom={}, seq={}".format(cpld_s.input_data[6], cpld_s.som, cpld_s.eom, cpld_s.seq))
        print("-- cpld_s.data_buffer={}".format(cpld_s.data_buffer))

      """
      while cpld_s.som == 1 and cpld_s.eom == 1:
        if cpld_s.som == 1:
          spdm_emu_data += bytes(cpld_s.data_buffer)
        if cpld_s.som == 0:
          spdm_emu_data += bytes(cpld_s.data_buffer[1:])

        print("-- spdm_emu_data={}".format(spdm_emu_data))
        cpld_s = mctp_spdm.MCTP_CPLD(self.avk.recv())
        print("-- cpld_s.input_data[6]={}, som={}, eom={}".format(cpld_s.input_data[6], cpld_s.som, cpld_s.eom))
        print("-- cpld_s.data_buffer={}".format(cpld_s.data_buffer))

      if cpld_s.som==0 and cpld_s.eom == 1:
        spdm_emu_data += bytes(cpld_s.data_buffer[1:])
      if cpld_s.som==1 and cpld_s.eom == 1:
        spdm_emu_data += bytes(cpld_s.data_buffer)
      """
      buffer_size = struct.pack('>I', len(spdm_emu_data))
      print("-- buffer_size = {}, spdm_emu_data={}".format(len(spdm_emu_data), spdm_emu_data))
      self.openspdm_data = b'\x00\x00\x00\x01'*2 + buffer_size + bytes(spdm_emu_data)
      temp = ' '.join(["%02x"%i for i in self.openspdm_data])
      logger.info('-- send to openspdm_data = {}'.format(temp))
      datachunk_s = self.openspdm_data
        #datachunk_s = spdm_emu_data
        # TBD: merge spdm_emu_data as spdm_emu_chunk size

      cpld_s.show()
      #cpld_msg = cpld_s.get_openspdm_data()
      #datachunk_s = cpld_msg
      logger.info("\n-- send to spdm_emu requester message:{}".format(' '.join(['{:02x}'.format(i) for i in datachunk_s])))

      self.req_conn.sendall(datachunk_s)
      self.raw_mctp_res.extend(datachunk_s)  # track single mctp message
      self.data_res.append(self.raw_mctp_res)  # append to data_req for all message

      """
      if self.bridge:
        # process merge multiple mctp over smbus pkts as one and send it to spdm-emu
        # TBD 7/3/22-11:42am
        cpld_s = mctp_spdm.MCTP_CPLD(self.avk.recv())  # CPLD is responder
        if cpld_s.is_multi_mctp():
        else:
        cpld_s.show()
        cpld_msg = cpld_s.get_openspdm_data()
        datachunk_s = cpld_msg
        logger.info("\n-- send to spdm_emu requester message:{}".format(' '.join(['{:02x}'.format(i) for i in datachunk_s])))

        self.req_conn.sendall(datachunk_s)
        self.raw_mctp_res.extend(datachunk_s)  # track single mctp message
        self.data_res.append(self.raw_mctp_res)  # append to data_req for all message
      """


  def process_mctp_requester(self):
    """ process requester MCTP packet
    """
    #logger.info("-- process mctp_requester ...")
    #print(self.raw_mctp_req.tobytes())
    if self.stop_transmit: return

    mctp_data = mctp_spdm.MCTP_SOCKET(self.raw_mctp_req.tobytes())
    #logger.info('\n-- To Responder: {}-responder'.format(self.res))
    #mctp_data.show()
    input_data = mctp_data.get_spdm_data()

    if input_data is not None:
     spdm_msg = spdm.egs_spdm(input_data)
     spdm_msg.decode_message()

     #print(mctp_data.spdm_msgcode)
     if mctp_data.spdm_msgcode in self.dict_spdm_requester.keys():
       self.dict_spdm_requester[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])
     else:
       self.dict_spdm_requester[mctp_data.spdm_msgcode] = []
       self.dict_spdm_requester[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])

     if mctp_data.spdm_msgcode in self.dict_spdm_responder.keys():
       self.dict_spdm_responder[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])
     else:
       self.dict_spdm_responder[mctp_data.spdm_msgcode] = []
       self.dict_spdm_responder[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])

    self.data_req.append(self.raw_mctp_req)  # append to data_req for all message
    self.raw_mctp_req = array('B', [])  # clear single message


  def process_mctp_responder(self):
    """ process responder MCTP packet
    """
    if self.stop_transmit: return
    logger.info("-- process mctp_responder ...")

    mctp_data = mctp_spdm.MCTP_SOCKET(self.raw_mctp_res.tobytes())
    logger.info('\n-- To Requester: {}-requester'.format(self.req))
    mctp_data.show()
    input_data = mctp_data.get_spdm_data()

    #STOP
    #if self.res == 'cpld':
    #  input_data = self.raw_mctp_res.tobytes()

    if input_data is not None:
      spdm_msg = spdm.egs_spdm(input_data)
      spdm_msg.decode_message()

      #print('--mctp_data.spdm_msgcode: ', mctp_data.spdm_msgcode)
      if mctp_data.spdm_msgcode in self.dict_spdm_requester.keys():
        self.dict_spdm_requester[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])
      else:
        self.dict_spdm_requester[mctp_data.spdm_msgcode] = []
        self.dict_spdm_requester[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])

      if mctp_data.spdm_msgcode in self.dict_spdm_responder.keys():
        self.dict_spdm_responder[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])
      else:
        self.dict_spdm_responder[mctp_data.spdm_msgcode] = []
        self.dict_spdm_responder[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])

    if spdm.dict_Measurements['MeasRecord']['size'] in [0x47, 0x87]:
      #print('-- spdm.dict_Measurement.MeasRecord.value', spdm.dict_Measurements['MeasRecord']['value'].hex())
      # stop for both 64 and 128 bytes measurement manifest size
      if spdm.dict_Measurements['MeasRecord']['value'].hex() in [LAST_MEASRECORD1, LAST_MEASRECORD2, LAST_MEASRECORD3]:
        self.stop_transmit = True

    self.data_res.append(self.raw_mctp_res)  # append raw_mctp_res to for all
    if self.raw_mctp_res.tobytes() == STOP_TRANSMIT:
      self.stop_transmit = True
    else:
      self.raw_mctp_res = array('B', [])  # clear for next message


  def setup_mctp_bridge(self):
    """setup BMC MCTP bridge """
    if self.bridge_up:  # if self.bridge_up is True, skip this
      return
    avkobj = self.avk
    bdgobj = mctp.MCTP_Bridge()

    cnt = 0
    while cnt < 100:
      pkt=avkobj.recv()
      if pkt[7] == 0x00:
        # mctp control message
        bdgobj.set_input_data(pkt)
        resp = bdgobj.gen_response()
        avkobj.send(resp)  # response mctp control pkt
        resplst = [x for x in resp]
        print("\n--{}. MCTPCtrlMsgCmd(0x{:02x}): \"{}\" ".format(cnt, bdgobj.mctp_msgCmd, mctp.dict_MCTP_Ctrl_CmdCode["0x{:02x}".format(bdgobj.mctp_msgCmd)]))
        print("--Receiving: {}".format(pkt))
        print("--Wrote-resp:{}".format(resplst))
        #bdgobj.show_mctpctrl_msg()
        if pkt[5] == 0x16:
          self.bridge_up = True
          break
      elif pkt[7] == 0x05:
        # print SPDM MCTP message
        print("~~!!~~Receiving SPDM message: {}".format(pkt))
        self.bridge_up = True
        break
      else:
        # print other MCTP message
        print("--Receiving message: {}".format(pkt))
      cnt += 1
    print("-- MCTP_Bridge Up: {}".format(self.bridge_up))


  def close_test(self):
    """ do close actions for the test """
    if self.req == 'spdm-emu': self.req_conn.close()
    if self.res == 'spdm-emu': self.sock_res.close()
    if (self.req == 'prot') or (self.res == 'prot'):
      self.avk.close()
    logging.shutdown()


def setup_mctp_bridge():
  """setup BMC MCTP bridge """
  avkobj = avktool.mctp_avark_bridge()
  bdgobj=mctp.MCTP_Bridge()

  cnt = 0
  get_version_cnt = 0
  get_cap_cnt = 0
  neg_alg_cnt = 0
  get_dgst_cnt =0
  while cnt < 10000:
    pkt=avkobj.recv()
    if pkt[7] == 0x00:
      # mctp control message
      bdgobj.set_input_data(pkt)
      resp = bdgobj.gen_response()
      avkobj.send(resp)  # response mctp control pkt
      resplst = [x for x in resp]
      print("\n--{}. MCTPCtrlMsgCmd(0x{:02x}): \"{}\" ".format(cnt, bdgobj.mctp_msgCmd, mctp.dict_MCTP_Ctrl_CmdCode["0x{:02x}".format(bdgobj.mctp_msgCmd)]))
      print("--Receiving: {}".format(pkt))
      print("--Wrote-resp:{}".format(resplst))
      #bdgobj.show_mctpctrl_msg()
    elif pkt[7] == 0x05 and pkt[9] == 0x84:
      # print SPDM MCTP message
      get_version_cnt += 1
      #print("~~!!~~Receiving SPDM message: {}, get_version_cnt: {}".format(pkt, get_version_cnt))
      if get_version_cnt == 1:
        # 0f 0e 6f 01 16 09 c8 05 10 04 00 00 00 01 00 10 44
        #resp1=[0x0f, 0x0e, 0x6f, 0x01, 0x16, 0x09, 0xc8, 0x05, 0x10, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x44]
        resp1=mctp.brige_smbus_data(mctp.lst_spdm_res[0]).smbus_data
        avkobj.send(bytes(resp1))
        lst=' '.join(['{:02x}'.format(i) for i in bytes(resp1)])
        print("--Receiving: {}".format(pkt))
        print("--Wrote-resp:{}".format(lst))
        get_version_cnt = 0  # clear get_version_cnt after response

    elif pkt[7] == 0x05 and pkt[9] == 0xE1:
      get_cap_cnt += 1
      #print("~~!!~~Receiving SPDM message: {}, get_cap_cnt: {}".format(pkt, get_cap_cnt))
      if get_cap_cnt == 1:
        #resp2=[0x0f, 0x12, 0x6f, 0x00, 0x00, 0x00, 0xc8, 0x05, 0x10, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0xf6]
        resp2=mctp.brige_smbus_data(mctp.lst_spdm_res[1]).smbus_data
        avkobj.send(bytes(resp2))
        lst=' '.join(['{:02x}'.format(i) for i in bytes(resp2)])
        print("--Receiving: {}".format(pkt))
        print("--Wrote-resp:{}".format(lst))
        get_cap_cnt = 0
    elif pkt[7] == 0x05 and pkt[9] == 0xE3:
      neg_alg_cnt += 1
      #print("~~!!~~Receiving SPDM message: {}, neg_alg_cnt: {}".format(pkt, neg_alg_cnt))
      if neg_alg_cnt == 1:
        #resp2=[0x0f, 0x12, 0x6f, 0x00, 0x00, 0x00, 0xc8, 0x05, 0x10, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0xf6]
        resp3=mctp.brige_smbus_data(mctp.lst_spdm_res[2]).smbus_data
        avkobj.send(bytes(resp3))
        lst=' '.join(['{:02x}'.format(i) for i in bytes(resp3)])
        print("--Receiving: {}".format(pkt))
        print("--Wrote-resp:{}".format(lst))
        neg_alg_cnt = 0
    elif pkt[7] == 0x05 and pkt[9] == 0x81:
      get_dgst_cnt += 1
      #print("~~!!~~Receiving SPDM message: {}, neg_alg_cnt: {}".format(pkt, get_dgst_cnt))
      if get_dgst_cnt == 1:
        resp4=mctp.brige_smbus_data(mctp.lst_spdm_res[3]).smbus_data
        avkobj.send(bytes(resp4))
        lst=' '.join(['{:02x}'.format(i) for i in bytes(resp4)])
        print("--Receiving: {}".format(pkt))
        print("--Wrote-resp:{}".format(lst))
        get_dgst_cnt = 0

    else:
      # print other MCTP message
      print("--Receiving message: {}".format(pkt))
    cnt += 1


def main(args):
  """ test PRoT command line options
  """
  parser = argparse.ArgumentParser(description="-- Run spdm-emu validation test ")
  parser.add_argument('-get_setup', action='store_true', help="copy execution json file to work folder")
  parser.add_argument('-s', '--setup', metavar="[setup json file]",  dest='setup_json', help='spdm-emu execution json file')
  parser.add_argument('-req', metavar="[spdm requester]",  dest='spdm_req', default = 'spdm-emu', help="set SPDM requester: either spdm-emu or prot, default is spdm-emu")
  parser.add_argument('-res', metavar="[spdm responder]",  dest='spdm_res', default = 'spdm-emu', help="set SPDM responder: either spdm-emu or prot, default is spdm-emu")
  #parser.add_argument('-t',   metavar="[spdm target]",     dest='target',   default = 'cpu', help="set SPDM target device: cpu or pcieep, default is cpu")

  subparser = parser.add_subparsers(dest='mctp_bridge')
  bridge = subparser.add_parser('bridge')
  bridge.add_argument('-s', '--setup', metavar="[setup json file]",  dest='setup_json', help='spdm-emu execution json file')
  bridge.add_argument('-req', metavar="[spdm requester]",  dest='spdm_req', default = 'prot', help="set SPDM requester: either spdm-emu or prot, default is prot")
  bridge.add_argument('-res', metavar="[spdm responder]",  dest='spdm_res', default = 'spdm-emu', help="set SPDM responder: either spdm-emu or prot, default is spdm-emu")
  bridge.add_argument('-t',   metavar="[spdm target]",     dest='target',   default = 'cpu', help="set SPDM target device: cpu or pcieep, default is cpu")

  args = parser.parse_args(args)
  #print(args)
  if args.get_setup:
    print('-- copy the execution json file to {}'.format(os.getcwd()))
    src_json_file = os.path.join(os.path.dirname(__file__), 'json', 'spdm-emu-exec', 'spdm_emu_execution.json')
    dst_json_file = os.path.join(os.getcwd(), 'spdm_emu_execution.json')
    shutil.copyfile(src_json_file, dst_json_file)
  elif args.setup_json and (not args.mctp_bridge):
    print("-- run spdm test between requester:{} and responder:{} using manifest:{}".format(args.spdm_req, args.spdm_res, args.setup_json))
    mytest = Run_SPDM_Test(args.setup_json)
    #mytest.setup_test(args.target, args.spdm_req, args.spdm_res)
    mytest.setup_test(args.spdm_req, args.spdm_res)
    mytest.run_test()
  elif args.setup_json and args.mctp_bridge:
    if args.spdm_res == 'prot': args.spdm_req = 'spdm-emu'
    if args.spdm_req == 'prot': args.spdm_res = 'spdm-emu'
    #if args.spdm_res == 'spdm-emu': args.spdm_req = 'prot'
    #if args.spdm_req == 'spdm-emu': args.spdm_res = 'prot'
    print("-- MCTP_Bridge: run spdm test over mctp_bridge between requester:{} and responder:{} using manifest:{}".format(args.spdm_req, args.spdm_res, args.setup_json))
    mytest = Run_SPDM_Test(args.setup_json, bridge=True)
    mytest.setup_test(args.target, args.spdm_req, args.spdm_res)
    mytest.run_test()

if __name__ == '__main__':
  main(sys.argv[1:])

