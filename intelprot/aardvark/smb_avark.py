#!/usr/bin/env python3
# smb_avark module
"""
  :platform: Linux, Windows
  :synopsis: i2c driver wrapper to send and receive traffic to CPLD using aadvark tool

  Aardvark is I2C/SPI host adapter, refer https://www.totalphase.com/products/aardvark-i2cspi/

  CPLD slave address is 0x70

"""

import binascii, warnings, logging, datetime, time
from array import array, ArrayType
import aardvark_py as avark
from intelprot import mctp

CPLD_SLAVE_ADDR = 0x70  # CPLD Slave Address 0x38 0011,1000
BMC_SLAVE_ADDR  = 0x09  # 0000,1001  0001,0010 (0x12)

BUS_TIMEOUT      = 100  # ms
BUS_POLL_TIMEOUT = 10   # ms
I2C_BITRATE      = 100  # 100 KHz

BUFFER_SIZE      = 65535 # Tx/Rx buffer size

STATUS_OPEN   =  1
STATUS_CLOSED = -1
STATUS_NOTSET =  0

import logging
logger = logging.getLogger(__name__)

def detect():
  """ detect aardvark device """
  print("Detecting Aardvark adapters...")

  # Find all the attached devices
  (num, ports, unique_ids) = avark.aa_find_devices_ext(16, 16)
  rtn = []
  if num > 0:
    print("%d device(s) found:" % num)
    # Print the information on each device
    for i in range(num):
      port      = ports[i]
      unique_id = unique_ids[i]
      # Determine if the device is in-use
      inuse = "(avail)"
      if (port & avark.AA_PORT_NOT_FREE):
        inuse = "(in-use)"
        port  = port & ~(avark.AA_PORT_NOT_FREE)
      # Display device port number, in-use status, and serial number
      print("    port = %d   %s  (%04d-%06d)" %
           (port, inuse, unique_id // 1000000, unique_id % 1000000))
      if (inuse == "(avail)"):
        rtn.append((True, port, inuse))
      else:
        rtn.append((False, port, inuse))
  else:
    print("No devices found.")
  return rtn


class mctp_avark(object):
  """ class for aardvark configuration as PCIe End Point device on SMBus

  :param device_addr: destination address

  """
  def __init__(self, device_addr):
    self.device_addr = device_addr
    self.cpld_slave_addr = CPLD_SLAVE_ADDR
    self.open()

  def open(self, port=0, bitrate=I2C_BITRATE):
    avark.aa_i2c_free_bus(port)
    avark.aa_close(port)  # close port 0 first
    self.port    = port
    self.status  = STATUS_NOTSET
    self.bitrate = bitrate
    self.handle = avark.aa_open(self.port)
    if self.handle <= 0:
      logger.error("Unable to open Aardvark device on port %d" % port)
      logger.error("Error code = %d" % self.handle)
      return False
    else:
      self.status = STATUS_OPEN

    # ensure it is configured as I2C subsystem is enabled
    avark.aa_configure(self.handle, avark.AA_CONFIG_SPI_I2C)
    avark.aa_i2c_pullup(self.handle, avark.AA_I2C_PULLUP_BOTH)
    avark.aa_i2c_bitrate(self.handle, I2C_BITRATE)
    avark.aa_i2c_bus_timeout(self.handle, BUS_TIMEOUT)
    avark.aa_i2c_slave_enable(self.handle, self.device_addr, 0, 0)  # enable slave mode


  def check_if_spdm_packet(self, lst):
    """ check if it is spdm mctp packet over smbus

    :param lst: list of received data bytes by aavark tool

    :return True: if it is SPDM payload, otherwise, return False
    """
    # add filter only report valid SPDM over MCTP packets
    # lst = 0f c9 01 00 00 00 c0 05 10 60
    # print('-->', lst[0], lst[7], lst[8])
    if (lst[0] == 0x0F) and (lst[7] == 0x05) and (lst[8] >>4 == 0x1):
      return True
    else:
      return False

  def recv(self):
    """ slave read data from Aardvark tool from CPLD SPDM SMBus interface

    """
    logger.info('-- recv waiting spdm mctp pkts over smbus')
    print('-- recv waiting spdm mctp pkts over smbus')
    #t1=time.time()
    #cnt = 0
    spdm_data = False
    while (spdm_data == False):
      num_bytes = 0
      data_recv = array('B', [])
      while(num_bytes <= 0):
        result = avark.aa_async_poll(self.handle, BUS_POLL_TIMEOUT)
        #print("--> result: {}".format(result))
        if result == avark.AA_ASYNC_I2C_READ:
          (num_bytes, addr, data_recv) = avark.aa_i2c_slave_read(self.handle, BUFFER_SIZE)
          print("-- num_bytes: {}, addr: {}, data_recv: {}".format(num_bytes, addr, data_recv))
        #time.sleep(0.01)
        #cnt += 1

      if num_bytes == 0:
        warnings.warn(UserWarning("i2c: Fail to get any response"))

      bdata=data_recv.tobytes()
      lst=' '.join(['{:02x}'.format(i) for i in bdata])
      #self.logger.info("num_bytes = {}, addr = 0x{:02X}, \n--CPLD: data_recv (in hex) = {}".format(num_bytes, addr, lst))
      spdm_data = self.check_if_spdm_packet(bdata)

    logger.info("num_bytes = {}, addr = 0x{:02X}, \n****CPLD: data_recv (in hex) = {}".format(num_bytes, addr, lst))
    return data_recv

  def send(self, data_send):
    """
    send data bytes from Aardvark tool

    :param data_send: data send out in bytearray
    :type bytes: bytes, bytearray

    append PEC byte::

      https://crccalc.com/
      In Aardvark: Master - addr 0x70
      SPDM_VERSION message bytes: 0F 0E 0B 00 00 00 C8 05 10 04 00 00 00 01 00 10 14
      Calculate PEC code as: "E0 0F 0E 0B 00 00 00 C8 05 10 04 00 00 00 01 00 10" --> 0x14

    """
    num_bytes = 0
    (err_flag, write_byte_count) = avark.aa_i2c_write_ext(self.handle, self.cpld_slave_addr, avark.AA_I2C_NO_FLAGS, array('B', data_send))
    logger.info('-- err_flag: {}, length = {}'.format(err_flag, write_byte_count))


  def send_recv(self, data_send):
    """ AFM: DeviceAddr=0x02, UUID=0x0001 """
    # INTERVAL_TIMEOUT = 1000
    num_bytes = 0
    data_recv = array('B', [])
    (err_flag, write_byte_count) = avark.aa_i2c_write_ext(self.handle, self.cpld_slave_addr, avark.AA_I2C_NO_FLAGS, array('B', data_send))

    result = avark.aa_async_poll(self.handle, BUS_POLL_TIMEOUT)
    if result == avark.AA_ASYNC_I2C_READ:
      (num_bytes, addr, data_recv) = avark.aa_i2c_slave_read(self.handle, BUFFER_SIZE)

    if num_bytes == 0:
      warnings.warn(UserWarning("i2c: Fail to get any response"))
    logger.info("err_flag = {}, slave_addr = 0x{:02X}, write_byte_count={}, data_send = {}".format(err_flag, self.cpld_slave_addr, write_byte_count, data_send))
    logger.info("num_bytes = {}, dest_addr = 0x{:02X}, data_recv = {}".format(num_bytes, self.device_addr, data_recv))
    return (err_flag, write_byte_count, data_send, data_recv)

  def free(self):
    """ free i2c bus """
    rtn = avark.aa_i2c_free_bus(self.port)
    return rtn

  def close(self):
    """ close Aardvark tool driver """
    self.free()
    rtn = avark.aa_close(self.port)
    if (rtn > 0):
      print("-- aardvark device is closed: {}".format(rtn))

#==== test ====
class mctp_avark_2(object):
  """ class for aardvark configuration as PCIe End Point device on SMBus

  :param device_addr: destination address

  """
  def __init__(self, device_addr):
    self.device_addr = device_addr
    self.bmc_slave_addr = BMC_SLAVE_ADDR
    self.open()

  def open(self, port=0, bitrate=I2C_BITRATE):
    avark.aa_i2c_free_bus(port)
    avark.aa_close(port)  # close port 0 first
    self.port    = port
    self.status  = STATUS_NOTSET
    self.bitrate = bitrate
    self.handle = avark.aa_open(self.port)
    if self.handle <= 0:
      logger.error("Unable to open Aardvark device on port %d" % port)
      logger.error("Error code = %d" % self.handle)
      return False
    else:
      self.status = STATUS_OPEN

    # ensure it is configured as I2C subsystem is enabled
    avark.aa_configure(self.handle, avark.AA_CONFIG_SPI_I2C)
    avark.aa_i2c_pullup(self.handle, avark.AA_I2C_PULLUP_BOTH)
    avark.aa_i2c_bitrate(self.handle, I2C_BITRATE)
    avark.aa_i2c_bus_timeout(self.handle, BUS_TIMEOUT)
    avark.aa_i2c_slave_enable(self.handle, self.device_addr, 0, 0)  # enable slave mode


  def check_if_spdm_packet(self, lst):
    """ check if it is spdm mctp packet over smbus

    :param lst: list of received data bytes by aavark tool

    :return True: if it is SPDM payload, otherwise, return False
    """
    # add filter only report valid SPDM over MCTP packets
    # lst = 0f c9 01 00 00 00 c0 05 10 60
    # print('-->', lst[0], lst[7], lst[8])
    if (lst[0] == 0x0F) and (lst[7] == 0x05) and (lst[8] >>4 == 0x1):
      return True
    else:
      return False

  def recv(self):
    """ slave read data from Aardvark tool from CPLD SPDM SMBus interface

    """
    logger.info('-- recv waiting spdm mctp pkts over smbus')
    print('-- recv waiting spdm mctp pkts over smbus')
    #t1=time.time()
    #cnt = 0
    spdm_data = False
    while (spdm_data == False):
      num_bytes = 0
      data_recv = array('B', [])
      while(num_bytes <= 0):
        result = avark.aa_async_poll(self.handle, BUS_POLL_TIMEOUT)
        #print("--> result: {}".format(result))
        if result == avark.AA_ASYNC_I2C_READ:
          (num_bytes, addr, data_recv) = avark.aa_i2c_slave_read(self.handle, BUFFER_SIZE)
          print("-- num_bytes: {}, addr: {}, data_recv: {}".format(num_bytes, addr, data_recv))
        #time.sleep(0.01)
        #cnt += 1

      if num_bytes == 0:
        warnings.warn(UserWarning("i2c: Fail to get any response"))

      bdata=data_recv.tobytes()
      lst=' '.join(['{:02x}'.format(i) for i in bdata])
      #self.logger.info("num_bytes = {}, addr = 0x{:02X}, \n--CPLD: data_recv (in hex) = {}".format(num_bytes, addr, lst))
      spdm_data = self.check_if_spdm_packet(bdata)

    logger.info("num_bytes = {}, addr = 0x{:02X}, \n****CPLD: data_recv (in hex) = {}".format(num_bytes, addr, lst))
    return data_recv

  def send(self, data_send):
    """
    send data bytes from Aardvark tool

    :param data_send: data send out in bytearray
    :type bytes: bytes, bytearray

    append PEC byte::

      https://crccalc.com/
      In Aardvark: Master - addr 0x70
      SPDM_VERSION message bytes: 0F 0E 0B 00 00 00 C8 05 10 04 00 00 00 01 00 10 14
      Calculate PEC code as: "E0 0F 0E 0B 00 00 00 C8 05 10 04 00 00 00 01 00 10" --> 0x14

    """
    num_bytes = 0
    (err_flag, write_byte_count) = avark.aa_i2c_write_ext(self.handle, self.bmc_slave_addr, avark.AA_I2C_NO_FLAGS, array('B', data_send))
    logger.info('-- err_flag: {}, length = {}'.format(err_flag, write_byte_count))
    print('-- err_flag: {}, length = {}'.format(err_flag, write_byte_count))


  def free(self):
    """ free i2c bus """
    rtn = avark.aa_i2c_free_bus(self.port)
    return rtn

  def close(self):
    """ close Aardvark tool driver """
    self.free()
    rtn = avark.aa_close(self.port)
    if (rtn > 0):
      print("-- aardvark device is closed: {}".format(rtn))


#BMC_SLAVE_ADDR = 0x12
#-----------------
class mctp_avark_bridge():
  """ class for aardvark configuration as MCTP-bridge after BMC
      for PCIe End Point device on SMBus
      select destination slave address; (0x37(7bit)<<1) - use 0x6E

  :param device_addr: destination address

  """

  def __init__(self, device_addr=0x37, recvTimeout=200):
    self.device_addr = device_addr
    self.cpld_slave_addr = CPLD_SLAVE_ADDR
    self.bmc_slave_addr  = BMC_SLAVE_ADDR
    self.handle = -1
    self.isRunning = False
    self.sendQueue = []
    self.recvQueue = []
    self.receiveTimeout = recvTimeout
    self.open()

  def open(self, port=0, bitrate=I2C_BITRATE):
    avark.aa_i2c_free_bus(port)
    avark.aa_close(port)  # close port 0 first
    self.port    = port
    self.status  = STATUS_NOTSET
    self.bitrate = bitrate
    self.handle  = avark.aa_open(self.port)
    if self.handle <= 0:
      logger.error("Unable to open Aardvark device on port %d" % port)
      logger.error("Error code = %d" % self.handle)
      return False
    else:
      self.status = STATUS_OPEN

    #checkError("Configure", aa_configure(self.handle,  AA_CONFIG_SPI_I2C))
    #checkError("Pullup", aa_i2c_pullup(self.handle, AA_I2C_PULLUP_NONE))
    #checkError("Bus timeout", aa_i2c_bus_timeout(self.handle, 1000))
    #checkError("BitRate", aa_i2c_bitrate(self.handle, 100))
    #checkError("Slave Enable", aa_i2c_slave_enable(self.handle, self.address, 0, 0))

    # ensure it is configured as I2C subsystem is enabled
    avark.aa_configure(self.handle, avark.AA_CONFIG_SPI_I2C)
    avark.aa_i2c_pullup(self.handle, avark.AA_I2C_PULLUP_NONE)
    avark.aa_i2c_bitrate(self.handle, I2C_BITRATE)
    avark.aa_i2c_bus_timeout(self.handle, 1000)
    avark.aa_i2c_slave_enable(self.handle, self.device_addr, 0, 0)  # enable slave mode

    self.isRunning = True
    return self.isRunning


  def check_if_mctp_ctrl_req_packet(self, lst):
    """ check if it is mctp control packet over smbus

    :param lst: list of received data bytes by aavark tool
    :return True: if it is MCTP control packet, otherwise, return False

    """
    #print(lst[0], lst[7], lst[8])
    if (int('0x'+lst[0], 16) == 0x0F) and (int('0x'+lst[7], 16) == 0x00) and \
       (int('0x'+lst[8], 16)>>7 == 0x1):
      return True
    else:
      return False

  def check_if_mctp_spdm_packet(self, lst):
    """ check if it is mctp spdm packet over smbus

    :param lst: list of received data bytes by aavark tool
    :return True: if it is MCTP control packet, otherwise, return False

    """

    if (int('0x'+lst[0], 16) == 0x0F) and (int('0x'+lst[7], 16) == 0x05):
      return True
    else:
      return False

  def recv(self):
    """ slave read data from Aardvark tool from BMC MCTP_Brdige SMBus interface

    """
    logger.info('-- recv waiting mctp ctrl pkts over smbus')
    print('-- recv waiting mctp ctrl pkts over smbus ...')
    #print("Waiting for i2c event")
    mctp_data = False
    while (mctp_data == False):
      num_bytes = 0
      data_recv = array('B', [])
      while(num_bytes <= 0):
        pollstatus = avark.aa_async_poll(self.handle, 200)
        while (pollstatus != avark.AA_ASYNC_NO_DATA):
          if pollstatus == avark.AA_ASYNC_I2C_READ:
            #print("Poll status {}".format(pollstatus))
            (num_bytes, addr, data_recv) = avark.aa_i2c_slave_read(self.handle, BUFFER_SIZE)
            bdata=data_recv.tobytes()
            #print("recv bdata:", bdata)
            lst=' '.join(['{:02x}'.format(i) for i in bdata])
            if num_bytes > 0:
              print("num_bytes = {}, addr = 0x{:02X}, -- MCTP_Bridge: data_recv (in hex) = {}".format(num_bytes, addr, lst))
            break
              #lst=lst.split(' ')
              #return [int(x, 16) for x in lst]
          elif pollstatus == avark.AA_ASYNC_I2C_WRITE:
            #print("Poll status {}".format(pollstatus))
            prevWriteStats = avark.aa_i2c_slave_write_stats(self.handle)
            #print("Previous write status fround while receiving {}".format(prevWriteStats))
          pollstatus = avark.aa_async_poll(self.handle, 0) # change poll timeout as 0

      lst=lst.split(' ')
      mctp_data = self.check_if_mctp_ctrl_req_packet(lst) or self.check_if_mctp_spdm_packet(lst)
      #print("mctp_data: {}".format(mctp_data))
    return [int(x, 16) for x in lst]


  def send(self, data_send):
    """
    send data bytes from Aardvark tool

    :param data_send: data send out in bytearray
    :type bytes: bytes, bytearray

    append PEC byte::

      https://crccalc.com/
      In Aardvark: Master - addr 0x70
      SPDM_VERSION message bytes: 0F 0E 0B 00 00 00 C8 05 10 04 00 00 00 01 00 10 14
      Calculate PEC code as: "E0 0F 0E 0B 00 00 00 C8 05 10 04 00 00 00 01 00 10" --> 0x14

      0f', '09', '13', '01', '00', '08', 'c8', '00', '81', '04', '00', '3f'

      response: 0,0,4,0,1,f1,f2,f1,0
      0, *, 4, 0 --> 0,0,4,0,1,f1,f2,f1,0
               0f, <bc:0e>,13,01 00 08 c8 0,0,4,0,1,f1,f2,f1,0 <crc>

    """
    num_bytes = 0
    (err_flag, write_byte_count) = avark.aa_i2c_write_ext(self.handle, self.bmc_slave_addr, avark.AA_I2C_NO_FLAGS, array('B', data_send))
    lst=' '.join(['{:02x}'.format(i) for i in data_send])
    #logger.info('-- err_flag: {}, length = {}, data_send={}'.format(err_flag, write_byte_count, lst))
    #print('-- err_flag: {}, length = {}'.format(err_flag, write_byte_count))
    if (err_flag != avark.AA_I2C_STATUS_OK):
      print("-- Write error {}".format(err_flag))
    else:
      #print('-- Write OK err_flag: {}, length = {}, data_send={}'.format(err_flag, write_byte_count, data_send))
      return
    if (err_flag == avark.AA_I2C_STATUS_ARB_LOST):
      print("Bus arbitration lost. This will cause i2c hang")
      # Method 1. Working
      while (err_flag != avark.AA_I2C_STATUS_OK):
        avark.aa_sleep_ms(10 + randint(1, 10))
        (err_flag, write_byte_count) = avark.aa_i2c_write_ext(self.handle, self.bmc_slave_addr, avark.AA_I2C_NO_FLAGS, array('B', data_send))
        print('-- Write OK err_flag: {}, length = {}'.format(err_flag, write_byte_count))


  def send_recv(self, data_send):
    """ AFM: DeviceAddr=0x02, UUID=0x0001 """
    # INTERVAL_TIMEOUT = 1000
    num_bytes = 0
    data_recv = array('B', [])
    (err_flag, write_byte_count) = avark.aa_i2c_write_ext(self.handle, self.cpld_slave_addr, avark.AA_I2C_NO_FLAGS, array('B', data_send))

    result = avark.aa_async_poll(self.handle, BUS_POLL_TIMEOUT)
    if result == avark.AA_ASYNC_I2C_READ:
      (num_bytes, addr, data_recv) = avark.aa_i2c_slave_read(self.handle, BUFFER_SIZE)

    if num_bytes == 0:
      warnings.warn(UserWarning("i2c: Fail to get any response"))
    logger.info("err_flag = {}, slave_addr = 0x{:02X}, write_byte_count={}, data_send = {}".format(err_flag, \
    self.cpld_slave_addr, write_byte_count, data_send))
    logger.info("num_bytes = {}, dest_addr = 0x{:02X}, data_recv = {}".format(num_bytes, self.device_addr, data_recv))
    return (err_flag, write_byte_count, data_send, data_recv)

  def free(self):
    """ free i2c bus """
    rtn = avark.aa_i2c_free_bus(self.port)
    return rtn

  def close(self):
    """ close Aardvark tool driver """
    self.free()
    rtn = avark.aa_close(self.port)
    if (rtn > 0):
      print("-- aardvark device is closed: {}".format(rtn))
