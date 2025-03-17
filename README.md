# Intel Server PRoT SPDM Python package (intel-server-prot-spdm)

## Description

**intelprot** is a python package for Intel Server Platform Root of Trust (PRoT) 
spdm development. It is used for PRoT design of SPDM based device attestation. 
This package is useful for both Intel PFR based PRoT and non-Intel PFR based PRoT system.

Intel® Platform Firmware Resilience (Intel® PFR) is a hardware-based
cybersecurity solution for platform firmware resilience. It is Intel PRoT solution. About Intel®
PFR: <https://www.intel.com/pfr>.

This package has been used for SPDM based device attestation using SMBus tool (Aardvark) on Intel reference platform with
open source project [spdm-emu](https://github.com/DMTF/spdm-emu).

The package covers for Eaglestream, Birchstream platform, and Idaville, Kaseyville platforms.

The tool package includes scripts to build Intel PRoT (PFR) compliant firmware and capsules for device attestation using DMTF SPDM_Emu open source project. 

Modules included in this package:

-   aardvark (need install its driver/api)
-   bmc
-   capsule
-   cpld
-   keys
-   mctp_spdm
-   pfm
-   sign
-   spdm
-   testprot
-   utility
-   verify

sphinx module generated html documentation is included in
*docs/html/index.html*.

## Installing

Download the wheel file and install it in your system.

``` console
pip install intelprot-x.x.x-py3-none-any.whl
```

## Requirements

This package requires Python 3.7 or above version. Dependencies modules:

1.  ecdsa
2.  crccheck
3.  tabulate
4.  ipmitool
5.  ecdsa
6.  requests
7.  aardvark_py

## Usage

Modules inside package can be imported in customer scripts, or run standalone in
Python console or Command Prompt.

``` python
>>>from intelprot import <module-name>
```

Run in command propmt/terminal:

    >python -m intelprot.<module-name> -h

Modules that have command line interface include : **bmc, capsule, cpld,
ifwi, sign, testprot, utility, verify**.

Please report issue or send email to admin if you observe any issue or
have new request that you want to assist your Intel PFR (PRoT) project. 
Note that this package is still work in progress for Birch Stream paltform. It has beed used for Eagle Stream platform. 

## Documentation

The documentation is available at ../docs/html/index.html

## Copyright and License

Copyright (c) 2023 Intel Corporation

Licensed under the Apache License, Version 2.0 (the \"License\"); you
may not use this file except in compliance with the License. You may
obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an \"AS IS\" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Refer Max10 FPGA source code release for FPGA soure code license.
