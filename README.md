# Intel Server PRoT SPDM Python package (intel-server-prot-spdm)

## Description

**intel-server-prot-spdm** is a python package for Intel Server Platform Root of Trust (PRoT) 
spdm development . It is used for image build, capsule generation and device attestation 
for both Intel PFR based PRoT and non-Intel PFR based PRoT designs.

The tool package includes scripts to build Intel® PFR compliant firmware, update
capsule, Attestation Firmware Manifest generation for attestation using SPDM emulation. 

This Python package is released to assist Intel® PFR project in Whitley, Idaville and Eaglestream server,
and Bitch Stream plaforms. For Birch stream platform, it is useful for both Intel PFR based PRoT 
and non-Intel PFR PRoT design.

This tool package also includes scripts that are needed for SPDM based
device attestation using SMBus tool on Intel® Eaglestream platform with
open source project [spdm-emu](https://github.com/DMTF/spdm-emu).

Intel® Platform Firmware Resilience (Intel® PFR) is a hardware-based
cybersecurity solution for platform firmware resilience. About Intel®
PFR: <https://www.intel.com/pfr>. Intel® PFR Whitley Max10 FPGA source code is [released in
GitHub](https://github.com/intel/platform-firmware-resiliency%3E).

Modules included in this package:

-   aardvark (driver and api)
-   bmc
-   capsule
-   cpld
-   ifwi
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

This package requires Python 3.6 or above version. Dependencies modules:

1.  python-ecdsa: pip install ecsda
2.  crccheck: pip install crccheck
3.  python-tabulate: pip install tabulate
4.  ipmitool

## Usage

Modules inside package can be included in scripts, run standalone in
Python console or command lines.

``` python
>>>from intelprot import <module-name>
```

Run in command propmt/terminal:

    >python -m intelprot.<module-name> -h

Modules that have command line interface include : **bmc, capsule, cpld,
ifwi, sign, testprot, utility, verify**.

Please report issue or send email to admin if you observe any issue or
have new request that you want to assist your Intel PFR project. Author
will update the related modules quickly.

## Documentation

The documentation is available at ../docs/html/index.html

## Copyright and License

Copyright (c) 2022 Intel Corporation

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
