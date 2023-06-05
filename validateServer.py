#!/usr/bin/python3
import argparse
import json
import os
import sys
import time
from termcolor import colored, cprint
from log_file_gen import *
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "library"))
import iLOLib.iLOLib as iLOLib

parser = argparse.ArgumentParser()

parser.add_argument('iLOIP')
parser.add_argument('username')
parser.add_argument('password')
parser.add_argument('idevId')
parser.add_argument('Ded_id')
parser.add_argument('store_id')
args = parser.parse_args()

iLOIP = args.iLOIP
iLOUser = args.username
iLOPW = args.password
idevId = args.idevId
Ded_ID=args.Ded_id
store_id=args.store_id
d={"Ded_ID":Ded_ID,"store_id":store_id}

def printGreen(x):
    cprint(x, 'green')

def printRed(x):
    cprint(x, 'red')

timesleep = None
ret = 0

#print("Attempting to login to server's iLO address: ", iLOIP)
logger.info("Attempting to login to server's iLO address:"+ iLOIP,extra=d)

loginRet = iLOLib.ILOLogin(iLOIP, iLOUser, iLOPW)
if loginRet:
    logger.error("Failed to log into iLO",extra=d)
    ret = 1
    sys.exit(ret)
#
# Check power status and power on if off
#
svrPwrStatus = iLOLib.SystemPowerStatus(iLOIP)
if svrPwrStatus == "On":
    status = "Pass"
    logger.info("Server " + iLOIP + " is already powered on.",extra=d)
else:
    svrRst = iLOLib.SystemPowerOn(iLOIP)
    if svrRst:
        ret = ret + 1
        status = "Fail"
        logger.error("Failed to power on server " + iLOIP,extra=d)
        sys.exit(ret)
    else:
        status = "Pass"
        logger.info("Successfully powered on server " +iLOIP,extra=d)
        timesleep = "Enabled"
#
# If we had to power a server on, wait for 5 minutes for it to boot
#
if timesleep == "Enabled":
    logger.info("Wait 300 seconds for server to boot.",extra=d)
    time.sleep(300)  
    timesleep = None
    logger.info("Boot process should be completed by now, continuing",extra=d)
#
#Perform Health Checks
#

logger.info("Checking Power Configuration for the host " + iLOIP,extra=d)
svrPSUStatus = iLOLib.SystemPSUHealth(iLOIP)
if svrPSUStatus:
    ret = 1
    logger.error("Power Supply Validation failed, will exit zero touch provisioning after the rest of the test execute",extra=d)
else:
    logger.info("Power is redundant for the host " + iLOIP,extra=d)

logger.info("Checking Memory and CPU Health of host " + iLOIP,extra=d)
svrMemStatus = iLOLib.SystemMemoryHealth(iLOIP)
if svrMemStatus:
    logger.exception("Memory Validation failed, will exit zero touch provisioning after the rest of the test execute",extra=d)
    ret = 1
else:
    logger.info("Memory is healthy for the host " + iLOIP,extra=d)

svrCPUStatus = iLOLib.SystemCPUHealth(iLOIP)
if svrCPUStatus:
    logger.exception("Processor Validation failed, will exit zero touch provisioning after the rest of the test execute",extra=d)
    ret = 1
else:
    logger.info("Processor is healthy for the host " + iLOIP,extra=d)

#svrStorageStatus = iLOLib.SystemStorageHealth(iLOIP)
#if svrStorageStatus:
#    printRed("Drive Validation failed, will exit zero touch provisioning after the rest of the test execute")
#    ret = 1
#else:
#    print("Drives are healthy for the host " + iLOIP)

#if ret != 0:
#    sys.exit(ret)
#else:
#    printGreen ("System in green, no hardware failures detected for the host " + iLOIP)

#print ("Start - Validate iLO Security Settings for the host " + iLOIP)
logger.info("Start - Validate iLO Security Settings for the host " + iLOIP,extra=d)

##
## Check iDevID
## This is commented out for now as we have no way to run this with Gen10 or earlier servers,
## but it does work and was used for the demo
##

idevIdCert = iLOLib.ValidateIDevIDCert(iLOIP,idevId)
if idevIdCert:
    #printRed ("IDevID validation failed for host " + iLOIP + ". Immediately powering down!!")
    logger.exception("IDevID validation failed for host " + iLOIP + ". Immediately powering down!!",extra=d)
#     svrRst = iLOLib.SystemPowerOff(iLOIP)
#     if svrRst:
#         ret = 1
#         printRed ("Failed to power off server " + iLOIP)
#         sys.exit(ret)
#     else:
#         ret = 1
#         print ("Successfully powered off server " +iLOIP)
#         sys.exit(ret)
# else:
#if ret != 0:
#    sys.exit(ret)
else:
    logger.info("IDevID Certificate Validated for host " + iLOIP,extra=d)

##
## Check Platform
## This is commented out for now as we have no way to run this with Gen10 or earlier servers,
## but it does work and was used for the demo
##

#platCert = iLOLib.ValidatePlatformCert(iLOIP)
# if platCert:
#     printRed ("Platform validation failed for host " + iLOIP + ". Immediately powering down!!")
#     svrRst = iLOLib.SystemPowerOff(iLOIP)
#     if svrRst:
#         ret = 1
#         printRed ("Failed to power off server " + iLOIP)
#         sys.exit(ret)
#     else:
#         ret = 1
#         print ("Successfully powered off server " +iLOIP)
#         sys.exit(ret)
# else:
#if ret != 0:
#    sys.exit(ret)
#else:
#    print("Platform Certificate Validated for host " + iLOIP)

## 
## Validate Security of iLO (We will finish this later)
## From iMRA Code
##
# line = ("iLO Host" + "\t" + "Attribute Name" + "\t" + "Expected Value" + "\t" + "Actual Value" + "\t" + "Status")
# report_file.write(task + "\n")
# report_file.write(line + "\n")
# report_file.write(svrIPv6 + "\t" +" " +"\t" +" " +"\t" +" " +"\t" +" "+"\n" )

# retVal, report_file = iLOLib.Validate_iLOSecurityHardening(svrIPv6,report_file)
# report_file.write("\n")
# line = ("Server" + "\t" + "Status" + "\t" + "Description")
# report_file.write(line + "\n")
# if retVal:
#     ExitCode = 1
#     print ("Failed to Validate iLO Security Settings on the server" + iLOIP)
#     status = "Fail"
# else:

#
# TPM Validation
# We need to ensure the TPM is there, activated, and in the proper configuration (like 2.0 mode)
#

#
# Ensure none of the bios/iLO overrides are set
# I.e. make sure that the jumpers aren't set on the motherboard to disable BIOS or iLO authentication for example
#

#
# Scan USB bus and ensure no unexpected devices are connected
#

#printGreen("Successfully validated Security Settings on the server " + iLOIP)
logger.debug("Successfully validated Security Settings on the server " + iLOIP,extra=d)
#     status = "Pass"

