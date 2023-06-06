#!/usr/bin/python
import json
import argparse
import subprocess
import sys
from termcolor import cprint

parser = argparse.ArgumentParser()

parser.add_argument('jsonFile')
args = parser.parse_args()

with open(args.jsonFile) as datafile:
    data = json.load(datafile)

def printGreen(x):
    cprint(x, 'green')

def printRed(x):
    cprint(x, 'red')

nutanix = False

#
# Execute iLO ZTP Script
# 
servers = data['Servers']
vCenter = data['vCenter']

#
# Port Validation for ILO's
#
print ("Checking ILO Connectivity & Port Validation ")
try:
    retcode = subprocess.run(['powershell', '-Command ', './ILO_Port_Check-3Node.ps1 ', args.jsonFile])
    if retcode.returncode != 0:
        printRed("Error: Validating Ports & ILO Connectivity failed.")
        print (retcode, file=sys.stderr)
        #sys.exit(retcode.returncode)
    else:
        printGreen("Network Connectivity for ILO Looks to be good")
except OSError as e:
    print("Execution failed:", e, file=sys.stderr)
    #sys.exit(e)

#
# Validation of Memory, CPU, Power Supplies 
#
for Server in servers:
    siLO = Server['iloIP']
    sUser = Server['username']
    sPassword = Server['password']
    sidevId = Server['idevId']
    try:
        #retcode = subprocess.run(['python validateServer.py ' + siLO + ' ' + sUser + ' ' + sPassword])
        retcode = subprocess.run(['python','validateServer.py', siLO, sUser, sPassword, sidevId],check=True)
        if retcode.returncode != 0:
           printRed("ERROR: Validate Server " + siLO + " script failed")
           print (retcode, file=sys.stderr)
           sys.exit(retcode.returncode)
        else:
           #print("Validate Server " + siLO + " returned", retcode, file=sys.stderr)
           printGreen("--Validation of iLO of the Server with iLO IP of " + siLO + " successful--")
    except OSError as e:
        print("Execution failed:", e, file=sys.stderr)
        sys.exit(e)

#
# Do ESXi checks
# 
print ("Logging into ESXi servers for validation tasks")
try:
    retcode = subprocess.run(['python', 'esxi-nic-validation.py' , args.jsonFile])
    if retcode.returncode != 0:
        printRed("NIC Checks failed.. Please correct it and proceed with ZTP")
        print (retcode, file=sys.stderr)
        sys.exit(retcode.returncode)
    else:
        printGreen("Validated NIC's for esxi hosts")
except OSError as e:
    print("ESXI NIC check failed:", e, file=sys.stderr)
    sys.exit(e)

#
# Add Servers to Cluster in vCenter
#
print ("Adding Servers to regional VMware vCenter")
try:
    retcode = subprocess.run(['python', 'vmwarecluster.py' , args.jsonFile])
    if retcode.returncode != 0:
        printRed("Error: Creation of the VMware Cluster failed.")
        print (retcode, file=sys.stderr)
        sys.exit(retcode.returncode)
    else:
        printGreen("VMware Cluster successfully created.")
except OSError as e:
    print("Execution failed:", e, file=sys.stderr)
    sys.exit(e)

#
# Configure VMWARE vSAN Storage
#
if not nutanix:
    print ("Starting configuration of VMware vSAN storage")
    try:
        #retcode = subprocess.run("python createvSAN.py " + args.jsonFile)
        retcode = subprocess.run(['python', 'createvSAN.py' , args.jsonFile])
        if retcode.returncode != 0:
            printRed("Error: Creation of the VMware vSAN Storage Cluster failed.")
            print (retcode, file=sys.stderr)
            sys.exit(retcode.returncode)
        else:
            printGreen("VMware vSAN Storage Cluster successfully created.")
    except OSError as e:
        print("Execution failed:", e, file=sys.stderr)
        sys.exit(e)

#
# Enable vSphere HA
#
print ("Enabling Vcenter HA")
try:
    retcode = subprocess.run(['python', 'vsphere-HA.py' , args.jsonFile])
    if retcode.returncode != 0:
        printRed("Failed to Enable vsphere HA. Please check the cluster on vCenter")
        print (retcode, file=sys.stderr)
        sys.exit(retcode.returncode)
    else:
        printGreen("Enabled vsphere HA")
except OSError as e:
    print("Could n't enable vsphere HA:", e, file=sys.stderr)
    sys.exit(e)

printGreen("---Zero Touch Provisioning complete for Store" + data['StoreID'] + "---")

exit()
