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

try:
    retcode = subprocess.run(['powershell', '-Command ', './ILO_Port_Check.ps1 ' , args.jsonFile])
    if retcode.returncode != 0:
        printRed("ERROR: Could not complete ILO Port check")
        print (retcode, file=sys.stderr)
        sys.exit(retcode.returncode)
    else:
        printGreen("Completed ILO Port check successfully")
except OSError as e:
    print("Execution failed: Could not complete ILO Port check", e, file=sys.stderr)
    sys.exit(e)

for Server in servers:
    siLO = Server['iloIP']
    sUser = Server['username']
    sPassword = Server['password']
    sidevId = Server['idevId']
    try:
        retcode = subprocess.run(['python','validateServer.py', siLO, sUser, sPassword, sidevId],check=True)
        if retcode.returncode != 0:
           printRed("ERROR: Validate Server " + siLO + " script failed")
           print (retcode, file=sys.stderr)
           sys.exit(retcode.returncode)
        else:
           printGreen("--Validation of iLO of the Server with iLO IP of " + siLO + " successful--")
    except OSError as e:
        print("Execution failed:", e, file=sys.stderr)
        sys.exit(e)

if not nutanix:
    print ("Starting execution of witness tagging")
    try:
        retcode = subprocess.run(['python', 'witness-cmd.py' , args.jsonFile])
        if retcode.returncode != 0:
            printRed("Error in executing witness tagging")
            print (retcode, file=sys.stderr)
            sys.exit(retcode.returncode)
        else:
            printGreen("Witness tagging done successfully on vmk0")

    except OSError as e:
        print("Execution failed:", e, file=sys.stderr)
        sys.exit(e)
#
# Do ESXi checks
# 
print ("Logging into ESXi servers for validation tasks")
try:
    retcode = subprocess.run(['powershell', '-Command ', './checkESXiHosts.ps1 ' , args.jsonFile])
    if retcode.returncode != 0:
        printRed("Error: Validating state of ESXi hosts failed.")
        print (retcode, file=sys.stderr)
        sys.exit(retcode.returncode)
    else:
        printGreen("All ESXi hosts are ready to be added to VMware vCenter")
except OSError as e:
    print("Execution failed:", e, file=sys.stderr)
    sys.exit(e)


#
# Add Servers to Cluster in vCenter
#
print ("Adding Servers to regional VMware vCenter")
try:
    retcode = subprocess.run(['powershell', '-Command', './createVMwareCluster.ps1' , args.jsonFile])
    if retcode.returncode != 0: 
        printRed("ERROR: Could not complete vCenter Import Steps")
        print (retcode, file=sys.stderr)
        sys.exit(retcode.returncode)
    else:
        printGreen("VMware Cluster for store created successfully")
except OSError as e:
    print("Execution failed: Could not add servers to vCenter", e, file=sys.stderr)
    sys.exit(e)

if not nutanix:
    print ("Starting configuration of VMware vSAN storage")
    try:
        retcode = subprocess.run(['python', 'vsan2node.py' , args.jsonFile])
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
# Add Servers to Cluster in vCenter
#
print ("Enabling Vcenter HA")
try:
    retcode = subprocess.run(['powershell', '-Command ', './EnableVcenterHA.ps1 ' , args.jsonFile])
    if retcode.returncode != 0:
        printRed("ERROR: Could not complete vCenter HA")
        print (retcode, file=sys.stderr)
        sys.exit(retcode.returncode)
    else:
        printGreen("Enabled Vcenter HA")
except OSError as e:
    print("Execution failed: Could not Enable vCenter HA", e, file=sys.stderr)
    sys.exit(e)

printGreen("---Zero Touch Provisioning complete for Store" + data['StoreID'] + "---")

exit()
