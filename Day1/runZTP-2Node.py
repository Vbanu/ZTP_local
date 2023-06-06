#!/usr/bin/python
import json
import argparse
import subprocess
import sys
from termcolor import cprint
from log_file_gen import *

#print(Ded_ID,store_id)

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
Ded_ID=data["DEDID"]
store_id="ST "+data["StoreID"]
d={"Ded_ID":Ded_ID,"store_id":store_id}

try:
    task="ILO_Port_Check"
    logger.info(task_start(task),extra=d)
    retcode = subprocess.run(['powershell', '-Command ', './ILO_Port_Check-2Node.ps1 ' , args.jsonFile])
    if retcode.returncode != 0:
        logger.error("ERROR: Could not complete ILO Port check",extra=d)
        logger.info(retcode, file=sys.stderr)
        sys.exit(retcode.returncode)
        logger.info(task_result(task,sys.stderr))
        
    else:
        logger.debug("Completed ILO Port check successfully ",extra=d)
        logger.info(task_result(task,"SUCCESS"),extra=d)
        
except OSError as e:
    logger.exception("Execution failed: Could not complete ILO Port check", e, file=sys.stderr,extra=d)
    logger.info(task_result(task,e),extra=d)
    
    
    sys.exit(e)


for Server in servers:
    siLO = Server['iloIP']
    sUser = Server['username']
    sPassword = Server['password']
    sidevId = Server['idevId']
    try:
        task="Validation of iLO of the Server with iLO IP"
        logger.info(task_start(task),extra=d)
        retcode = subprocess.run(['python','validateServer.py', siLO, sUser, sPassword, sidevId, Ded_ID, store_id],check=True)
        if retcode.returncode != 0:
           #printRed("ERROR: Validate Server " + siLO + " script failed")
           logger.error("ERROR: Validate Server " + siLO + " script failed ",extra=d)
           #print (retcode, file=sys.stderr)
           logger.info(retcode, file=sys.stderr,extra=d)
           logger.info(task_result(task,"ERROR: Validate Server " + siLO + " script failed"),extra=d)
           sys.exit(retcode.returncode)
           
        else:
           #printGreen("--Validation of iLO of the Server with iLO IP of " + siLO + " successful--")
           logger.debug("--Validation of iLO of the Server with iLO IP of " + siLO + " successful--",extra=d)
           logger.info(task_result(task,"SUCCESS"),extra=d)
    except OSError as e:
        #print("Execution failed:", e, file=sys.stderr)
        logger.exception("Execution failed:", e, file=sys.stderr,extra=d)
        logger.info(task_result(task,e),extra=d)
        sys.exit(e)


if not nutanix:
    #print ("Starting execution of witness tagging")
    logger.info("Starting execution of witness tagging",extra=d)
    
    try:
        task="witness tagging"
        logger.info(task_start(task),extra=d)
        retcode = subprocess.run(['python', 'witness-cmd.py' , args.jsonFile])
        if retcode.returncode != 0:
            logger.error("Error in executing witness tagging ",extra=d)
            logger.info(retcode, file=sys.stderr)
            logger.info(task_result(task,"Error in executing witness tagging"),extra=d)
            sys.exit(retcode.returncode)
        else:
            #printGreen("Witness tagging done successfully on vmk0")
            logger.debug("Witness tagging done successfully on vmk0 ",extra=d)
            logger.info(task_result(task,"SUCCESS"),extra=d)

    except OSError as e:
        logger.exception("Execution failed:", e, file=sys.stderr,extra=d)
        logger.info(task_result(task,e),extra=d)
        sys.exit(e)
#
# Do ESXi checks
# 
#print ("Logging into ESXi servers for validation tasks")
logger.info("Logging into ESXi servers for validation tasks",extra=d)

try:
    task="ESXi servers validation"
    logger.info(task_start(task),extra=d)
    retcode = subprocess.run(['powershell', '-Command ', './checkESXiHosts.ps1 ' , args.jsonFile])
    if retcode.returncode != 0:
        logger.error("Error: Validating state of ESXi hosts failed ",extra=d)
        logger.info(retcode, file=sys.stderr,extra=d)
        logger.info(task_result(task,"Error: Validating state of ESXi hosts failed"),extra=d)
        sys.exit(retcode.returncode)
    else:
        logger.debug("All ESXi hosts are ready to be added to VMware vCenter",extra=d)
        logger.info(task_result(task,"SUCCESS"),extra=d)
except OSError as e:
    logger.exception("Execution failed:", e, file=sys.stderr,extra=d)
    logger.info(task_result(task,e),extra=d)
    sys.exit(e)


#
# Add Servers to Cluster in vCenter
#
#print ("Adding Servers to regional VMware vCenter")
logger.info("Adding Servers to regional VMware vCenter",extra=d)

try:
    task="Adding Servers to regional VMware vCenter"
    logger.info(task_start(task),extra=d)
    retcode = subprocess.run(['powershell', '-Command', './createVMwareCluster.ps1' , args.jsonFile])
    if retcode.returncode != 0: 
        logger.error("ERROR: Could not complete vCenter Import Steps ",extra=d)
        logger.info(retcode, file=sys.stderr,extra=d)
        logger.info(task_result(task,"ERROR: Could not complete vCenter Import Steps"),extra=d)
        sys.exit(retcode.returncode)
    else:
        logger.debug("VMware Cluster for store created successfully ",extra=d)
        logger.info(task_result(task,"SUCCESS"),extra=d)
except OSError as e:
    logger.exception("Execution failed: Could not add servers to vCenter", e, file=sys.stderr,extra=d)
    logger.info(task_result(task,e),extra=d)
    sys.exit(e)


if not nutanix:
    logger.info("Starting configuration of VMware vSAN storage",extra=d)
    
    try:
        task="Starting configuration of VMware vSAN storage"
        logger.info(task_start(task),extra=d)
        retcode = subprocess.run(['python', 'vsan2node.py' , args.jsonFile])
        if retcode.returncode != 0:
            logger.error("Error: Creation of the VMware vSAN Storage Cluster failed",extra=d)
            logger.info(retcode, file=sys.stderr,extra=d)
            logger.info(task_result(task,"Error: Creation of the VMware vSAN Storage Cluster failed"),extra=d)
            sys.exit(retcode.returncode)
        else:
            #printGreen("VMware vSAN Storage Cluster successfully created.")
            logger.debug("VMware vSAN Storage Cluster successfully created - ",extra=d)
            task_result(task,"SUCCESS")
    except OSError as e:
        logger.exception("Execution failed:", e, file=sys.stderr,extra=d)
        logger.info(task_result(task,e),extra=d)
        sys.exit(e)

#
# Add Servers to Cluster in vCenter
#
#print ("Enabling Vcenter HA")
logger.info("Enabling Vcenter HA",extra=d)

try:
    task="Enabling Vcenter HA"
    logger.info(task_start(task),extra=d)
    retcode = subprocess.run(['powershell', '-Command ', './EnableVcenterHA.ps1 ' , args.jsonFile])
    if retcode.returncode != 0:
        logger.error("ERROR: Could not complete vCenter HA",extra=d)
        logger.info(retcode, file=sys.stderr,extra=d)
        logger.info(task_result(task,"ERROR: Could not complete vCenter HA"),extra=d)
        sys.exit(retcode.returncode)
    else:
        logger.debug("Enabled Vcenter HA ",extra=d)
        logger.info(task_result(task,"SUCCESS"),extra=d)
except OSError as e:
    logger.exception("Execution failed: Could not Enable vCenter HA", e, file=sys.stderr,extra=d)
    logger.info(task_result(task,e),extra=d)
    sys.exit(e)


logger.debug("---Zero Touch Provisioning complete for Store",extra=d )
task=""
exit()
