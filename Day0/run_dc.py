#!/usr/bin/python
import json
import argparse
import subprocess
import sys
from log_file_gen import *

parser = argparse.ArgumentParser()

parser.add_argument('jsonFile')
args = parser.parse_args()


with open(args.jsonFile) as datafile:
    data = json.load(datafile)


servers = data['Servers']
vCenter = data['vCenter']
Ded_ID=data["DEDID"]
store_id="ST "+data["StoreID"]
d={"Ded_ID":Ded_ID,"store_id":store_id}


logger.info("Witness VM deployment using OVA file",extra=d)

try:
    task="Witness VM deployment using OVA file"
    logger.info(task_start(task),extra=d)
    retcode = subprocess.run(['powershell', '-Command ', './lockmakerdeployment-2210.ps1 ' , args.jsonFile])
    if retcode.returncode != 0:
        logger.error("Error: Deployement failed ",extra=d)
        logger.info(retcode, file=sys.stderr,extra=d)
        logger.info(task_result(task,"Error: witness VM Deployement failed"),extra=d)
        sys.exit(retcode.returncode)
    else:
        logger.debug("Witness VM deployment success",extra=d)
        logger.info(task_result(task,"SUCCESS"),extra=d)
except OSError as e:
    logger.exception("Execution failed:", e, file=sys.stderr,extra=d)
    logger.info(task_result(task,e),extra=d)
    sys.exit(e)
