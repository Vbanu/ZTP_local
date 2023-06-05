import argparse
import paramiko
import json
import os
import ssl
import sys
from termcolor import cprint
from log_file_gen import *
#
# Get the json file from the argument pass and set it up to be used
#
parser = argparse.ArgumentParser()
parser.add_argument('jsonFile')
parser.add_argument('--debug', 
                    default=False)
					
args = parser.parse_args()
debug = args.debug
with open(args.jsonFile) as datafile:
    data = json.load(datafile)
esxis = data['Servers']
Ded_ID=data["DEDID"]
store_id="ST "+data["StoreID"]


d={"Ded_ID":Ded_ID,"store_id":store_id}
	
for esxi in esxis:
    try:
        mgmtIP = esxi['mgmtIP']
        ESXIUser = esxi['username']
       	OSPW = esxi['osPassword']
        # create an SSH client object
        ssh = paramiko.SSHClient()
 	# automatically add the host key
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # connect to the remote host
        #print('executing witness command on node'+mgmtIP)
        logger.info('executing witness command on node'+mgmtIP,extra=d)
        ssh.connect(hostname=mgmtIP, username='root', password=OSPW)
	# execute the command on the remote host
        stdin, stdout, stderr = ssh.exec_command('esxcli vsan network ip add -i vmk0 -T=witness')
        # print the output
        #print(stdout.read().decode())
        logger.info(stdout.read().decode(),extra=d)
	# close the SSH connection
        ssh.close()
        del stdin, stdout, stderr
    except OSError as e:
        #print("Execution failed:", e, file=sys.stderr)
        logger.exception("Execution failed:", e, file=sys.stderr)
        sys.exit(e)


