from pyVim.connect import SmartConnect,Disconnect
from pyVmomi import vim
import argparse
import atexit
import json
import os
import ssl
import sys


# Get the json file from the argument pass and set it up to be used
parser = argparse.ArgumentParser()
parser.add_argument('jsonFile')
args = parser.parse_args()

with open(args.jsonFile) as datafile:
    data = json.load(datafile)
    
esxis = data['Servers']

if sys.version_info[:3] > (2, 7, 8):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

# Connect to the ESXi host using the vSphere API

def check_nic_status(host, user, password):
    # Connect to the ESXi host
    try:
        print('Connecting to the host:', host)
        si = SmartConnect(host=host, user=user, pwd=password,port=int(443),sslContext=context)
    except vim.fault.InvalidLogin:
        raise SystemExit("Invalid username or password. Please check credentials for vCenter")
    except Exception as e:
        raise SystemExit("Hit an error: %s" %e)

    # Get the host system object
    host_system = si.content.rootFolder.childEntity[0].hostFolder.childEntity[0].host[0]

    # Get the network adapter information
    nics = host_system.config.network.pnic

    # Check the status of each NIC
    for nic in nics:
        print(f'NIC {nic.device} is {"up" if nic.linkSpeed else "down"}')

    # Disconnect from the ESXi host
    Disconnect(si)

if __name__ == '__main__':
    for esxi in esxis:
        host = esxi['mgmtIP']
        user = 'root'
        password = esxi['osPassword']
        check_nic_status(host, user, password)
