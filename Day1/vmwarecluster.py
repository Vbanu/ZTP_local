from pyVim import connect
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from termcolor import cprint
import argparse
import atexit
import json
import os
import ssl
import sys
import time

#
# Get the json file from the argument pass and set it up to be used
#
parser = argparse.ArgumentParser()
parser.add_argument('jsonFile')

args = parser.parse_args()

with open(args.jsonFile) as datafile:
    data = json.load(datafile)
    
vCenter = data['vCenter']
esxis = data['Servers']
# Ignore SSL certificate verification errors
if sys.version_info[:3] > (2, 7, 8):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE


# Datacenter and cluster names
datacenter_name = vCenter['DCName']
cluster_name = vCenter['clusterName']

# Connect to vCenter
si = connect.SmartConnect(
    host=vCenter['IP']  ,
    user=vCenter['username']  ,
    pwd=vCenter['password']  ,
    port=int(443) ,
    sslContext=context )

# Get root folder
root_folder = si.content.rootFolder

# Check if datacenter exists, create it if not
datacenter = None
for dc in root_folder.childEntity:
    if dc.name == datacenter_name:
        datacenter = dc
        print('datacenter already exists')
        break

if not datacenter:
    print('Creating datacenter:',datacenter_name)
    datacenter = root_folder.CreateDatacenter(name=datacenter_name)

# Check if cluster exists, create it if not
cluster = None
for c in datacenter.hostFolder.childEntity:
    if isinstance(c, vim.ClusterComputeResource) and c.name == cluster_name:
        cluster = c
        print('Cluster already exists')
        break

if not cluster:
    print('creating cluster:',cluster_name)
    #rp = datacenter.hostFolder.CreateResourcePool("Resources")
    cluster_spec = vim.cluster.ConfigSpecEx()
    #cluster_spec.dasConfig = vim.cluster.DasConfigInfo()
    #cluster_spec.dasConfig.enabled = True
    cluster = datacenter.hostFolder.CreateClusterEx(name=cluster_name, spec=cluster_spec)

# Add the hosts to the cluster
for esxi in esxis:
    host = esxi['mgmtIP']
    print(host)
    password = esxi['osPassword']
    host_connect_spec = vim.host.ConnectSpec(hostName=host, userName='root', password=password, force=True)
    try:
        host_system = cluster.AddHost(spec=host_connect_spec, asConnected=True)
        print(f"Host {host} added to cluster {cluster_name}")
    except vim.fault.AlreadyExists:
        print(f"Host {host} already exists in cluster {cluster_name}")
    except Exception as e:
        print(f"Error adding host {host} to cluster {cluster_name}: {e}")

print('Waiting 5 seconds for the hosts to get reflected in vCenter')
time.sleep(10)
# Get host system
search = si.content.searchIndex
# Find out host from vCenter using IP address or hostname
for esxi in esxis:
    esxi_host = search.FindByIp(ip = esxi['mgmtIP'], vmSearch=False)

    if esxi_host is None:
        print("Host not found with specified DNS name")
    else:
        # Check if host is in maintenance mode
        if esxi_host.runtime.inMaintenanceMode:
            # Exit maintenance mode
            print("Exiting maintenance mode for host {}".format(esxi_host.name))
            task = esxi_host.ExitMaintenanceMode_Task(5)
            while task.info.state == vim.TaskInfo.State.running:
                continue
            print("Host {} is now out of maintenance mode".format(esxi_host.name))
        else:
            print("Host {} is not in maintenance mode".format(esxi_host.name))

# Disconnect from vCenter
Disconnect(si)
