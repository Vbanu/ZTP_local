from pyVim.connect import SmartConnect,Disconnect
from pyVmomi import vim, VmomiSupport
import sys
import ssl
import time
import argparse
import json

parser = argparse.ArgumentParser()

parser.add_argument('jsonFile')
args = parser.parse_args()

with open(args.jsonFile) as datafile:
    data = json.load(datafile)
	
vCenter = data['vCenter']

if sys.version_info[:3] > (2, 7, 8):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

# Set the ESXi host connection details
host = vCenter['IP']
user = vCenter['username']
password = vCenter['password']

# Connect to the ESXi host using the vSphere API
try:
    si = SmartConnect(host=host, user=user, pwd=password,port=int(443),sslContext=context)
except vim.fault.InvalidLogin:
    raise SystemExit("Invalid username or password. Please check credentials for vCenter")
except Exception as e:
    print("Hit an error: %s" %e)

# Get the vSphere Datacenter object
datacenter_name = vCenter['DCName']
content = si.RetrieveContent()
datacenter = None
for obj in content.rootFolder.childEntity:
    if obj.name == datacenter_name and isinstance(obj, vim.Datacenter):
        datacenter = obj
        break
if not datacenter:
    raise ValueError(f"Datacenter '{datacenter_name}' not found")

# Get the vSphere Cluster object
cluster_name = vCenter['clusterName']
cluster = None
for obj in datacenter.hostFolder.childEntity:
    if obj.name == cluster_name and isinstance(obj, vim.ClusterComputeResource):
        cluster = obj
        break
if not cluster:
    raise ValueError(f"Cluster '{cluster_name}' not found in datacenter '{datacenter_name}'")

# Enable vSphere HA on the cluster
cluster_spec = vim.cluster.ConfigSpecEx()
cluster_spec.dasConfig = vim.cluster.DasConfigInfo(enabled=True)
task = cluster.ReconfigureComputeResource_Task(cluster_spec, modify=True)
# Wait for the task to complete
while task.info.state == vim.TaskInfo.State.running:
    time.sleep(1)

if task.info.state == vim.TaskInfo.State.success:
    print(f"vSphere HA enabled on cluster '{cluster_name}'")
else:
    print(f"Failed to enable vSphere HA on cluster '{cluster_name}'")

Disconnect(si)
