from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

# Connect to vCenter Server
vcenter_host = "10.10.103.111"
username = "root"
password = "HP1nvent!"
try:
    si = SmartConnect(host=vcenter_host, user=username, pwd=password)
    
    esxi_hosts = si.content.rootFolder.childEntity[0].hostFolder.childEntity
    virtual_switch_name = "Vmnetwork_test"
    portgroup_name = "test_portgroup"

    for esxi_host in esxi_hosts:
        vswitches = esxi_host.config.network.vswitch
        for vswitch in vswitches:
            if vswitch.name == virtual_switch_name:
                spec = vim.host.PortGroup.Specification()
                spec.name = portgroup_name
                spec.vswitchName = vswitch.name
                spec.policy = vim.host.NetworkPolicy()
                spec.policy.nicTeaming = vim.host.NetworkPolicy.NicTeamingPolicy()
                spec.policy.nicTeaming.policy = "loadbalance_ip"
                spec.policy.nicTeaming.reversePolicy = False
                spec.policy.security = vim.host.NetworkPolicy.SecurityPolicy()
                spec.policy.security.allowPromiscuous = False
                spec.policy.security.forgedTransmits = False
                spec.policy.security.macChanges = False
                try:
                    esxi_host.configManager.networkSystem.AddPortGroup(spec)
                    print("Port group created successfully on", esxi_host.name)
                except Exception as e:
                    print("Error creating port group on", esxi_host.name, ":", str(e))


except Exception as e:
    print("Error connecting to vCenter Server:", str(e))

