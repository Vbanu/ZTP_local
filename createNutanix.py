import logging
import os
import platform
import re
import select
import subprocess
import time

import paramiko
import requests
import json
import argparse
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from termcolor import colored, cprint

parser = argparse.ArgumentParser()

parser.add_argument('jsonFile')
args = parser.parse_args()

with open(args.jsonFile) as datafile:
    data = json.load(datafile)

def printGreen(x):
    cprint(x, 'green')

def printRed(x):
    cprint(x, 'red')

# Create the log file and setup python logging.
log_filename = "log/cluster-setup.log"
os.makedirs(os.path.dirname(log_filename), exist_ok=True)

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )

#This script is to be run once the following (sample) cluster create script has been executed
#cluster -s 192.168.0.137,192.168.0.138,192.168.0.139 --cluster_external_ip 192.168.0.140 --cluster_name hou-clus2 --dns_servers 192.68.0.1 --ntp_servers ntp.hpecorp.net create

#BEGIN User Defined Variables
# Make sure to change these variables to match your environment!
# Desired Cluster name (Only applies if cluster is Unnamed!)
# This is important as the default storage pool and container will be renamed/recreated based on the cluster name
# This is the STORE in format st####
vCenter = data['vCenter']
prism = data['Prism']
cvm = data['CVMs']

clustername = vCenter['clusterName']    # Unique Home Depot Store Number
CIP = prism['clusterIP']                # Prism Element VIP - Defined in Cluster Create Script
user = prism['peUsername']                # Default user account for Prism Element
defpasswd = "Nutanix/4u"                # defpasswd = "nutanix/4u"
passwd = prism['pePassword']            # Desired new password for Prism Element Cluster
VCSAIP = vCenter['IP']                  # VCSA IP Address
VCSAuser = vCenter['username']          # VCSA Username
VCSApwd = vCenter['password']           # VCSA Password - I DO NOT KNOW THIS PW
username = "The Home Depot"             # EULA info
companyName = "The Home Depot"          # EULA info
jobTitle = "The Home Depot"             # EULA info
PCIP = prism['pcIP']	                # Prism Central IP - This will be centrally hosted by The Home Depot, not in a store
PCuser = prism['pcUsername']		    # Prism Central User with rights to register clusters
PCpw = prism['pcPassword']               # Prism Central password for "admin" account
bannermsg = "Welcome to The Home Depot Store Cloud Platform.  This is the MTC Lab representing Store " + clustername # Welcome Message for Prism Element
scs=[clustername + "smvsa01",clustername + "smvsa02",clustername + "_backup",clustername + "_local"] # Datastore Creation variables - creates 4 datastores

##########################################################
#Unused Variables for Stores - leave for future reference#
##########################################################
DNS1 = "192.68.0.1"
DNS2 = "8.8.8.8"
NTP1 = "ntp.hpecorp.net"
NTP2 = "time.google.com"
SMTPADD = "mail.homedepot.com"	    # SMTP Address DNS name
SMTPDOM = "homedepot.com"	    # mail domain name; do not include the @ sign, just everything after it.
SMTPPORT = 25
proxyaddress = "proxy.company.com"
proxyname = "proxy"		    # Please note that proxy-types are hard coded below as HTTP and HTTPS
proxyport = 7070
directory_url = "ldaps://ucs.sat22.lan:636" #authconfig directory settings
#directory_url = "ldap://dc.company.local:389"   # not using secure ldap?
domain = "sat22.lan"
group_search_type = "NON_RECURSIVE"
dirname = "sat22"
diruser = "otto@sat22.lan"	    # Do not forget the @domain.name otherwise you're gonna get a nice long error message! No, I mean like really, really long.
dirpw = "nutanix/4u2"		    # password, yes, I know. But this can be a read only user/password!
# Setting up 1 user and 1 group:
roleuser = ["otto","ADuser"]	    # AD users to give User Admin rights to
roleuserrole = "ROLE_USER_ADMIN"
rolegroup = "VCAdmins"		    # Active Directory Group to give Cluster Admin rights to
rolegrouprole = "ROLE_CLUSTER_ADMIN"
##########################
#End of Variable Settings#
##########################

#############################################################
# Turn on (1) or off (0) settings below (useful for testing)#
#############################################################
create = 1
setnewpw = 1	# change default pw from defpasswd to passwd
seteula = 1		# Accept the EULA and register; BY CHANGING THIS FROM A 0 to a 1 YOU ARE ACCEPTING THE EULA!
setsmtp = 0		# set up the smtp info
setdns = 0		# verify and if necessary correct DNS servers
setntp = 0		# verify and if necessary correct NTP servers
setproxy = 0	# set the proxy
set2048 = 1		# disable the 2048 game
setwelcome = 1	# enable and set the text of the welcome banner
setauth = 0 	# this one includes actually testing ldap auth
setrole = 0		# ##### WARNING: DESTRUCTIVE! #####  AD role mapping by creating predefined roles (see "Set Up Role Mapping" below for further info)
setuser = 0		# Set up the readonly local user
setstorage = 1	# ##### WARNING: DESTRUCTIVE! #####  Setup storage defaults by deleting default pool/container and creating new ones
setPC = 1		# Join Prism Central
setVCSA = 1		# Prism Element vCenter Registration
setVCSAauth = 1	# CVM vCenter Authentication
setPEsplash = 1 # Prism Element Splash Name


# The rest of these variables shouldn't need to be changed under normal circumstances.
# EDIT WITH CAUTION
# Define URIs here.  Keep them as variables as the API could change.
buri2 = "https://" + CIP + ":9440/PrismGateway/services/rest/v2.0"
buri1 = "https://" + CIP + ":9440/PrismGateway/services/rest/v1/"
uri_hosts = "hosts/"
uricluster = "/cluster/"
uricluster1 = "cluster"
urichangepw = "utils/change_default_system_password"
urieulas = "eulas/accept"
uripulse = "pulse"
urialert = "alerts/configuration"
urismtp = "/cluster/smtp"
uridns = "/cluster/name_servers"
urintp = "/cluster/ntp_servers"
uriproxy = "http_proxies/"
urivm = "/vms/"
urisc = "/storage_containers/"
uriim = "/images/"
uritask = "/tasks/"
urisysdata = "application/system_data"
uriauth = "/authconfig/"
uridir = "directories/"
uritest = "connection_status"
urirole = "authconfig/directories/" + dirname + "/role_mappings"
uriuser = "users/"
uricheckPC = "multicluster/cluster_external_state"
uriPC = "multicluster/add_to_multicluster"
uristorage = "storage_pools"
uricontainer = "/storage_containers/"
uricontainer1 = "containers/"
uri_add_datastore = "datastores/add_datastore"
urivcsareg = "management_servers/register"
urivcsaauth = "genesis"


###############################################
# DO NOT CHANGE ANYTHING BELOW THIS LINE!!!!! #
###############################################
headers = {'content-type': 'application/json'}
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
FNULL = open(os.devnull, 'w')

def ping(host):
    ping_str = "-n 1" if  platform.system().lower()=="windows" else "-c 1"
    args = "ping " + " " + ping_str + " " + host
    need_sh = False if  platform.system().lower()=="windows" else True
    return subprocess.call(args, shell=need_sh, stdout=FNULL, stderr=subprocess.STDOUT) == 0

# should convert these to try|except
def restget(uri):
    response = requests.get(uri,auth=HTTPBasicAuth(user,passwd),headers=headers,verify=False)
    return(response)

def restpost(uri,payload, password=passwd):
    response = requests.post(uri,auth=HTTPBasicAuth(user,password),headers=headers,json=payload,verify=False)
    return(response)

def restpatch(uri,payload):
    response = requests.patch(uri,auth=HTTPBasicAuth(user,passwd),headers=headers,json=payload,verify=False)
    return(response)

def restpatch2(uri,payload):
    response = requests.patch(uri,auth=HTTPBasicAuth(user,passwd),headers=headers,data=payload,verify=False)
    return(response)

def restput(uri,payload):
    response = requests.put(uri,auth=HTTPBasicAuth(user,passwd),headers=headers,json=payload,verify=False)
    return(response)

def restput2(uri,payload):
    response = requests.put(uri,auth=HTTPBasicAuth(user,passwd),headers=headers,data=payload,verify=False)
    return(response)

def restdelete(uri,payload):
    response = requests.delete(uri,auth=HTTPBasicAuth(user,passwd),headers=headers,json=payload,verify=False)
    return(response)


def ssh_connect(hostname, username, password):
    port = 22
    ssh_host = paramiko.SSHClient()
    ssh_host.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    logging.info(f"Trying to connect to {hostname}")
    try:
        ssh_host.connect(hostname=hostname, port=port, username=username, password=password)
    except paramiko.ssh_exception.AuthenticationException as e:
        ssh_host = None
        logging.exception(f"Error authenticating SSH connection for {username}@{hostname}:{port}. Error: {e}")
    except paramiko.BadAuthenticationType as e:
        ssh_host = None
        logging.exception(f"Error authenticating SSH connection for {username}@{hostname}:{port}. Error: {e}")
    except Exception as e:
        ssh_host = None
        logging.exception(f"Error with SSH connection for {username}@{hostname}:{port}. Error: {e}")
    logging.info(f"Successfully connected to {hostname}")
    return ssh_host


def ssh_run_command(ssh_ref, cmd):
    lines = []
    logging.info(f"Launching command: {cmd}")
    try:
        stdin, stdout, stderr = ssh_ref.exec_command(cmd)
        while True:
            logging.debug(f"Received output: {stdout}")
            logging.debug(f"Received errors: {stderr}")
            line = stdout.readline()
            if not line:
                break
            logging.debug(f"line: {line}")
            lines.append(line)
    except Exception as e:
        logging.exception(f"Error running command {cmd} with SSH. Error {e}")
        lines = None
    return lines


def myexec(ssh, cmd, timeout, want_exitcode=False):
  # one channel per command
  stdin, stdout, stderr = ssh.exec_command(cmd)
  # get the shared channel for stdout/stderr/stdin
  channel = stdout.channel

  # we do not need stdin.
  stdin.close()
  # indicate that we're not going to write to that channel anymore
  channel.shutdown_write()

  # read stdout/stderr in order to prevent read block hangs
  stdout_chunks = []
  output = stdout.channel.recv(len(stdout.channel.in_buffer))
  stdout_chunks.append(output)
  logging.debug(output.decode('utf-8'))
  #stdout_chunks.append(stdout.channel.recv(len(stdout.channel.in_buffer)))
  # chunked read to prevent stalls
  while not channel.closed or channel.recv_ready() or channel.recv_stderr_ready():
      # stop if channel was closed prematurely, and there is no data in the buffers.
      got_chunk = False
      readq, _, _ = select.select([stdout.channel], [], [], timeout)
      for c in readq:
          if c.recv_ready():
              output = stdout.channel.recv(len(c.in_buffer))
              stdout_chunks.append(output)
              logging.debug(output.decode('utf-8'))
              #stdout_chunks.append(stdout.channel.recv(len(c.in_buffer)))
              got_chunk = True
          if c.recv_stderr_ready():
              # make sure to read stderr to prevent stall
              err = stderr.channel.recv_stderr(len(c.in_stderr_buffer))
              logging.error(err.decode('utf-8'))
              #stderr.channel.recv_stderr(len(c.in_stderr_buffer))
              got_chunk = True
      '''
      1) make sure that there are at least 2 cycles with no data in the input buffers in order to not exit too early (i.e. cat on a >200k file).
      2) if no data arrived in the last loop, check if we already received the exit code
      3) check if input buffers are empty
      4) exit the loop
      '''
      if not got_chunk \
          and stdout.channel.exit_status_ready() \
          and not stderr.channel.recv_stderr_ready() \
          and not stdout.channel.recv_ready():
          # indicate that we're not going to read from this channel anymore
          stdout.channel.shutdown_read()
          # close the channel
          stdout.channel.close()
          break    # exit as remote side is finished and our bufferes are empty

  # close all the pseudofiles
  stdout.close()
  stderr.close()

  result = b''.join(stdout_chunks).decode('utf-8')
  if want_exitcode:
      # exit code is always ready at this point
      return (result, stdout.channel.recv_exit_status())
  return result


# cluster -s 192.168.0.137,192.168.0.138,192.168.0.139 --cluster_external_ip 192.168.0.140 --cluster_name hou-clus2 --dns_servers 192.68.0.1 --ntp_servers ntp.hpecorp.net create
def create_cluster():
    cvms = list()
    for i in cvm:
        cvms.append(i['mgmtIP'])

    cvm_ips = ",".join(cvms)
    cmd = f". /etc/profile; cluster -s {cvm_ips} --cluster_external_ip {CIP} --cluster_name {clustername} --dns_servers {DNS1} --ntp_servers {NTP1} create"
    CVM_USER = cvm[0]['username']
    CVM_PASSWORD = cvm[0]['password']
    ssh_ref = ssh_connect(cvms[0], CVM_USER, CVM_PASSWORD)
    if ssh_ref:
        output = myexec(ssh_ref, cmd, None)
        #logging.debug(f" Final output: {output}")
        ssh_ref.close()
    else:
        logging.error(f"SSH connection to CVM at IP address {cvms[0]} failed")


def get_hosts_uuids():
    uri = buri1 + uri_hosts
    status = restget(uri)
    hosts = []
    if (status.ok):
        num_entities = status.json()['metadata']['totalEntities']
        for a in status.json()['entities']:
            uuid = a.get('uuid', None)
            if uuid:
                hosts.append(uuid)
        if len(hosts) != num_entities:
            print("Failed to get hosts uuids.\n  Please investigate.  Exiting...")
            raise SystemExit
        return hosts
    else:
        print("Failed to get hosts uuids:\t", status.json()['message'],"\n  Please investigate.  Exiting...")
        raise SystemExit


########################
# MAIN                 #
########################
if __name__ == '__main__':
    if create:
        create_cluster()

    if ping(CIP):
        print("\n")
        ###############################
        # Change the default password #
        ###############################
        if (setnewpw):
            uri = buri1 + urichangepw
            payload = {'oldPassword': defpasswd, 'newPassword': passwd}
            status = restpost(uri,payload,password=defpasswd)
            if (status.ok):
                print("Changed default password:\t" , status.json())
            else:
                print("Failed to change default password:\t", status.json() ,"\n  Please investigate.  Exiting...")
                raise SystemExit

        ########################################
        # GET Cluster Information and store it #
        ########################################
        """
        uri = buri2 + uricluster
        status = restget(uri)
        if (status.ok):
            cname = status.json()['name']
            cluversion = status.json()['version']
            print("Cluster UUID:\t " + status.json()['uuid'])
            print("Cluster ID:\t " + status.json()['id'])
            if ("Unnamed" in cname):
                print("Cluster is",cname,"\nAttempting to rename the cluster to",clustername)
                uri = buri1 + uricluster1
                payload = {"name":clustername,"clusterExternalIPAddress":status.json()['cluster_external_ipaddress'],"clusterExternalDataServicesIPAddress":status.json()['cluster_external_data_services_ipaddress']}
                status = restput(uri,payload)
                if (status.ok):
                    print("Renamed the cluster:\t" , status.json())
                    cname = clustername
                else:
                    print("Failed to rename the cluster:\t", status.json()['message'] ,"\n  Please investigate.  Exiting...")
                    raise SystemExit
            else:
                print("Cluster Name:\t " + cname)
            print("AOS Version:\t " + cluversion)
        else:
            print("Unable to get Cluster Name:\t ", status.json() ,"\n  Please investigate.  Exiting...")
            raise SystemExit
        """

        #####################
        # Set the SMTP data #
        #####################
        if (setsmtp):
            uri = buri2 + urismtp
            payload = {'address': SMTPADD ,'from_email_address': clustername + "@" + SMTPDOM,'port': SMTPPORT}
            status = restput(uri,payload)
            if (status.ok):
                print("Set SMTP Settings:" , payload)
            else:
                print("Unable to set SMTP Settings!\n  Please investigate.  Exiting...")
                raise SystemExit


        ################################
        # Accept the EULA and register #
        ################################
        if (seteula):
            uri = buri1 + urieulas
            payload = {'username': username, 'companyName': companyName, 'jobTitle': jobTitle}
            status = restpost(uri,payload)
            if (status.ok):
                print("Accepting the EULA:\t" , status.json())
            else:
                print("Failed to accept the EULA:\t", status.json() ,"\n  Please investigate.  Exiting...")
            #	raise SystemExit

            uri = buri1 + uripulse
            #payload = {"emailContactList":'',"enable":True,"verbosityType":'',"enableDefaultNutanixEmail":True,"defaultNutanixEmail":'',"nosVersion":'',"isPulsePromptNeeded":False,"remindLater":''}
            payload = {"emailContactList":[],"enable":True,"verbosityType":"BASIC_COREDUMP","enableDefaultNutanixEmail":True,"defaultNutanixEmail":"nos-asups@nutanix.com","isPulsePromptNeeded":False,"remindLater":False}
            status = restput(uri,payload)
            if (status.ok):
                print("Accepting Pulse ON:\t" , status.json())
            else:
                print("Failed to accept Pulse:\t", status.json() ,"\n  Please investigate.  Exiting...")
                raise SystemExit

            uri = buri1 + urialert
            payload = {"enableDefaultNutanixEmail":True}
            status = restput(uri,payload)
            if (status.ok):
                print("Pulse setup complete:\t" , status.json())
            else:
                print("Failed to setup Pulse:\t", status.json() ,"\n  Please investigate.  Exiting...")
                raise SystemExit

        ################
        # disable 2048 #
        ################
        if (set2048):
            uri = buri1 + urisysdata
            payload = {'key': 'disable_2048', 'type':'ui_config', 'value':'true'}
            keyexists = 0
            status = restget(uri)
            for a in range(len(status.json())):
                if ("disable_2048" in status.json()[a]['key']):
                    keyexists = 1

            if (keyexists == 1):
                status = restput(uri,payload)
            else:
                status = restpost(uri,payload)

            if (status.ok):
                print("Disabled 2048:\t " , payload)
            else:
                print("Unable to disable 2048!\n  Please investigate.  Exiting...")
                raise SystemExit

        ######################
        # Set Welcome Banner #
        ######################
        if (setwelcome):
            uri = buri1 + urisysdata
            payload = {'key': 'welcome_banner_status', 'type':'WELCOME_BANNER', 'value':'true'}
            keyexists = 0
            status = restget(uri)
            for a in range(len(status.json())):
                if ("welcome_banner_status" in status.json()[a]['key']):
                    keyexists = 1

            if (keyexists == 1):
                status = restput(uri,payload)
            else:
                status = restpost(uri,payload)

            if (status.ok):
                print("Enabled Banner:\t " , payload)
            else:
                print("Unable to Enable Banner!\n  Please investigate.  Exiting...")
                raise SystemExit
            payload = {'key': 'welcome_banner_content', 'type': 'WELCOME_BANNER', 'value': bannermsg}
            keyexists = 0
            status = restget(uri)
            for a in range(len(status.json())):
                if ("welcome_banner_content" in status.json()[a]['key']):
                    keyexists = 1

            if (keyexists == 1):
                status = restput(uri,payload)
            else:
                status = restpost(uri,payload)
            status = restput(uri,payload)
            if (status.ok):
                print("Set Banner:\t " , payload)
            else:
                print("Unable to Set Banner!\n  Please investigate.  Exiting...")
                raise SystemExit


        ##########################
        # Set up Default Storage #
        ##########################
        if (setstorage):
            # WARNING: This will rename any and all storage pools with the name "default" in it to the cluster name!
            uri = buri1 + uristorage
            status = restget(uri)
            for a in range(len(status.json()['entities'])):
                if ("default" in status.json()['entities'][a]['name']):
                    print(status.json()['entities'][a]['name'])
                    uri = buri1 + uristorage + "?force=true"
                    payload = {"clusterUuid": status.json()['entities'][a]['clusterUuid'], "genericDTO": {"storagePoolUuid": status.json()['entities'][a]['storagePoolUuid'], "name": clustername}}
                    status = restpatch(uri,payload)
                    if (status.ok):
                        print("Renamed default Storage Pool successfully:" , status.json())
                    else:
                        print("Failed to rename default Storage Pool:\t ", status ,"\n  Please investigate.  Exiting...")
                        raise SystemExit
                else:
                    print("Default Storage Pool not found!")
            # delete default storage container
            uri = buri1 + uricontainer1
            status = restget(uri)
            for a in range(len(status.json()['entities'])):
                if ("default" in status.json()['entities'][a]['name']):
                    defsc = status.json()['entities'][a]['name']
                    uri = buri1 + uricontainer1 + status.json()['entities'][a]['id'] + "?ignoreSmallFiles=true"
                    payload = {"ignoreSmallFiles": True}
                    status2 = restdelete(uri,payload)
                    if (status2.ok):
                        print("Deleted default storage container:\t" , defsc)
                    else:
                        print("Failed to delete default storage container:\t", status.json()['message'] ,"\n  Please investigate.")
                        raise SystemExit

            # create additional storage containers and mount as NFS datastores
            hosts_uuids = get_hosts_uuids()
            for a in scs:
                uri = buri1 + uricontainer1
                if ("backup" in a):
                    payload = {"name":a,"advertisedCapacity":2199023255552,"compressionEnabled":True,"compressionDelayInSecs":0,"fingerPrintOnWrite":"OFF","onDiskDedup":"OFF"}
                else:
                    payload = {"name":a,"compressionEnabled":True,"compressionDelayInSecs":0,"fingerPrintOnWrite":"OFF","onDiskDedup":"OFF"}
                status = restpost(uri,payload)
                if (status.ok):
                    print("New storage container created:\t" , a)
                    uri = buri1 + uricontainer1 + uri_add_datastore
                    payload = {
                        "container_name": a,
                        "datastore_name": a,
                        "node_uuids": get_hosts_uuids()
                    }
                    status2 = restpost(uri, payload)
                    if (status2.ok):
                        print(f"Mounted storage container as NFS datastore:\t {a}.")
                    else:
                        print(f"Failed to mount storage container as NFS datastore:\t {a}. "
                              f"Error: {status.json()['message']} \n  Please investigate.")
                        raise SystemExit
                else:
                    print("Failed to create new storage container:" , a + " \n  Please investigate.")
                    raise SystemExit

        ##############################
        # PE to vCenter Registration #
        ##############################
        if (setVCSA):
            uri = buri1 + urivcsareg
            payload = {"adminUsername": VCSAuser,"adminPassword": VCSApwd,"ipAddress": VCSAIP,"port":"443"}
            status = restpost(uri,payload)
            if (status.ok):
                print("PE Successfully Registered with vCenter:\t" , status.json())
            else:
                print("Failed to Register PE with vCenter:\t", status.json() ,"\n  Please investigate.  Exiting...")
                raise SystemExit

        ##############################
        # CVM vCenter Authentication #
        ##############################
        if (setVCSAauth):
            uri = buri1 + urivcsaauth
            payload = {"value":"{\".oid\":\"ClusterManager\",\".method\":\"set_mgmt_server_info\",\".kwargs\":{\"mgmt_info\":{\"host_type\":\"esx\",\"server_ip\":\"192.168.0.134\",\"server_username\":\"administrator@hou-thd.local\",\"server_passwd\":\"Password!234\"}}}"}
            status = restpost(uri,payload)
            if (status.ok):
                print("CVM Successfully Authenticated with vCenter:\t" , status.json())
            else:
                print("Failed to Authenticate CVM with vCenter:\t", status.json() ,"\n  Please investigate.  Exiting...")
                raise SystemExit

        #################
        # Set PE Splash #
        #################
        if (setPEsplash):
            uri = buri1 + urisysdata
            payload = {"type":"custom_login_screen","key":"product_title","value":"PE for " + clustername}
            status = restput(uri,payload)
            if (status.ok):
                print("Prism Element Splash Successfully Set:\t" , status.json())
            else:
                print("Failed to Set PE Splash:\t", status.json() ,"\n  Please investigate.  Exiting...")
                raise SystemExit

        ################################
        # Add Cluster to Prism Central #
        ################################
        if (setPC):
            if (ping(PCIP)):
                uri = buri1 + uricheckPC
                keyexists = 0
                status = restget(uri)
                if (status.json()):
                    keyexists = 1

                if (keyexists == 1):
                    print("Already joined to Prism Central named '",
                          status.json()[0]['clusterDetails']['clusterName'], "' at IP",
                          status.json()[0]['clusterDetails']['ipAddresses'])
                else:
                    uri = buri1 + uriPC
                    payload = {"ipAddresses": [PCIP], "username": PCuser, "password": PCpw}
                    status = restpost(uri, payload)
                    if (status.ok):
                        print("Registered to Prism Central successfully:", status.json())
                    else:
                        print("Failed to join Prism Central:\t ", status.json()['message'],
                              "\n  Please investigate.  Exiting...")
            else:
                print("Cannot ping Prism Central at " + PCIP)
                print("Please investigate.")
    else:
        print("Cannot ping cluster at " + CIP)
        print("Please investigate.  Exiting...")
        raise SystemExit


print("\n")
