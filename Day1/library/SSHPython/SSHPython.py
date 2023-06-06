"""
* Connect to the remote server
* Execute the given command
* Upload a file
* Download a file
"""
import paramiko
import os
import socket
import time
import platform    # For getting the operating system name
import subprocess  # For executing a shell command
import sys
import json
import datetime
import argparse
from argparse import RawTextHelpFormatter
import re
import requests
import types
import io
import http.client
import urllib.request, urllib.parse, urllib.error
import ssl
import subprocess
import logging
from platform import system as system_name
from os import system as system_call
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings()

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "library", "common"))

from python_logger import logger_fle_lvl
logger_fle_lvl('info')

Fail = "Fail"
Pass = "Pass"


def execute_command(client, command, timeout=600, exitCodeCheck=False, print_commands=False, printErrorMsg=True):
    """Execute a command on the remote host.Return a tuple containing
    an integer status and a two strings, the first containing stdout
    and the second containing stderr from the command."""
    ssh_output = None
    ssh_error = None
    result_flag = Pass
    cmdexitcode = 1
    try:
        if client:
            time.sleep(1)
            if print_commands:
                logging.info("Executing command --> ", (command))
            stdin, stdout, stderr = client.exec_command(
                command, timeout=timeout)
            ssh_output = stdout.read().decode('UTF-8').strip("\n")
            ssh_error = stderr.read().decode('UTF-8').strip("\n")
            if exitCodeCheck:
                cmdexitcode = stdout.channel.recv_exit_status()
            if cmdexitcode != 0 and exitCodeCheck and printErrorMsg:
                logging.info("Problem occurred while running command:" +
                      command + ssh_error)
                result_flag = Fail
            elif ssh_error and printErrorMsg:
                logging.info("Problem occurred while running command:" +
                      command + ssh_error)
                result_flag = Fail
            if print_commands:
                logging.info("Command execution completed successfully", command)
        else:
            logging.info("Could not establish SSH connection")
            result_flag = Fail
    except socket.timeout as e:
        logging.info("Command timed out.", command)
        result_flag = Fail
    except paramiko.SSHException:
        logging.info("Failed to execute the command!", command)
        result_flag = Fail
    except Exception as e:
        logging.info("Failed to execute the command!", command)
        logging.info('Exception:', e)
        result_flag = Fail

    return result_flag, ssh_output, ssh_error


def upload_file(client, localFilepath, remoteFilepath):
    "This method uploads the file to remote server"
    result_flag = Pass
    try:
        if client:
            ftp_client = client.open_sftp()
            ftp_client.put(localFilepath, remoteFilepath)
            ftp_client.close()
        else:
            logging.info("Could not establish SSH connection")
            result_flag = Fail
    except Exception as e:
        logging.info('\nUnable to upload the file to the remote server', remoteFilepath)
        logging.info('PYTHON SAYS:', e)
        result_flag = Fail
        #ftp_client.close()

    return result_flag


def download_file(client, remoteFilepath, localFilepath):
    "This method downloads the file from remote server"
    result_flag = Pass
    try:
        if client:
            ftp_client = client.open_sftp()
            ftp_client.get(remoteFilepath, localFilepath)
            ftp_client.close()
        else:
            logging.info("Could not establish SSH connection")
            result_flag = Fail
    except Exception as e:
        logging.info('\nUnable to download the file from the remote server', remoteFilepath)
        logging.info('PYTHON SAYS:', e)
        result_flag = Fail
        #ftp_client.close()

    return result_flag


def connect_host(hostIP, username, password):
    "Login to the remote server"
    result_flag = Pass
    try:
        # Paramiko.SSHClient can be used to make connections to the remote server and transfer files
        logging.info("Establishing ssh connection...")
        client = paramiko.SSHClient()
        # Parsing an instance of the AutoAddPolicy to set_missing_host_key_policy() changes it to allow any host.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Connect to the server
        client.connect(hostname=hostIP, port=22, username=username, password=password, timeout=20, allow_agent=False,
                       look_for_keys=False)
        logging.info(hostIP, " - Connected to the server")
    except paramiko.AuthenticationException:
        logging.info(hostIP, " - Authentication failed, please verify your credentials")
        result_flag = Fail
    except paramiko.SSHException as sshException:
        logging.info(hostIP, " - Could not establish SSH connection: %s" % sshException)
        result_flag = Fail
    except socket.timeout as e:
        logging.info(hostIP, " - Connection timed out")
        result_flag = Fail
    except Exception as e:
        logging.info(hostIP, " - Exception in connecting to the server")
        logging.info('Exception:', e)
        result_flag = Fail
    else:
        result_flag = Pass
    return client, result_flag


def checkFile(client, filePath, type="File"):
    "This method checks if file exsist"
    try:
        if client:
            if type == "File":
                cmdstatus, ssh_output, ssh_error = execute_command(
                    client, "test -f " + filePath, 10, True)
            else:
                cmdstatus, ssh_output, ssh_error = execute_command(
                    client, "test -d " + filePath, 10, True)
        else:
            logging.info("Could not establish SSH connection")
            cmdstatus = Fail
    except Exception as e:
        logging.info('Exception:', e)
        cmdstatus = Fail

    return cmdstatus


def put_all(client, localpath, remotepath):
    """
    Copying directory recursively to remote location
    """
    try:
        sftp = client.open_sftp()
        os.chdir(os.path.split(localpath)[0])
        parent = os.path.split(localpath)[1]
        for walker in os.walk(parent):
            try:
                remote_path = os.path.join(remotepath, walker[0])
                remote_path = remote_path.replace("\\", "/")
                sftp.mkdir(remote_path)
                sftp.cwd(remote_path)
            except:
                pass

            for file in walker[2]:
                file_path = os.path.join(localpath, file)
                remote_file_path = remote_path + "/" + file.replace("\\","/")
                logging.info(file_path, remote_file_path)
                try:
                    sftp.put(file_path, remote_file_path)
                except Exception as e:
                    continue
            for file in os.listdir(os.path.join(os.getcwd(), parent, walker[1][0])):
                file_path = os.path.join(
                    os.getcwd(), parent, walker[1][0], file)
                remote_file_path = remote_path + "/" + file.replace("\\", "/")
                logging.info(file_path, remote_file_path)
                try:
                    sftp.put(file_path, remote_file_path)
                except Exception as e:
                    continue
            sftp.chdir(remote_path)
    except Exception as e:
        logging.info("exception is %s", e)


def pingIp(ipAddress):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    command = f'ping -n 1 {ipAddress} | find "TTL=" > NUL' if platform.system().lower() == 'windows' else f'ping -c 1 {ipAddress} | grep -i "ttl=" > /dev/null'
    for i in range(5):
        pingStatus = subprocess.call(command,shell=True) == 0

    return pingStatus




def getchannel(hostip,username,password):
    try:
        global ssh,channel,channel_data
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostip, 22, username, password)
        channel = ssh.invoke_shell()
        return channel

    except Exception as e:
        logging.info(getStamp()+"Exception is connecting to afc")
        logging.info("Exception",e)


def waitForChannel():
    channel_ready_status = True
    try:
        global channel, channel_data
        while channel_ready_status:
            if channel.recv_ready():
                logging.info((getStamp() + "Getting initial connect information:"))
                channel_data += str(channel.recv(9999))
                time.sleep(5)
                logging.info((getStamp() + "Channel is ready:"))
                channel_ready_status = False
            else:
                time.sleep(5)
                continue
    except Exception as e:
        logging.info("Exception in getting channel back")
        logging.info("Exception:",e)
    return channel_ready_status


def sendcmd(cmd,islist=False):
    try:
        global channel
        global channel_data
        channel_data=""
        if islist and type(cmd) != None:
            for command in cmd:
                channel_data = ""
                channel.send(command)
                channel.send('\n')
                time.sleep(1)
                channel_data += str(channel.recv(9999))
        elif cmd != "":
            channel.send(cmd)
            channel.send('\n')
            time.sleep(1)
            channel_data = str(channel.recv(9999))
        return channel_data

    except Exception as e:
        logging.info("Exception in {} cmd execution ".format(cmd))
        logging.info("Exception",e)



def getStamp():
    return datetime.datetime.utcnow().strftime("%A, %d. %B %Y %I:%M%p") + " "