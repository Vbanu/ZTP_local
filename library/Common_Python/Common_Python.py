'''
DISCLAIMER OF WARRANTY
This document may contain the following HPE or other software: XML, CLI
statements, scripts, parameter files. These are provided as a courtesy, free of
charge, AS-IS by Hewlett Packard Enterprise, L.P. (HPE). HPE shall have no
obligation to maintain or support this software. HPE MAKES NO EXPRESS OR
IMPLIED WARRANTY OF ANY KIND REGARDING THIS SOFTWARE INCLUDING ANY WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE OR NON-INFRINGEMENT.
HPE SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR
CONSEQUENTIAL DAMAGES, WHETHER BASED ON CONTRACT, TORT OR ANY OTHER LEGAL
THEORY,IN CONNECTION WITH OR ARISING OUT OF THE FURNISHING, PERFORMANCE OR USE
OF THIS SOFTWARE.(c) Copyright 2017 Hewlett Packard Enterprise, L.P. The
information contained herein is subject to change without notice. The only
warranties for HPE products and services are set forth in the express warranty
statements accompanying such products and services. Nothing herein should be
construed as constituting an additional warranty. HPE shall not be liable for
technical or editorial errors or omissions contained herein.
'''


import os
import time
import datetime
import subprocess
import json
import logging

from python_logger import logger_fle_lvl
logger_fle_lvl('info')

# Function to write intro at start of script to stdout
def printintro(PLUGIN_NAME, PLUGIN_PURPOSE):
    scriptname = os.path.basename(__file__)
    stamp = datetime.datetime.fromtimestamp(
        time.time()).strftime('%Y-%m-%d Time %H-%M-%S')
    logging.info('----------------------------------------------------------------------------------------------------------'
          + "\n")
    logging.info('Plugin Name: ' + PLUGIN_NAME)
    logging.info('Plugin Purpose: ' + PLUGIN_PURPOSE)
    logging.info('Script Name: ' + scriptname)
    logging.info('Start Time: ' + stamp)
    logging.info('----------------------------------------------------------------------------------------------------------'
          + "\n")

# Function to write ending of script to stdout


def printoutro():
    stamp = datetime.datetime.fromtimestamp(
        time.time()).strftime('%Y-%m-%d Time %H-%M-%S')
    logging.info('----------------------------------------------------------------------------------------------------------'
          + "\n")
    logging.info('Stop Time: ' + stamp)
    logging.info('----------------------------------------------------------------------------------------------------------'
          + "\n")

# Function to write a line to sequence builder report


def seqbuildreportrow(seqbuildreport, groupName, keyName, affectedObjects, serviceObjects, enabled="enabled", iffail="yes", actual="NA", expected="NA", parallel="N/A"):
    report_file = open(seqbuildreport, "a")
    #line = ('%s\t%s\t%s\t%s\t%s\n' % (groupName, keyName, parallel, affectedObjects, actual, expected))
    if len(serviceObjects) >= 3:
        row_dict = {"groupname" : groupName,
                "keyname" : keyName,
                "parallelwithprev" : parallel,   #"NA",
                "affectedobjects" : affectedObjects,
                "serviceObjects" : serviceObjects,
                "enabled" : enabled,
                "currentversion" : actual,
                "toversion" : expected,
                "iffail" : iffail }
        line = json.dumps(row_dict)
        # line = ('{"groupname" : "%s", "keyname" : "%s", "parallelwithprev" : "%s", "affectedobjects" : "%s", "serviceObjects" : "%s", "enabled" : "%s", "currentversion" : "%s",  "toversion" : "%s",  "iffail" : "%s"}\n' % (
        #     groupName, keyName, parallel, affectedObjects, serviceObjects, enabled, actual, expected, iffail))
        # report_file.write(line)
        logging.info("Added " + line + " to workflow")
        report_file.write(line + "\n")
    else:
        logging.info("Required inputs not found")
    report_file.close()


def seqbuildreportnote(seqbuildreport, note):
    report_file = open(seqbuildreport, "a")
    line = ('{"type" : "note", "note" : "%s"}\n' % (note))
    report_file.write(line)
    report_file.close()

# Prints report table header


def reportIntro(reportwriter, category, validationName):
      line = (category + "\t" + "Status" + "\t" + "Description")
      reportwriter.write(validationName + "\n")
      reportwriter.write(line + "\n")

# Prints report row


def reportRow(reportwriter, category, status, description):
    line = (category + "\t" + status + "\t" + description)
    reportwriter.write(line + "\n")


# Function to wait for any ip to ping
def waitforNetwork(ip):
    try:
        count = 0
        resp = subprocess.call("ping " + ip + " -n 5", shell=True)
        while count < 90 and resp != 0:
            resp = subprocess.call("ping " + ip + " -n 5", shell=True)
            time.sleep(20)
            count = count + 1

        if resp == 0:
            return True
        else:
            logging.info("OneView is taking long time to come online")
            return False

    except Exception as e:
        logging.info("Error occurred - ", str(e))
        return None

# Function to Generate JSON file
def generateJSON(path,data):
    try:
        json_object = json.dumps(data, indent=4)
        with open(path, "w") as outfile:
            outfile.write(json_object)
    except Exception as e:
        logging.info("Exception in generating JSON file", str(e))

class gatewayConstants:
    osInfraNWPurposeName    = "OS and Infrastructure Management Network"
    platforGlNWPurposeName  = "Platform and GreenLake Services Network"
    iloMgmtPurpose          = "iLO Management"
    pduMgmtPurpose          = "PDU Management"
    mgmtServerMgmtPurpose   = "Management Server Management"
    platformAndGlPurpose    = "Platform And GreenLake Services"
    platformDataPurpose     = "Platform Data"
    netSwitchMgmtPurpose    = "Network Switch Management"
    externalNetPurpose      = "FS External"
    externalNetPurposeName  = "Foundation Services External Network"
    pfSenseSyncPurpose      = "pfSense Sync"
    pfSenseSyncPurposeName  = "pfSense Sync Network"