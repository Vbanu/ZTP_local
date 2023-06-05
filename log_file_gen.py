import os,logging
import json
import argparse
import sys


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        # Set the color of the levelname based on the logging level
        if record.levelno == logging.DEBUG:
            levelname_color = '\033[1;32m'  # Blue '\033[1;34m'
        elif record.levelno == logging.INFO:
            levelname_color = '\033[1;37m'  #white # Green '\033[1;32m' 
        elif record.levelno == logging.WARNING:
            levelname_color = '\033[1;33m'  # Yellow
        elif record.levelno == logging.ERROR:
            levelname_color = '\033[1;31m'  # Red
        elif record.levelno == logging.CRITICAL:
            levelname_color = '\033[1;41m'  # White on red background
        else:
            levelname_color = '\033[0m'  # Normal

        # Format the message using the superclass formatter
        message = super().format(record)
        # Add the color to the levelname
        message = message.replace(record.levelname, levelname_color + record.levelname + '\033[0m')

        return message


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#removing previous handlers 
if logger.hasHandlers():
    logger.handlers.clear()


fh = logging.FileHandler('main_ZTP.log')
fh.setFormatter(logging.Formatter('%(Ded_ID)s -%(store_id)s - %(asctime)s - %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S'))


ch = logging.StreamHandler(stream=sys.stderr)
ch.setFormatter(ColoredFormatter('%(Ded_ID)s -%(store_id)s - %(asctime)s - %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(ch)

#Adding handler to the logger
logger.addHandler(fh)

def task_start(st):
    return ("Task name- "+st+"Task started ")
         
def task_result(task,result):
    return ("Task name- "+task+" task complition status "+result)

#logging.shutdown()
