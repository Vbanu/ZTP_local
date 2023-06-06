import logging, datetime, os, sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "library", "pythonLib"))
from python_logger_config import data


def delete_old_logs(xdays=data.get("DELETE_LOG_DAYS")):
    """ This function is to delete logfiles based on given days
    Args/Input: We have to provide days in digit/integer/number format
    Returns: It will return a message
        for success case: Last days log files deleted for success case,
        for error failure case: Exception error message will be returned
    """
    msg = "something went wrong"
    try:
        path = data.get("file_path")
        if os.path.exists(path):
            for file in os.listdir(path):
                if file.endswith('.log'):
                    full_path = os.path.join(path, file)  # to get the file full_path
                    timestamp = os.stat(full_path).st_ctime  # to get the file created date
                    # timestamp = os.stat(full_path).st_m_time # to get the file modified date
                    create_time = datetime.datetime.fromtimestamp(timestamp)
                    delta = datetime.datetime.now() - create_time
                    if delta.days < xdays:
                        os.remove(full_path)
                        msg = 'Last {} days log files deleted'.format(xdays)
    except Exception as e:
        msg = str(e.message)
    return msg


def logger_fle_lvl(lvl=data.get("DEFAULT_LOG_LEVEL")):
    """ This function is to create loggs based on given  log level with datetime, log level, line number, file name,
        message. We can configure file path in config file or we can view standard output logs
        Args/Input: We have to provide log levels
        Returns: It will return a message
            for success case: Successfully logger file created,
            for error failure case: Exception error message will be returned
    """
    try:
        log_level_dic = {'info': logging.INFO, 'debug': logging.DEBUG, 'warning': logging.WARNING,
                         'error': logging.ERROR,
                         'critical': logging.CRITICAL}
        log_lvl = log_level_dic.get(lvl)
        logging.basicConfig(stream=sys.stdout, level=log_lvl,
                            format='%(asctime)s %(levelname)s Line:%(lineno)d  %(filename)s - %(message)s',
                            filemode='a', datefmt=data.get("date_format"))
        msg = 'Successfully {} logger file created'.format(lvl)
    except Exception as e:
        msg = str(e.message)
    return msg
