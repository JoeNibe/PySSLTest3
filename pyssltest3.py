import collections
import concurrent
import threading
import itertools
import datetime
import requests
import logging
import random
import pickle
import json
import time
import sys
import csv

from concurrent.futures import ThreadPoolExecutor
from itertools import cycle
threadLock = threading.Lock()

# Importing color module
try:
    from colorama import Fore, Style, init
except ImportError:
    print("[-]Import Error. Please install colorama Module. \n>pip install colorama")
    sys.exit(0)

# Setting up the logger to output DEBUG to a file and INFO to screen
levels = [logging.CRITICAL, logging.ERROR, logging.WARN, logging.INFO, logging.DEBUG]
LOGGER = logging.getLogger('ssllabtest3')
LOGGER.setLevel(logging.DEBUG)

fh = logging.StreamHandler()  # Console Logger
fh_file = logging.FileHandler('pyssltest3_log.txt')  # File Logger
fh.setLevel(levels[0])  # Controls the console debug level
fh_file.setLevel(levels[4])  # Controls the file debug level

fh_formatter = logging.Formatter('%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                 datefmt='%d-%m-%Y %H:%M:%S')
fh_file_formatter = logging.Formatter('%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                      datefmt='%d-%m-%Y %H:%M:%S')

fh.setFormatter(fh_formatter)
fh_file.setFormatter(fh_file_formatter)
LOGGER.addHandler(fh)
LOGGER.addHandler(fh_file)
LOGGER.info("-"*100)
# Logger Setup Done

__version__ = '2.2'
__author__ = 'Febin Jose; joenibe.github.io'
__license__ = 'GNU General Public License v3.0'

# Global Variables
API_URLS = {'dev': 'https://api.dev.ssllabs.com/api/v3/',
            'stable': 'https://api.ssllabs.com/api/v3/'
            }

API_INFO = API_URLS['stable'] + "info"
API_ANALYZE = API_URLS['stable'] + "analyze?"
API_GET_DATA = API_URLS['stable'] + "getEndpointData?"
HEARTBEAT = 45
THREADS = 9
WRITE_TO_BACKUP = 50  # removed in preserve order change: Added as pickle backup
FROM_CACHE = False
INTERNET_CON = True
INTERNET_SLEEP = cycle([60, 120, 240])  # Time to sleep, if there is no internet
SCANNED = 0
ERRORS = 0
CSV_FILE = "output.csv"
urltime_objs = []  # List of time taken by each url
ssllab_objs = []  # List of ssllabdomain dicts
file_apps_list = []
concur_errors = 0

# Parameters to send with request
new_params = {"publish": "off", "ignoreMismatch": "on", "all": "done", "host": "", "startNew": "on"}
cache_params = {"publish": "off", "ignoreMismatch": "on", "all": "done", "host": "", "fromCache": "on"}
get_data = {"publish": "off", "ignoreMismatch": "on", "all": "done", "host": ""}

# The framework dict that is used to store info for each url
SSLLabDomain_Dict = {'host': '', 'ip': '', 'status_msg': '', 'scanned': '', 'scan_result': {}, 'headers': {},
                     'return_code': '', 'grade': '', 'sec_grade': '', 'heartbleed': '',
                     'goldenDoodle': '', 'logjam': '', 'poodle_tls': '', 'poodle_ssl': '', 'openssl_lucky': '',
                     'ticketbleed': '', 'bleichenbacher': '', 'zombiePoodle': '', 'zeroLengthPaddingOracle': '',
                     'sleepingPoodle': '', 'drown': '', 'freak': '', 'insec_reneg': '', 'openSslCcs': '',
                     'insec_suite': '', 'ssl2': '', 'ssl2_disabled': '', 'hostname_mismatch': '', 'cert_exp': '',
                     'self_signed_cert': '', 'cert_valid_from': '', 'cert_valid_till': '',
                     'cert_issuer': '', 'cert_trusted': '', 'ssl3': '', 'rc4': '', 'rc4_only': '', 'cert_revoked': "",
                     'cert_chain_issue': '', 'cert_chain_incomp': '', 'crime': '', 'forwardSecrecy': '',
                     'weak_priv_key': '', 'weak_sig': '', 'sec_reneg': '', 'tls1.0': '', 'tls1.1': '', 'tls1.2': '',
                     'tls1.3': '', 'thumbprint': '', 'commonNames': '', 'alt_name': '',
                     'conn_error': 0, 'retries': 10, 'scan_err': False
                     }

# The dict that controls the order and content of output file
csv_write_dict = collections.OrderedDict([
    ('Input_URL', 'host'), ('IP', 'ip'),
    ('Status', 'status_msg'), ('Return Code', 'return_code'),
    ('Grade', 'grade'), ('Secondary grade', 'sec_grade'),
    ('Drown', 'drown'), ('Freak', 'freak'), ('Logjam', 'logjam'), ('Heartbleed', 'heartbleed'),
    ('Poodle TLS', 'poodle_tls'), ('Poodle SSL', 'poodle_ssl'), ('Golden Doodle', 'goldenDoodle'),
    ('ROBOT', 'bleichenbacher'), ('Zombie Poodle', 'zombiePoodle'), ('Sleeping Poodle', 'sleepingPoodle'),
    ('OpenSSL ccs', 'openSslCcs'), ('Zero Length Padding Oracle', 'zeroLengthPaddingOracle'),
    ('openSSL Lucky Minus 20 (OpenSSL Padding Oracle vuln)', 'openssl_lucky'), ('Ticketbleed', 'ticketbleed'),
    ('CRIME', 'crime'), ('SSL v2', 'ssl2'), ('SSLv2 SuitesDisabled', 'ssl2_disabled'), ('SSL v3', 'ssl3'),
    ('TLS 1.0', 'tls1.0'), ('TLS 1.1', 'tls1.1'), ('TLS 1.2', 'tls1.2'), ('TLS 1.3', 'tls1.3'),
    ('RC4', 'rc4'), ('RC4 Only', 'rc4_only'), ('Forward Secrecy Supported', 'forwardSecrecy'),
    ('Insecure renegotiation', 'insec_reneg'), ('Secure Renegotiation', 'sec_reneg'),
    ('Insecure Suite', 'insec_suite'), ('Certificate Issuer', 'cert_issuer'),
    ('Certificate Trusted', 'cert_trusted'), ('Certificate Valid From', 'cert_valid_from'),
    ('Certificate Valid Till', 'cert_valid_till'), ('Hostname Mismatch', 'hostname_mismatch'),
    ('Certificate Revoked', 'cert_revoked'), ('Certificate expired', 'cert_exp'),
    ('Self signed certificate', 'self_signed_cert'), ('Cert Chain Issue', 'cert_chain_issue'),
    ('Cert Chain Incomplete', 'cert_chain_incomp'), ('Weak Private Key', 'weak_priv_key'),
    ('Weak Signature', 'weak_sig'), ('Thumbprint', 'thumbprint'), ('Common Names', 'commonNames'),
    ('Alternate Names', 'alt_name')
])


# Custom Error Class to Raise
class AccessError(Exception):
    pass


def welcome():
    """
    Just a fun thing i wanted to try out.
    http://www.patorjk.com/software/taag/#p=display&h=1&v=0&f=ANSI%20Shadow&t=PYSSLTEST%203
    :return: None
    """
    init()
    welcome_text = """
        ██████╗ ██╗   ██╗        ███████╗███████╗██╗  ████████╗███████╗███████╗████████╗    ██████╗
        ██╔══██╗╚██╗ ██╔╝        ██╔════╝██╔════╝██║  ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝    ╚════██╗
        ██████╔╝ ╚████╔╝  █████╗ ███████╗███████╗██║     ██║   █████╗  ███████╗   ██║        █████╔╝
        ██╔═══╝   ╚██╔╝   ╚════╝ ╚════██║╚════██║██║     ██║   ██╔══╝  ╚════██║   ██║        ╚═══██╗
        ██║        ██║           ███████║███████║███████╗██║   ███████╗███████║   ██║       ██████╔╝
        ╚═╝        ╚═╝           ╚══════╝╚══════╝╚══════╝╚═╝   ╚══════╝╚══════╝   ╚═╝       ╚═════╝     """
    print("\n" * 2)
    print(f"{Fore.LIGHTBLUE_EX}{welcome_text}", end="")
    print(f"{Fore.LIGHTGREEN_EX}  █{Fore.LIGHTRED_EX} version {__version__}{Fore.LIGHTGREEN_EX} █")
    print(f"{Fore.LIGHTGREEN_EX}\t{'=' * 93}")
    print("\n"*2)
    print(f"{Fore.WHITE}[+] {Fore.LIGHTRED_EX}Loading URLS. Please Wait...")
    print(Style.RESET_ALL)


def heartbeat(total_count, poolx):
    """
    The core heatbeat function that prints out the updates every HEARTBEAT seconds.
    This function is also responsible for printing the output to backup and csv file
    working:
        Starts a while loop until the apps are complete
            checks if we have internet conn using internet_check()
            calculates average time and remaining URLS data
            print the items in color coded format

            Then comes the file writing to backup section.
                checks if threshold of WRITE_TO_BACKUP has reached
                if it has reached, write to backup file and change the count of files written

        When the loop exits
            convert our ssllabs_objs list to dict
            write to csv in the order it was read from input file. This is done using file_apps_list
    :param total_count: The  total count of application
    :return: None
    """
    try:
        time.sleep(5)
        files_written = 0
        temp_scanned = 0
        avg_countdown_start = time.time()
        avg_time = 100
        while (SCANNED < total_count) and HEARTBEAT:
            try:
                # Checking for internet connection
                while not internet_check():
                    sleep_time = next(INTERNET_SLEEP)
                    print(f"{Fore.RED}[-]{Fore.LIGHTRED_EX}No Internet connection. Pausing for "
                          f"{Fore.LIGHTGREEN_EX}{sleep_time/60} {Fore.LIGHTRED_EX}minutes{Fore.RESET}\n  ")
                    time.sleep(sleep_time)

                avg_countdown = time.time() - avg_countdown_start
                if temp_scanned != SCANNED:  # New applications completed scanning
                    # An experimental ET remaining calculator
                    avg_time = avg_countdown / SCANNED
                    temp_scanned = SCANNED
                else:
                    # If no apps were added then reduce time by HEARTBEAT seconds
                    tick_down = HEARTBEAT/(total_count-SCANNED)
                    avg_time = avg_time - tick_down if avg_time > tick_down else 100

                remaining = total_count - SCANNED

                print(f'[*]{Fore.GREEN} {SCANNED} URLs Scanned', end=':')
                LOGGER.debug(f'[*] {SCANNED} URLs Scanned')
                print(f'{Fore.RED} {ERRORS} Errors', end=':')
                LOGGER.debug(f'[*] {ERRORS} Errors')
                print(f'{Fore.BLUE} {remaining} URLs Remaining', end=":")
                LOGGER.debug(f'[*] {remaining} URLs Remaining')
                print(f'{Fore.WHITE} Estimated time remaining ',
                      f'{Fore.LIGHTRED_EX}{str(datetime.timedelta(seconds=avg_time*remaining)).split(".")[0]}')
                # print(f'{Fore.BLACK} {"-"*50}')
                print(Style.RESET_ALL)

                # Backing up data to pickle
                files_to_write = SCANNED - files_written
                # checks if threshold has reached
                if files_to_write >= WRITE_TO_BACKUP:
                    print(f"[+] {Fore.LIGHTGREEN_EX}Saving to Backup File")
                    print(Style.RESET_ALL)
                    with threadLock:
                        save_obj(ssllab_objs, "pysslbackup")
                    files_written = SCANNED

                time.sleep(HEARTBEAT)

            except (KeyboardInterrupt, SystemExit):
                print('\n! Received keyboard interrupt, quitting threads.\n')
                sys.exit()
            except Exception as e:
                LOGGER.error(e, exc_info=True)

        # Write everything to backup file and output file
        print(f"[+] {Fore.LIGHTGREEN_EX}Saving to Backup File")
        save_obj(ssllab_objs, "pysslbackup")
        print(Style.RESET_ALL)
        print(f"[+] {Fore.LIGHTGREEN_EX}Writing to Output File")
        print(Style.RESET_ALL)

        # We are converting list of dicts to dict of dicts, so we can write to csv preserving the order of the list
        ssllab_objs_csv = {}
        for obj in ssllab_objs:
            ssllab_objs_csv[obj.get('host')] = obj

        # Iterate and print each app in global apps list and get the corresponding data from the list converted to dict
        error_apps_list = []
        for url in file_apps_list:
            if ssllab_objs_csv.get(url):
                write_to_csv(csvdata=ssllab_objs_csv.get(url))
            else:
                error_apps_list.append(url)
                LOGGER.error(f"--------------UNEXPECTED error--- {url}")
        if error_apps_list:
            print(f'[-] {Fore.RED}Unexpected ERROR. Rerun the following URLs')
            print(Style.RESET_ALL)
            for eurl in error_apps_list:
                print(eurl)

    except Exception as e:
        LOGGER.error(e, exc_info=True)


def save_obj(obj, name):
    try:
        with open(name + '.pkl', 'wb') as f:
            pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)
    except Exception as e:
        LOGGER.error(e, exc_info=True)


def write_to_csv(csvdata="", heading=0):
    """
    Function that writes to output csv file
    :param csvdata: ssllab dict containing the data to be written
    :param heading: settin it to 1 writes the csv file header
    :return: None
    """
    try:
        writer = csv.writer(CSV_FILE)
        if heading:
            writer.writerow(csv_write_dict.keys())
        else:
            writer.writerow([csvdata[value] if value else "" for value in csv_write_dict.values()])
    except Exception as e:
        LOGGER.error(e, exc_info=True)


def internet_check():
    """
    Try getting duckduckgo.com. Incase of error there is no internet
    :return: false if no internet else true
    """
    global INTERNET_CON
    try:
        requests.head('https://duckduckgo.com', timeout=5)
        INTERNET_CON = True
        LOGGER.info("Internet is up")
        return True
    except (KeyboardInterrupt, SystemExit):
        print('\n! Received keyboard interrupt, quitting threads.\n')
        sys.exit()
    except Exception as e:
        LOGGER.error(f"No Internet {str(e)}")
        INTERNET_CON = False
    return False


def api_info():
    """
    Checks if API is up, exists if not Up
    :return: None
    """
    try:
        response = requests.get(API_INFO, timeout=10)
        response_json = json.loads(response.content)
        if response.status_code == 200 and response_json.get('criteriaVersion'):
            # print(response_json)
            print(f"[NOTICE] SSL Labs v{response_json.get('engineVersion')} "
                  f"(Criteria Cersion {response_json.get('criteriaVersion')})")
            print(f"[NOTICE] {response_json.get('messages')[0]}\n")
            LOGGER.info(f"[*] X-Max: {Fore.RED}{response_json.get('maxAssessments')}")
            LOGGER.info("SSL Lab API is up")
        else:
            print(f"[-]{Fore.RED}SSL Lab API is Down. Or maybe its your network connection.\n\n")
            sys.exit(0)
    except (KeyboardInterrupt, SystemExit):
        print('\n! Received keyboard interrupt, quitting threads.\n')
        sys.exit()
    except Exception as e:
        print(f"{Fore.RED}[-]SSL Lab API is Down. Or maybe its your network connection.\n\n")
        LOGGER.error(e, exc_info=True)
        sys.exit(0)


def handle_dict_error(ssl_dict):
    """
    Handles changing dict values to err. called if any error in scanning
    :param ssl_dict: ssllab_dict to write err to
    :return: None
    """
    # List of keys to avoid
    b_list = ['host', 'ip', 'status', 'status_msg', 'scan_result', 'return_code', 'headers',
              'scanned', 'retries', 'conn_error', 'scan_err']
    for key, value in ssl_dict.items():
        if key not in b_list:
            ssl_dict[key] = "Err"
    ssl_dict['scan_err'] = True
    ssl_dict['scanned'] = "Y"


def test_bit(num, offset):
    """
    Checks if a certain bit is set. required to check few parameters
    https://www.geeksforgeeks.org/check-whether-k-th-bit-set-not/
    :param num: the num to test
    :param offset: the bit to check
    :return: true is bit at offset is set else false
    """
    mask = 1 << offset
    return num & mask


def parse_scan_result(ssl_lab_dict):
    """
    This function is used to parse the data from the main dict.

    base = response['endpoints'][0]: This is used to reduce the length of the code.

    Something you will see throughout the function
    ssl_lab_dict['weak_sig'] = "Y" if "SHA1" in base.get('sigAlg') else ("N" if base.get('sigAlg') else "Err")
        It returns "Y" if the first condition is true ("Y" if "SHA1" in base.get('sigAlg')). Otherwise it returns the
        value it gets from the second expression(("N" if base.get('sigAlg') else "Err")). The "Err" part is used as a
        kind of error handling, just in case there is some issue with that certain parameter. It might never be used,
        but adding it just in case. Also the "Err" assigning is different in certain checks

    Check out the documentation (https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md) to better
    understand the parameters that are checked.

    :param ssl_lab_dict: The Dict containing the scan data
    :return: 0 in case of a error to exit from the func else None
    """
    response = ssl_lab_dict['scan_result']
    if not ssl_lab_dict['return_code']:
        ssl_lab_dict['return_code'] = response.get('status')

    # Setting the main parameters of url
    try:
        base = response.get('endpoints', "")
        if not base:
            LOGGER.error(f"No Endpoints. Access Error - {ssl_lab_dict['host']}", exc_info=True)
            raise AccessError
        else:
            base = base[0]
            ssl_lab_dict['status_msg'] = base.get('statusMessage', "Err")
            ssl_lab_dict['ip'] = base.get('ipAddress', 'Err')
            ssl_lab_dict['grade'] = base.get('grade', 'Err')
            ssl_lab_dict['sec_grade'] = base.get('gradeTrustIgnored', 'Err')

    except Exception as e:
        LOGGER.error(f"{e} - {ssl_lab_dict['host']}", exc_info=True)
        handle_dict_error(ssl_lab_dict)
        return 0  # If there is an error here then there is no point in proceeding. So exit

    # Certificate related issues
    try:
        base = response['certs'][0]
        if not base:
            LOGGER.debug(f"Access Error - {ssl_lab_dict['host']}")
            raise AccessError

        # cert trusted
        ssl_lab_dict['cert_trusted'] = "Y" if base.get('issues') == 0 else "N"

        # cert issuer
        issuer_sub = base.get('issuerSubject')
        if issuer_sub:
            issuer = ""
            for item in issuer_sub.split(','):
                issuer = item if "CN=" in item else ""
                break
            ssl_lab_dict['cert_issuer'] = issuer.split("CN=")[-1] if issuer else ""

        # valid from and valid till
        valid_from = base.get('notBefore')
        valid_till = base.get('notAfter')
        ssl_lab_dict['cert_valid_from'] = datetime.datetime.utcfromtimestamp(int(str(valid_from)[:10])).strftime('%d-%m-%Y')\
            if valid_from else ""
        ssl_lab_dict['cert_valid_till'] = datetime.datetime.utcfromtimestamp(int(str(valid_till)[:10])).strftime('%d-%m-%Y')\
            if valid_till else ""

        ssl_lab_dict['weak_sig'] = "Y" if "SHA1" in base.get('sigAlg') else ("N" if base.get('sigAlg') else "Err")
        ssl_lab_dict['commonNames'] = ",".join(value for value in base.get('commonNames')) \
            if base.get('commonNames') else ""
        ssl_lab_dict['alt_name'] = ",".join(value for value in base.get('altNames')) \
            if base.get('altNames') else ""
        ssl_lab_dict['thumbprint'] = base.get('sha1Hash', "Err")

        # Checking for weak key algorithm
        if "SA" in base.get('keyAlg') and base.get('keySize') < 2048:
            ssl_lab_dict['weak_priv_key'] = "Y"
        elif "EC" in base.get('keyAlg') and base.get('keySize') < 256:
            ssl_lab_dict['weak_priv_key'] = "Y"
        elif base.get('keyAlg', "Err") != "Err":
            ssl_lab_dict['weak_priv_key'] = "N"
        else:
            ssl_lab_dict['weak_priv_key'] = "Err"

        # Other Certificate Issues
        cert_issues = base.get('issues', "Err")
        if cert_issues != "Err":
            # Check of the domain is right on cert
            ssl_lab_dict['hostname_mismatch'] = "Y" if test_bit(cert_issues, 3) else \
                ("N" if base.get('sigAlg') else "Err")

            # Check is certificate has been revoked
            ssl_lab_dict['cert_revoked'] = "Y" if test_bit(cert_issues, 4) else "N"

            # Check if cert has expired
            if test_bit(cert_issues, 1) or test_bit(cert_issues, 2):
                ssl_lab_dict['cert_exp'] = "Y"
            else:
                ssl_lab_dict['cert_exp'] = "N"

            # Self Signed
            ssl_lab_dict['self_signed_cert'] = "Y" if test_bit(cert_issues, 6) else "N"
        else:
            ssl_lab_dict['hostname_mismatch'] = "Err"
            ssl_lab_dict['cert_exp'] = "Err"
            ssl_lab_dict['self_signed_cert'] = "Err"
            ssl_lab_dict['cert_revoked'] = 'Err'

    except Exception as e:
        LOGGER.error(f"{e}- {ssl_lab_dict['host']}", exc_info=True)
        handle_dict_error(ssl_lab_dict)
        return 0  # Exiting if there are no certs

    # Checking Common Issues/Vulnerabilities and version checks
    try:
        base = response['endpoints'][0]['details']
        if not base:
            LOGGER.debug(f"Access Error. Base is empty - {ssl_lab_dict['host']}")
            raise AccessError

        ssl_lab_dict['freak'] = "Y" if base.get('freak') else ("N" if not base.get('freak', "Err") else "Err")
        # Drown Error
        if not base.get('drownErrors'):
            ssl_lab_dict['drown'] = "Y" if base.get('drownVulnerable') else \
                                ("N" if not base.get('drownVulnerable', "Err") else "Err")
        else:
            ssl_lab_dict['drown'] = "Assessment Err"

        ssl_lab_dict['logjam'] = "Y" if base.get('logjam') else ("N" if not base.get('logjam', "Err") else "Err")
        ssl_lab_dict['poodle_ssl'] = "Y" if base.get('poodle') else ("N" if not base.get('poodle', "Err") else "Err")
        ssl_lab_dict['heartbleed'] = "Y" if base.get('heartbleed') \
            else ("N" if not base.get('heartbleed', "Err") else "Err")

        ssl_lab_dict['openSslCcs'] = "N"
        ssl_lab_dict['openSSLLuckyMinus20'] = "N"
        ssl_lab_dict['ticketbleed'] = "N"
        ssl_lab_dict['bleichenbacher'] = "N"
        ssl_lab_dict['zombiePoodle'] = "N"
        ssl_lab_dict['goldenDoodle'] = "N"
        ssl_lab_dict['zeroLengthPaddingOracle'] = "N"
        ssl_lab_dict['sleepingPoodle'] = "N"
        ssl_lab_dict['poodle_tls'] = "N"

        # Check Open SSL CCS
        if base.get('openSslCcs') == 3:
            ssl_lab_dict['openSslCcs'] = "Y"
        elif base.get('openSslCcs') == 1:
            ssl_lab_dict['openSslCcs'] = "N"
        elif base.get('openSslCcs') == -1:
            ssl_lab_dict['openSslCcs'] = "Fail"
        elif base.get('openSslCcs', 'Err') == 'Err':
            ssl_lab_dict['openSslCcs'] = "Err"

        # Check Golden Doodle
        if base.get('goldenDoodle') == 5 or base.get('goldenDoodle') == 4:
            ssl_lab_dict['goldenDoodle'] = "Y"
        elif base.get('goldenDoodle') == 1:
            ssl_lab_dict['goldenDoodle'] = "N"
        elif base.get('goldenDoodle') == -1:
            ssl_lab_dict['goldenDoodle'] = "Fail"
        elif base.get('goldenDoodle', 'Err') == 'Err':  # Can't Change to else as base.get might return other values
            ssl_lab_dict['goldenDoodle'] = "Err"

        # Check Poodle tls
        if base.get('poodleTls') == 2:
            ssl_lab_dict['poodle_tls'] = "Y"
        elif base.get('poodleTls') == 1:
            ssl_lab_dict['poodle_tls'] = "N"
        elif base.get('poodleTls') == -1:
            ssl_lab_dict['poodle_tls'] = "Fail"
        elif base.get('poodleTls', 'Err') == 'Err':  # Can't Change to else as base.get might return other values
            ssl_lab_dict['poodle_tls'] = "Err"

        # Check openSSLLuckyMinus20
        if base.get('openSSLLuckyMinus20') == 2:
            ssl_lab_dict['openssl_lucky'] = "Y"
        elif base.get('openSSLLuckyMinus20') == 1:
            ssl_lab_dict['openssl_lucky'] = "N"
        elif base.get('openSSLLuckyMinus20') == -1:
            ssl_lab_dict['openssl_lucky'] = "Fail"
        elif base.get('openSSLLuckyMinus20', 'Err') == 'Err':
            ssl_lab_dict['openssl_lucky'] = "Err"

        # Check ticketbleed
        if base.get('ticketbleed') == 2:
            ssl_lab_dict['ticketbleed'] = "Y"
        elif base.get('ticketbleed') == 1:
            ssl_lab_dict['ticketbleed'] = "N"
        elif base.get('ticketbleed') == -1:
            ssl_lab_dict['ticketbleed'] = "Fail"
        elif base.get('ticketbleed', 'Err') == 'Err':  # Can't Change to else as base.get might return other values
            ssl_lab_dict['ticketbleed'] = "Err"

        # Check bleichenbacher
        if base.get('bleichenbacher') == 2 or base.get('bleichenbacher') == 3:
            ssl_lab_dict['bleichenbacher'] = "Y"
        elif base.get('bleichenbacher') == 1:
            ssl_lab_dict['bleichenbacher'] = "N"
        elif base.get('bleichenbacher', 'Err') == -1:
            ssl_lab_dict['bleichenbacher'] = "Fail"
        elif base.get('bleichenbacher', 'Err') == 'Err':  # Can't Change to else as base.get might return other values
            ssl_lab_dict['bleichenbacher'] = "Err"

        # Check zombiePoodle
        if base.get('zombiePoodle') == 2 or base.get('zombiePoodle') == 3:
            ssl_lab_dict['zombiePoodle'] = "Y"
        elif base.get('zombiePoodle') == 1:
            ssl_lab_dict['zombiePoodle'] = "N"
        elif base.get('zombiePoodle', 'Err') == -1:
            ssl_lab_dict['zombiePoodle'] = "Fail"
        elif base.get('zombiePoodle', 'Err') == 'Err':  # Can't Change to else as base.get might return other values
            ssl_lab_dict['zombiePoodle'] = "Err"

        # Check zeroLengthPaddingOracle
        if base.get('zeroLengthPaddingOracle') == 6 or base.get('zeroLengthPaddingOracle') == 7:
            ssl_lab_dict['zeroLengthPaddingOracle'] = "Y"
        elif base.get('zeroLengthPaddingOracle') == 1:
            ssl_lab_dict['zeroLengthPaddingOracle'] = "N"
        elif base.get('zeroLengthPaddingOracle', 'Err') == -1:
            ssl_lab_dict['zeroLengthPaddingOracle'] = "Fail"
        elif base.get('zeroLengthPaddingOracle', 'Err') == 'Err':
            ssl_lab_dict['zeroLengthPaddingOracle'] = "Err"

        # Check sleepingPoodle
        if base.get('sleepingPoodle') == 10 or base.get('sleepingPoodle') == 11:
            ssl_lab_dict['sleepingPoodle'] = "Y"
        elif base.get('sleepingPoodle') == 1:
            ssl_lab_dict['sleepingPoodle'] = "N"
        elif base.get('sleepingPoodle', 'Err') == -1:
            ssl_lab_dict['sleepingPoodle'] = "Fail"
        elif base.get('sleepingPoodle', 'Err') == 'Err':  # Can't Change to else as base.get might return other values
            ssl_lab_dict['sleepingPoodle'] = "Err"

        # Check if insecure regen is enabled. Check ssl documentation for better understanding
        regenvar = base.get('renegSupport', 'Err')
        if regenvar != "Err":
            ssl_lab_dict['insec_reneg'] = "Y" if test_bit(regenvar, 0) else "N"
            ssl_lab_dict['sec_reneg'] = "Y" if test_bit(regenvar, 1) else "N"
        else:
            ssl_lab_dict['insec_reneg'] = 'Err'
            ssl_lab_dict['sec_reneg'] = 'Err'

        # SSL/TLS Version check
        ssl_lab_dict['ssl2'] = "N"
        ssl_lab_dict['ssl3'] = "N"
        ssl_lab_dict['tls1.0'] = "N"
        ssl_lab_dict['tls1.1'] = "N"
        ssl_lab_dict['tls1.2'] = "N"
        ssl_lab_dict['tls1.3'] = "N"
        ssl_lab_dict['ssl2_disabled'] = "NA"
        if base.get('protocols'):
            for protocol in base.get('protocols'):
                if "SSL" in protocol.get('name'):
                    if protocol.get('version') == "2.0":  # no string interning for 2.0
                        ssl_lab_dict['ssl2'] = "Y"
                        if protocol.get('v2SuitesDisabled'):
                            ssl_lab_dict['ssl2_disabled'] = "Y"
                        else:
                            ssl_lab_dict['ssl2_disabled'] = "N"

                    if protocol.get('version') == "3.0":
                        ssl_lab_dict['ssl3'] = "Y"

                if "TLS" in protocol.get('name'):
                    if protocol.get('version') == "1.3":
                        ssl_lab_dict['tls1.3'] = "Y"
                    elif protocol.get('version') == "1.2":
                        ssl_lab_dict['tls1.2'] = "Y"
                    elif protocol.get('version') == "1.1":
                        ssl_lab_dict['tls1.1'] = "Y"
                    elif protocol.get('version') == "1.0":
                        ssl_lab_dict['tls1.0'] = "Y"

        else:
            ssl_lab_dict['ssl2'] = "Err"
            ssl_lab_dict['ssl3'] = "Err"
            ssl_lab_dict['tls1.3'] = "Err"
            ssl_lab_dict['tls1.2'] = "Err"
            ssl_lab_dict['tls1.1'] = "Err"
            ssl_lab_dict['tls1.0'] = "Err"

        # Check if insecure/weak suite is used
        ssl_lab_dict['insec_suite'] = "N"
        if base.get('suites'):
            for suit in base.get('suites')[0].get('list'):
                if suit.get('q') == 0 or suit.get('q') == 1:
                    ssl_lab_dict['insec_suite'] = "Y"
        else:
            ssl_lab_dict['insec_suite'] = "Err"

        # RC4 checks
        ssl_lab_dict['rc4'] = "Y" if base.get('supportsRc4') else ("N" if not base.get('supportsRc4', "Err") else "Err")
        ssl_lab_dict['rc4_only'] = "Y" if base.get('rc4Only') else ("N" if not base.get('rc4Only', "Err") else "Err")

        # Forward Secrecy check
        frwd_secrecy = base.get('forwardSecrecy', 'Err')
        if frwd_secrecy != "Err":
            ssl_lab_dict['forwardSecrecy'] = "Y" if test_bit(frwd_secrecy, 2) else "N"
        else:
            ssl_lab_dict['forwardSecrecy'] = "Err"

        # Check CRIME
        if base.get('compressionMethods') and not base.get('supportsNpn'):
            ssl_lab_dict['crime'] = "Y"
        else:
            ssl_lab_dict['crime'] = "N"

    except Exception as e:
        LOGGER.error(f"{e} - {ssl_lab_dict['host']}", exc_info=True)

    # Check Certificate chaining issues
    try:
        base = response['endpoints'][0]['details']['certChains'][0]
        cert_issue_var = base.get('issues', 'Err')
        if cert_issue_var != "Err":
            if test_bit(cert_issue_var, 0):
                ssl_lab_dict['cert_chain_issue'] = "Y"
            else:
                ssl_lab_dict['cert_chain_issue'] = "N"
                if test_bit(cert_issue_var, 1):
                    ssl_lab_dict['cert_chain_incomp'] = "Y"
                else:
                    ssl_lab_dict['cert_chain_incomp'] = "N"

        else:
            ssl_lab_dict['cert_chain_issue'] = "Err"
            ssl_lab_dict['cert_chain_issue'] = "Err"

    except Exception as e:
        LOGGER.error(f"{e} - {ssl_lab_dict['host']}", exc_info=True)


def handle_api_error(response):
    """
    Handles errors if API returns a non 200 response and sleeps if required.
    This function was taken from a sslab test script I found on github. It has a very nice way of handling API errors.
    :param response: The non 200 response received from API
    :return: None
    """
    try:
        global concur_errors
        status = response.status_code
        # Errors are joined with a ;
        error_message = '; '.join('{}{}{}'.format(error.get('field') or '',
                        ': ' if error.get('field') else '', error.get('message') or 'Unknown error')
                        for error in response.json().get('errors') or ()) or response.text

        if status == 400:
            LOGGER.warning(f'[API] invocation error: {error_message}')
            time.sleep(random.randint(5, 15))
        elif status == 429:
            LOGGER.warning(f'[API] client request rate too high or too many new assessments too fast: {error_message}')
            x_max = response.headers.get('X-Max-Assessments')
            x_cur = response.headers.get('X-Current-Assessments')
            if x_max and x_cur:
                if not (int(x_max) - int(x_cur)):
                    with threadLock:
                        concur_errors += 1
                    LOGGER.error(f"Limit Reached. Sleeping for Random time")
                    time.sleep(random.randint(30, 180))
                else:
                    time.sleep(random.randint(5, 15))
        elif status == 500:
            LOGGER.warning(f'[API] internal error: {error_message}')
            time.sleep(random.randint(5, 15))
        elif status == 503:
            LOGGER.warning(f'[API] the service is not available: {error_message}')
        elif status == 529:
            LOGGER.warning(f'[API] the service is overloaded: {error_message}')
            time.sleep(random.randint(5, 15))
        else:
            LOGGER.warning(f'[API] unknown status code: {status} {error_message}')
            time.sleep(random.randint(5, 15))
    except (KeyboardInterrupt, SystemExit):
        print('\n! Received keyboard interrupt, quitting threads.\n')
        sys.exit()
    except Exception as e:
        LOGGER.error(e, exc_info=True)


def analyze_url(url, ssl_lab_dict, params, initiate=0):
    """
    This function makes the calls to ssl API and gets the progress status.
    Added a sleep function if there is no internet connection
    ssl_lab_dict['conn_error'] < 5:     This is parameter used to make sure that atleast 10 retries are made incase
                                        of a conn error


    :param url: The url to scan
    :param ssl_lab_dict: The main dict that will be used for storing data for this url
    :param params: The parameters that are sent along with the request. Can be initiate, cache or get data
    :param initiate: This parameter is set to 1 when the request to initiate the scan is send. This is required to
                        return initiated status when the api returns 200 response. Essentially it is used to
                        differentiate between scan initiated and in progress message
    :return: 1 if scan was successful/initiated else 0
    """
    # Pause if there is no internet connection
    while not INTERNET_CON:
        # print(INTERNET_CON, url)
        LOGGER.debug(f"No Internet conn. Sleeping for some time. - {url}")
        time.sleep(random.randint(30, 240))

    params['host'] = url
    ssl_lab_dict['host'] = url
    try:
        response = requests.get(API_ANALYZE, params=params, timeout=10)
        LOGGER.debug(f"Got URL status {url}")
        if response.status_code != 200:
            handle_api_error(response)
            # time.sleep(20)
            return 0
        elif response.status_code == 200 and initiate:  # If initiate is set, return 1 if we get 200 response.
            return 1
        response_json = json.loads(response.content)
        status = response_json.get('status')

        LOGGER.debug(f'{url} status {status}')
        if status and ("READY" in status or "ERROR" in status):  # Scan successful. Set values and return 1
            ssl_lab_dict['scanned'] = "Y"
            ssl_lab_dict['scan_result'] = response_json
            ssl_lab_dict['headers'] = response.headers

            if status == "ERROR":
                ssl_lab_dict['status_msg'] = response_json.get('statusMessage')
                ssl_lab_dict['scan_err'] = True
            LOGGER.info(f'{url} Scan complete')
            return 1
        else:
            time.sleep(25)  # Scan IN PROGRESS. Sleep for 25 and retry
            return 0
    except requests.exceptions.ConnectionError:  # Conn Error seems to be common. So catch it and retry 5 times
        if ssl_lab_dict['conn_error'] < 5:
            LOGGER.error(f"Conn Error. Increasing Counter {url}")
            ssl_lab_dict['conn_error'] += 1
            time.sleep(random.randint(5, 15))
            return 0
        else:
            LOGGER.error(f"Conn Error Count exceeded. Skipping {url}", exc_info=True)
            handle_dict_error(ssl_lab_dict)
            ssl_lab_dict['return_code'] = "Conn Err"
            ssl_lab_dict['status_msg'] = "Could not connect to API"
            ssl_lab_dict['scan_err'] = True
            return 1
    except requests.exceptions.Timeout:
        LOGGER.error(f"Timeout Error --- {url}", exc_info=True)
        return 0
    except (KeyboardInterrupt, SystemExit):
        print('\n! Received keyboard interrupt, quitting threads.\n')
        sys.exit()
    except Exception as e:
        LOGGER.error(f"{e}{url}", exc_info=True)
        handle_dict_error(ssl_lab_dict)
        ssl_lab_dict['return_code'] = "Unknown Error"
        ssl_lab_dict['status_msg'] = "Unknown Error"
        ssl_lab_dict['scan_err'] = True
        LOGGER.error("Unknown error details", exc_info=True)
        return 1


def run_ssl(url):
    """
    This is  a wrapper function that is called by the Thread.
    It will initiate the scan and then keep making requests until it gets the scan data.
    There are two calls to analyze(). First one to initiate the scan and the second one to get data.

    ssl_lab_dict['retries'] :   This is a protection mechanism in case the func keeps on failing to start the scan.
                                This param will make sure that the func doesn't try more than 10(default) times to start
                                the scan. Now i have diabled it in analyze to make sure that long running urls complete
    ssllab_objs[]           :   This is a list that will contain all the dict objects.
                                Planning to use it for heartbeat. Edit:Used it

    :param url: the url of the application to scan
    :return: None
    """
    global SCANNED, ERRORS
    try:
        time.sleep(random.randint(5, 60))  # Sleeping for arbitrary time to slow down requests
        start = time.time()
        ssl_lab_dict = dict(SSLLabDomain_Dict)

        initiated = 0  # Will keep on initiating until we get 200 response
        while not initiated and ssl_lab_dict['retries']:
            LOGGER.debug(f'{url} Initiating')
            if FROM_CACHE:
                initiated = analyze_url(url, ssl_lab_dict, cache_params, initiate=1)
            else:
                initiated = analyze_url(url, ssl_lab_dict, new_params, initiate=1)
            ssl_lab_dict['retries'] -= 1

        # Sleep for 25 before polling status
        time.sleep(25)

        # ssl_lab_dict['retries'] = 30  # Resetting the counter for retries
        scanned = 0  # WIll keep on requesting until we get scan data
        while not scanned:  # and ssl_lab_dict['retries']:
            LOGGER.debug(f"Polling Scan status in while loop {url}")
            scanned = analyze_url(url, ssl_lab_dict, get_data)
            # ssl_lab_dict['retries'] -= 1

        parse_scan_result(ssl_lab_dict)  # The function that parses the received data.
    except Exception as e:
        LOGGER.error(f"{str(e)}{url}", exc_info=True)

    # Separating append into a different try to make sure that this part is not skipped
    try:
        # Locking thread, as increment is not thread safe. (I didn't know that increment could be non atomic)
        # https://stackoverflow.com/questions/35088139/how-to-make-a-thread-safe-global-counter-in-python
        if ssl_lab_dict['scanned'] == "Y":
            with threadLock:
                SCANNED += 1
        if ssl_lab_dict['scan_err']:
            with threadLock:
                ERRORS += 1
        with threadLock:
            ssllab_objs.append(ssl_lab_dict)  # Adding the dict into a list. Not locking because .append is thread safe.
            # But i am blocking it now

        LOGGER.debug(f'{url} took {time.time()-start}')
        urltime_objs.append(time.time()-start)
    except (KeyboardInterrupt, SystemExit):
        print('\n! Received keyboard interrupt, quitting threads.\n')
        sys.exit()
    except Exception as e:
        LOGGER.error(f"{str(e)}{url}", exc_info=True)


def parse_arguments():
    """
    https://stackoverflow.com/questions/24180527/argparse-required-arguments-listed-under-optional-arguments
    :return: Parser Namespace
    """
    from argparse import ArgumentParser
    parser = ArgumentParser()
    optional_args = parser._action_groups.pop()
    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument('-i', '--input', help='The input file with list of URLs', required=True)
    required_args.add_argument('-o', '--output', help='Output csv file', required=True)

    #  Optional Arguments
    optional_args.add_argument('-c', '--cache', help='Use Cached Data from SSL LAB',
                               required=False, action='store_true')
    optional_args.add_argument('-b', '--heartbeat', help='Interval between status report',
                               required=False)
    optional_args.add_argument('-w', '--write', help='Application Number Threshold to write to backup file',
                               required=False)
    optional_args.add_argument('-t', '--threads', help='Set the number of threads', required=False)
    optional_args.add_argument('-v', action='store_const', dest='level', default=0, const=3,
                               help='Verbose Logging level:INFO', required=False)
    optional_args.add_argument('-d', action='store_const', dest='level', default=0, const=4,
                               help='Verbose Logging level:DEBUG', required=False)
    parser._action_groups.append(optional_args)
    return parser.parse_args()


def create_task_generator(urls):
    """
    A lazy generator to save memory. It will give the url tasks one by one to main without keeping everything in memory
    :param urls: the list of urls to create task for
    :return: function that can be called to get the url output
    """
    for url in urls:
        def inner(url=url):
            return run_ssl(url)
        yield inner


def main():
    """
    Main function that calls everything.
    :return: None
    """
    global FROM_CACHE
    global HEARTBEAT
    global WRITE_TO_BACKUP
    global THREADS
    global CSV_FILE
    global file_apps_list

    try:
        cli_args = parse_arguments()
        CSV_FILE = cli_args.output
        if cli_args.cache:
            FROM_CACHE = True
        if cli_args.heartbeat:
            HEARTBEAT = cli_args.heartbeat
        if cli_args.write:
            WRITE_TO_BACKUP = cli_args.write
        if cli_args.threads:
            THREADS = cli_args.threads
        if cli_args.level:
            fh.setLevel(levels[cli_args.level])

        welcome()   # Prints welcome message
        api_info()  # Check if api is up

        # Count no of urls and add it to global list
        with open(cli_args.input) as f:
            for total_count, l in enumerate(f):
                pass
        total_count += 1
        print(f'[+] {total_count} URLS Loaded\n')

        CSV_FILE = open(cli_args.output, 'w', newline='')
        write_to_csv(heading=1)

        url_file = open(cli_args.input, 'r')
        start = time.time()
    except Exception as e:
        LOGGER.error(e)
        print(f"{Fore.RED}[-] Critical Error.\n{e}\n[-] Exiting....\n")
        sys.exit(-1)

    # ------------------------------------------------
    # Threadpool executor that launches the task
    # inspired by https://alexwlchan.net/2019/10/adventures-with-concurrent-futures/
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        try:
            futures_set = set()
            file_apps_list = [ssl_url.strip() for ssl_url in url_file.readlines()]
            urls_generator = (url for url in file_apps_list)
            task_generator = create_task_generator(file_apps_list)
            pool.submit(heartbeat, total_count, pool)
            for task in itertools.islice(task_generator, THREADS+2):
                futures_obj = pool.submit(task)
                futures_obj.url = next(urls_generator)
                # futures_obj.add_done_callback(done_action)
                futures_set.add(futures_obj)

            while futures_set:
                # print(futures_set)
                # print(THREADS_COMPLETE)
                done, futures_set = concurrent.futures.wait(futures_set, return_when=concurrent.futures.FIRST_COMPLETED)
                LOGGER.debug(f"Incomplete URLS THREADS -- {futures_set}")
                # Schedule the next set of futures.  We don't want more than N futures
                # in the pool at a time, to keep memory consumption down.

                for task in itertools.islice(task_generator, len(done)):
                    futures_obj = pool.submit(task)
                    futures_obj.url = next(urls_generator)
                    # futures_obj.add_done_callback(done_action)
                    futures_set.add(futures_obj)

        except (KeyboardInterrupt, SystemExit):
            print(f'{Fore.LIGHTBLUE_EX}\n!!!!{Fore.RED} Received keyboard interrupt,{Fore.LIGHTRED_EX} '
                  f'Quitting threads and {Fore.LIGHTGREEN_EX}Cleaning Up {Fore.LIGHTBLUE_EX}!!!!\n{Fore.RESET}')
            pool.shutdown(wait=False)
            HEARTBEAT = 0
            sys.exit()
        except Exception as e:
            LOGGER.critical(f"------Critical error in main thread ------{e}", exc_info=True)

        # THis will hopefully exit the heartbeat function.
        HEARTBEAT = 0
    # --------------------------------------------------
    LOGGER.info(f'Total time {time.time() - start}')
    LOGGER.debug(f"Total Concur Error: {concur_errors}")
    for obj in ssllab_objs:
        obj['scan_result'] = "Gone"
        obj['headers'] = "Gone"

    t_sum = 0
    for t in urltime_objs:
        t_sum += t
    LOGGER.info(f'Sum of url urltime_objs {t_sum}')
    print("\n[+] Scan Completed\n")


if __name__ == "__main__":
    main()
