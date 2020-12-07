"""
Copyright [2020] [Cisco Systems]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import sys
import time
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable HTTP warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# logging format, for now logging on stdout but can be directed to a file too
logging.basicConfig(format='%(asctime)s - %(message)s',
                    datefmt='%a %b %d %H:%M:%S %Y', level=logging.INFO)

fmc_token = None

config = {
    'host':      'ful1056-pod',
    'username':  'admin',
    'password':  '',
    'files': set()
}


class Token(object):
    """The token is needed to interact with the FMC APIs."""
    MAX_REFRESHES = 3
    TOKEN_LIFETIME = 29 * 60
    API_PLATFORM_VERSION = "api/fmc_platform/v1"

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.uuid = None
        self.verify_cert = False
        self.token_refreshes = 0
        self.access_token = None
        self.refresh_token = None
        self.token_creation_time = None
        self.generate_token()

    def generate_token(self):
        """
        Create new or refresh expired tokens.
        :return: None
        """
        logging.info("generating token")

        if self.token_refreshes <= self.MAX_REFRESHES and self.access_token is not None:
            headers = {
                "Content-Type": "application/json",
                "X-auth-access-token": self.access_token,
                "X-auth-refresh-token": self.refresh_token,
            }
            url = f"https://{self.host}/{self.API_PLATFORM_VERSION}/auth/refreshtoken"

            logging.info(
                f"Refreshing tokens, {self.token_refreshes} out of {self.MAX_REFRESHES} refreshes, "
                f"from {url}."
            )
            response = requests.post(url, headers=headers, verify=False)
            logging.info(
                "Response from refreshtoken() post:\n"
                f"\turl: {url}\n"
                f"\theaders: {headers}\n"
                f"\tresponse: {response}"
            )
            self.token_refreshes += 1
        else:
            # generate new token
            self.token_refreshes = 0
            self.token_creation_time = datetime.datetime.now()
            headers = {"Content-Type": "application/json"}
            url = f"https://{self.host}/{self.API_PLATFORM_VERSION}/auth/generatetoken"
            logging.info(f"Requesting new tokens from {url}.")
            response = requests.post(
                url,
                headers=headers,
                auth=requests.auth.HTTPBasicAuth(self.username, self.password),
                verify=False
            )

        self.access_token = response.headers.get("X-auth-access-token")
        self.refresh_token = response.headers.get("X-auth-refresh-token")
        self.uuid = response.headers.get("DOMAIN_UUID")

        logging.info(
            "Result of generate token:\n"
            f"\taccess_token: {self.access_token}\n"
            f"\trefresh_token: {self.refresh_token}\n"
            f"\tuuid: {self.uuid}"
        )

    def get_token(self):
        """
        Check validity of current token. If needed make a new or refresh the existing token.
        :return self.access_token
        """
        if datetime.datetime.now() > (
            self.token_creation_time
            + datetime.timedelta(seconds=self.TOKEN_LIFETIME)
        ):
            logging.info("Token about to expire.  Generate a new token.")
            self.token_refreshes = 0
            self.access_token = None
            self.refresh_token = None
            self.generate_token()
        return self.access_token

def getAuthorInfo():
    logging.info('yatisjos@cisco.com')

def makeAPICall(url):
    """
    Makes an API call and returns the next page if it exists
    """
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': fmc_token.get_token()
    }

    response = requests.get(url, headers=headers, verify=False)
    response_dict = json.loads(response.text)
    
    if 'next' in response_dict['paging']:
        url = response_dict['paging']['next'][0]
        logging.info(f"Next page:{url}")
    else:
        logging.info("No next page, so we are done processing")
        url = None

    return response_dict['items'], url


def getHealthMetrics():
    """
    Next TODO: Get health Metrics
    """
    # make call
    # url = f"https://{fmc_token.host}/api/fmc_config/v1/domain/{fmc_token.uuid}/health/alerts?expanded=true
    #logging.info(f"Request: {url}")

def deleteFile(fileName):
    
    MYDIR = config['host'].split(":")
    MYDIR1 = MYDIR[0]
    fileName=MYDIR1 +'/'+fileName
    if os.path.exists(fileName):
        os.remove(fileName) 
        logging.info('Removing file ' + fileName)

def writeToFile(fileName, data, append=False):
    logging.info('Saving file' + fileName)

    MYDIR = config['host'].split(":")
    print(MYDIR)
    MYDIR1=MYDIR[0]
    print(MYDIR1)
    CHECK_FOLDER = os.path.isdir(MYDIR1)

    # If folder doesn't exist, then create it.
    if not CHECK_FOLDER:
        os.makedirs(MYDIR1)
        logging.info("created folder : ", MYDIR1)

    with open(MYDIR1+'/'+fileName, 'a') as f:
        f.write(data + '\n')
        f.close()

def getHealthAlerts():
    """
    Get health alerts
    """
    if not getVersion():
        return False
    
    logging.info("Getting Health Alerts")
    deleteFile("healthAlerts")

    # make call
    url = f"https://{fmc_token.host}/api/fmc_config/v1/domain/{fmc_token.uuid}/health/alerts?expanded=true"
    logging.info(f"Request: {url}")

    # keep paging through the values until you run out of pages
    while url:
        # check the response back from FMC API
        response, url = makeAPICall(url)
        logging.info("Response: "+json.dumps(response, indent=2))
        writeToFile('healthAlerts', json.dumps(response, indent=2), append=True)
        return response

def getServerVersion():
    """
    Get ServerVersion
    """
    logging.info("Getting Server Version")
    deleteFile("serverVersion")

    # make call
    url = f"https://{fmc_token.host}/api/fmc_platform/v1/info/serverversion?expanded=true"
    logging.info(f"Request: {url}")

    response, url = makeAPICall(url)
    logging.info("Response: "+json.dumps(response, indent=2))
    writeToFile('serverVersion', json.dumps(response, indent=2))
    return response

def getDeviceRecords():
    """
    Get DeviceRecords
    """
    logging.info("Getting Device Records")

    # make call
    url = f"https://{fmc_token.host}/api/fmc_config/v1/domain/{fmc_token.uuid}/devices/devicerecords?expanded=true"
    logging.info(f"Request: {url}")

    deleteFile("deviceRecords")
    # keep paging through the values until you run out of pages
    while url:
        # check the response back from FMC API
        response, url = makeAPICall(url)
        logging.info("Response: "+json.dumps(response, indent=2))
        writeToFile('deviceRecords', json.dumps(response, indent=2),append=True)

def parse_arguments(args=None):
    """
    Functionality: Parses the input parameters supplied to the script when its called.
    --host: Supply the host IP
    --user: FMC user name
    --password: FMC password
    Output: None
    """

    parser = argparse.ArgumentParser(
        description='FMC script to extract health data')
    parser.add_argument('--host', required=True, help='FMC IP')
    """parser.add_argument('--username', required=True, help='FMC user name')
    parser.add_argument('--password', required=True, help='FMC password')
    """
    parsed_args = vars(parser.parse_args(args))

    for key in parsed_args.keys():
        config[key] = parsed_args.get(key)
    
    config['username'] = os.environ.get('username')
    config['password'] = os.environ.get('password')

def initToken():
    global fmc_token
    fmc_token = Token(host=config['host'], username=config['username'], password=config['password'])

def getVersion():
    response=getServerVersion()
    logging.info("Response: "+json.dumps(response, indent=2))
    version = response[0]['serverVersion']

    if '6.6.0' in version:
        return False
    elif '6.5.0' in version:
        return False
    elif '6.4.0'  in version:
        return False
    elif '6.3.0'  in version:
        return False
    elif '6.2.0' in version:
        return False

    logging.info("True")
    return True

def main():
    """
    Functionality: Everything kicks off from here
    """
    logging.info("Starting Firepower Device Health statstics Script")
    parse_arguments()
    initToken()
    getHealthAlerts() #6.7 onwards only
    getServerVersion()
    getDeviceRecords()
    logging.info("End Of script")


if __name__ == "__main__":
    sys.exit(main())
