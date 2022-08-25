####################################
#                                  #
#   Author : Krushi Vasani         #
#                                  #
####################################

import argparse
from datetime import date
import http
import json
import os
import sys
import time
import subprocess as sp
from unicodedata import name
import uuid
import warnings
from getpass import getpass, getuser
from urllib.parse import parse_qs, urlparse
import jwt
import requests
import re
from pathlib import Path
from bs4 import BeautifulSoup
from jira.client import JIRA

warnings.filterwarnings(action="ignore", category=ResourceWarning)
warnings.filterwarnings(action='ignore', message='Unverified HTTPS request')

parser = argparse.ArgumentParser()

parser.add_argument('-s', '--stack',
                    help='Stack name',
                    required=True)

parser.add_argument('-t', '--target',
                    help=' Target name (Example: sh1,c0m1,idm1,indexer,shc1',
                    required=True)

parser.add_argument('-j', '--jira',
                    help='Jira ticket (Example: TO-16301)',
                    required=True)

package=[]
AD_USER = getuser()
SHELL_PATH = os.environ['PATH']
HOME_PATH = os.environ['HOME']
# print("Take backup:\n1. Using EBTOOL\n2. Package ID\n")
choice = input("Take backup:\n1. Using EBTOOL\n2. App Specific\n3. Exit \n")
if choice == '2':
            package = input("Enter Package ID : ").split(',')
print("Your username is " + AD_USER)


JIRA_SERVER = "https://splunk.atlassian.net"
args = parser.parse_args()

# Arguments
STACK = args.stack
BACKUP_NODES = args.target

# Strings
POST_DOMAIN = ".splunkcloud.com"
SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/"
JIRA_ID = "KRUSHI"
CO2_ENV = ""
VAULT_TOKEN = ""
SHC_MEMBER = ""
ADMIN_VAULT_PASS = ""

# Dictionaries
co2_instances = {}
instance_dict={}

# Lists
BACKUP_NODESS =[]

if args.jira is not None:
    JIRA_ID = args.jira

VAULT_ADDR = "https://vault.splunkcloud.systems"
VAULT_PATH = "/v1/cloud-sec-lve-ephemeral/creds/"

AD_PASSWORD = getpass(prompt='Enter your AD_PASSWORD: ', stream=None)


OKTA_PASSWORD = getpass(
    prompt='OKTA_PASSWORD (If it is the same as AD_PASSWORD, just press Enter): ', stream=None)

if OKTA_PASSWORD == '':
    OKTA_PASSWORD = AD_PASSWORD
       
# read JIRA_TOKEN from ~/.jira/token file
JIRA_TOKEN = ""
try:
    with open('/Users/' + AD_USER + '/.jira/token', "r") as jira_token_read:
        JIRA_TOKEN = jira_token_read.read().strip()
except FileNotFoundError as fe:
    JIRA_TOKEN = getpass(prompt='Enter your JIRA_TOKEN: ', stream=None)
    if ".jira" not in os.listdir('/Users/' + AD_USER):
        os.mkdir('/Users/' + AD_USER + '/.jira/')
    with open('/Users/' + AD_USER + '/.jira/token', "w") as jira_token_write:
        jira_token_write.write(JIRA_TOKEN)

EMAIL_ID = (AD_USER + '@splunk.com')

if POST_DOMAIN == ".splunkcloud.com":
    CO2_ENV = "prod"
    CO2APIENDPOINT = "https://api.co2.lve.splunkcloud.systems"
    
try:
    setEnv = str(os.popen('cloudctl config use ' +
                    CO2_ENV + ' 2>&1').read())
except Exception as e:
    print(e)
    
print("CO2 Configuration:\n" + setEnv + "##########")

def co2_check_token():
    token_file = HOME_PATH + '/.cloudctl/token_' + CO2_ENV
    try:
        if os.path.exists(token_file):
            if os.path.getsize(token_file) > 0:
                with open(token_file, 'r') as content_file:
                    token = content_file.read()
                decodedToken = jwt.decode(
                    token, options={"verify_signature": False})
                jsonToken = json.dumps(decodedToken)
                tokenExpireTime = json.loads(jsonToken)["exp"]
                currentTime = int(time.strftime("%s"))
                difference = tokenExpireTime - currentTime
                if difference > 60:
                    return True

    except Exception as e:
        print(e)

    return False



def co2_login():
    while co2_check_token() is not True:
        token_file = HOME_PATH + '/.cloudctl/token_' + CO2_ENV 
        print("SplunkCloud: Logging into CO2")

        try:
            header = {'Accept': 'application/json',
                      'Content-Type': 'application/json', 'Cache-Control': 'no-cache'}
            login_url = "https://splunkcloud.okta.com/api/v1/authn"
            login_payload = {'username': AD_USER, 'password': AD_PASSWORD}

            login_response = requests.post(
                login_url, headers=header, json=login_payload)

            if login_response.status_code != 200:
                raise Exception()

            login_response_json = json.loads(login_response.text)
            stateToken = str(login_response_json['stateToken'])
            push_verification_link = str(
                login_response_json['_embedded']['factors'][0]['_links']['verify']['href'])

            push_url = push_verification_link
            push_payload = {'stateToken': stateToken}
            push_response_json = ''

            while True:
                push_response = requests.post(
                    push_url, headers=header, json=push_payload)

                if push_response.status_code != 200:
                    raise Exception()

                push_response_json = json.loads(push_response.text)
                auth_status = str(push_response_json['status'])

                if auth_status == "SUCCESS":
                    break

                time.sleep(0.5)

            session_token = str(push_response_json['sessionToken'])

            with open(HOME_PATH + "/.cloudctl/config.yaml", 'r') as cloudctl_config:
                configs = cloudctl_config.readlines()

            for config in configs:

                if "idpclientid" in config:
                    client_id = config.split(": ")[1].rstrip('\n')

                if "idpserverid" in config:
                    server_id = config.split(": ")[1].rstrip('\n')

            access_token_url = "https://splunkcloud.okta.com/oauth2/" + server_id + "/v1/authorize?client_id=" + client_id + "&nonce=" + str(uuid.uuid4()) + \
                "&prompt=none&redirect_uri=https%3A%2F%2Fdoes.not.resolve%2F&response_type=token&scope=&sessionToken=" + \
                session_token + "&state=not.used"
            access_token_response = requests.get(
                access_token_url, allow_redirects=False)

            if access_token_response.status_code != 302:
                raise Exception()

            parsed_access_token_header = urlparse(
                access_token_response.headers['location'])
            access_token = parse_qs(parsed_access_token_header.fragment)[
                'access_token'][0]

            with open(token_file, 'w') as token_f:
                token_f.write(access_token)

        except Exception as e:
            print("\nSplunkCloud: Failed to log into CO2\n" + e)

def get_vault_token():
    """
    Function to get the vault API token
    """
    # will store token as global variable to reuse for all calls to vault
    global VAULT_TOKEN
    # URL to hit the vault auth okta endpoint
    url = VAULT_ADDR + '/v1/auth/okta/login/' + AD_USER
    payload = '{"password": "' + OKTA_PASSWORD + '"}'

    try:
        print("Vault: Sending 2FA prompt to your phone now...")
        vault_token_json = requests.post(url, data=payload)
        print("Vault: Verification received. Checking Status")

        if vault_token_json.status_code != 200:
            raise Exception(
                'Failed to get Vault Token. Check for your password and try again.')

    except Exception as e:
        print(e)
        print(' ...Exiting... ')
        quit()

    vault_token_json = json.loads(vault_token_json.text)
    VAULT_TOKEN = str(vault_token_json['auth']['client_token'])
    with open("/Users/" + AD_USER + "/.vault-token", "w") as fvault:
        fvault.write(VAULT_TOKEN)

    print("Vault: Authenticated!\n##########")

def check_vault_login():
    now = time.time()
    current = Path.home()
    token_path = current.joinpath(".vault-token")
    print(token_path)
    try:
        mod_time = os.stat(token_path).st_mtime
        file_size = os.stat(token_path).st_size
    except Exception as e:
        print("unable to get token time and size.", e)
        mod_time = 0
        file_size = 0
    file_age = now - mod_time
    if file_size != 0 and file_age < 28800:
        global VAULT_TOKEN
        f = open(str(token_path), "r")
        VAULT_TOKEN = f.read()
        f.close()
        print("Vault: Already Authenticated!\n##########")
    else:
        try:
            print("Vault login")
            get_vault_token()
        except Exception as e:
            raise RuntimeError(f'Unable to logged in into "Vault" ({e})')

try:
    check_vault_login()
    co2_login()

except Exception as e:
    print(e)
    quit()

def get_token():
  f = open(str(Path.home())+"/.cloudctl/token_"+ CO2_ENV, "r")
  return f.read()

try:
    res = requests.get(CO2APIENDPOINT+"/v3/stacks/"+STACK+"/instances", headers={"authorization": "Bearer "+get_token().strip()})	
    co2_instances = res.json()	
except Exception as e:
    print(e)
    quit()

try:
    token_request = requests.post("https://splunkbase.splunk.com/api/account:login/",
                                  data=[('username', AD_USER + '@splunk.com'), ('password', AD_PASSWORD)])
except Exception as e:
    print(e)
    quit()

if token_request.status_code == 200:
    SPLUNKBASE_TOKEN = (BeautifulSoup(
        token_request.text, "html.parser")).feed.id.text
else:
    print("Failed to get Splunkbase Token... Check AD_PASSWORD")
    quit()

def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write(
                "Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

def patch_http_response_read(func):
    def inner(*args):
        try:
            return func(*args)
        except http.client.IncompleteRead as e:
            return e.partial

    return inner

http.client.HTTPResponse.read = patch_http_response_read(
    http.client.HTTPResponse.read)


try:
    results = co2_instances
    urls=[]
    if 'inputs_data_managers' in results:
        for idm in results["inputs_data_managers"]:
            for ids in idm["urls"]:
                idm_name = idm["name"]
                instance_dict[idm_name]=ids

    if 'cluster_master' in results:
        # for cm in results["cluster_master"]:
            for cms in range(1):
                cm_name =results["cluster_master"]["name"]
                cm_fqdn=results["cluster_master"]["urls"][-1]
                instance_dict[cm_name]= cm_fqdn

    if 'search_heads' in results:
        for sh in results["search_heads"]:
            for ids in sh["urls"]:
                if(sh["name"] == 'shc1'):
                    pass
                else:
                    sh_name = sh["name"]
                    instance_dict[sh_name]=ids

    if 'search_head_clusters' in results:
        for sh in results["search_head_clusters"]:
            for shcs in sh["instances"]:
                for ids in shcs["urls"]:
                    ids = ids.split('.')[0]
                    urls.append(ids)
                    shc_name = sh["name"]
                    instance_dict[shc_name]=urls
                    
    if 'indexers' in results:
        for idx in results["indexers"]:
            for ids in idx["urls"]:
                idxs = 'indexer'
                instance_dict[idxs]=ids

    # if 'indexers' in results:
    #     for idx in results["indexers"]:
    #         for ids in idx["urls"]:
    #             print(ids)

    if BACKUP_NODES is not None:
        for BACKUP_NODES in BACKUP_NODES.split(','):
            BACKUP_NODESS.append(BACKUP_NODES)
    print(instance_dict)

    if 'c0m1' in BACKUP_NODESS:
        if 'indexer' in BACKUP_NODESS:
            print("\nYou chose c0m1 and indexer both target.If stack is Classic then choose only c0m1.If stack is NOAH then choose only indexer.")
            quit()
    JIRA_CMT_STR = "h2. Took backup:\n"

    while(choice!='3'):
        for i in instance_dict.keys():
            for j in BACKUP_NODESS:
                if j.startswith('shc') & (i==j):
                    for x in instance_dict[i]:
                        if choice == '1':
                            JIRA_CMT_STR+="*on "+x+"*\n"
                            JIRA_CMT_STR+="{code:java}\n"
                            cmd =  "sft ssh " + x + " --command 'sudo su  - splunk >/dev/null -c \"PYTHONPATH="" LD_LIBRARY_PATH="" >/dev/null; local-backup-splunketc backup;\"'"
                            # subprocess.call(cmd, shell=True)
                            op= os.popen(cmd).read()
                            JIRA_CMT_STR+="splunk@"+x+":~$  local-backup-splunketc backup\n"
                            # JIRA_CMT_STR+=op
                            # print(op)

                            with open('tempf.txt', 'w') as f:
                                print(op, file=f)
                                
                            with open("tempf.txt","r") as file_one:

                                patrn = "Tab-completion"
                                patrn1="closed"
                                patrn2="Required space constraint not met"
                                for line in file_one:

                                    if re.search(patrn, line):
                                        pass
                                    elif re.search(patrn1, line):
                                        pass
                                    elif re.search(patrn2, line):
                                        JIRA_CMT_STR+="Required space constraint not met"
                                    else:
                                        JIRA_CMT_STR+=line
                            JIRA_CMT_STR+="splunk@"+x+":~$ \n"
                            JIRA_CMT_STR+="{code}\n"
                        if choice == '2':
                            JIRA_CMT_STR+="*on "+x+"*\n"
                            for k in package:
                                JIRA_CMT_STR+="{code:java}\n"
                                cmd = "sft ssh " + x + " --command 'sudo su  - splunk -c \"date;cd /opt/splunk/;mkdir /opt/splunk/tmp/"+JIRA_ID+";cd;cd /opt/splunk/etc/apps/;cp -pR "+str(k)+"/ /opt/splunk/tmp/"+JIRA_ID+"/;ls -la /opt/splunk/tmp/"+JIRA_ID+"/\"'"  
                                op= os.popen(cmd).read()
                                JIRA_CMT_STR+="splunk@"+x+":~/etc/apps$  cp -pR "+str(k)+"/ /opt/splunk/tmp/"+JIRA_ID+"/\n"
                                JIRA_CMT_STR+="splunk@"+x+":~/etc/apps$  ls -la /opt/splunk/tmp/"+JIRA_ID+"/\n"

                                with open('tempf.txt', 'w') as f:
                                    print(op, file=f)

                                with open("tempf.txt","r") as file_one:

                                    patrn = "Tab-completion"
                                    patrn4 = "closed"
                                    patrn1="No such file or directory"
                                    patrn3="mkdir: cannot create directory"
                                    patrn5="UTC"
                                    for line in file_one:

                                        if re.search(patrn, line):
                                            pass
                                        elif re.search(patrn3, line):
                                            pass
                                        elif re.search(patrn4, line):
                                            pass
                                        elif re.search(patrn5, line):
                                            DATE = line
                                        elif re.search(patrn1, line):
                                            JIRA_CMT_STR+="Package not found\n"
                                            break
                                        else:
                                            JIRA_CMT_STR+=line
                                JIRA_CMT_STR+="splunk@"+x+":~/etc/apps$ date\n"
                                JIRA_CMT_STR+=DATE
                                JIRA_CMT_STR+="splunk@"+x+":~/etc/apps$ \n"
                                JIRA_CMT_STR+="{code}\n"


                elif(i==j):
                    node_fqdn = str(instance_dict[j]).split('.')[0]
                    if choice == '1':
                        JIRA_CMT_STR+="*on "+node_fqdn+"*\n"
                        JIRA_CMT_STR+="{code:java}\n"
                        # cmd="this is a test text"
                        cmd =  "sft ssh " + node_fqdn + " --command 'sudo su  - splunk >/dev/null -c \"PYTHONPATH="" LD_LIBRARY_PATH="" >/dev/null; local-backup-splunketc backup; date\"'"
                        # subprocess.call(cmd, shell=True)
                        op= os.popen(cmd).read()
                        JIRA_CMT_STR+="splunk@"+node_fqdn+":~$  local-backup-splunketc backup\n"
                        # JIRA_CMT_STR+=op
                        # print(op)

                        with open('tempf.txt', 'w') as f:
                            print(op, file=f)

                        with open("tempf.txt","r") as file_one:

                            patrn = "Tab-completion"
                            patrn1="closed"
                            patrn2="Required space constraint not met"
                            for line in file_one:

                                if re.search(patrn, line):
                                    pass
                                elif re.search(patrn1, line):
                                    pass
                                elif re.search(patrn2, line):
                                    JIRA_CMT_STR+="Required space constraint not met"
                                else:
                                    JIRA_CMT_STR+=line
                        JIRA_CMT_STR+="splunk@"+node_fqdn+":~$ \n"
                        JIRA_CMT_STR+="{code}\n"
                    if choice =='2':
                        if j.startswith('c0m1'):
                            JIRA_CMT_STR+="*on "+node_fqdn+"*\n"
                            for k in package:
                                JIRA_CMT_STR+="{code:java}\n"
                                cmd = "sft ssh " + node_fqdn + " --command 'sudo su  - splunk -c \"date;cd /opt/splunk/;mkdir /opt/splunk/tmp/"+JIRA_ID+";cd;cd /opt/splunk/etc/master-apps/;cp -pR "+str(k)+"/ /opt/splunk/tmp/"+JIRA_ID+"/;ls -la /opt/splunk/tmp/"+JIRA_ID+"/\"'"  
                                op= os.popen(cmd).read()
                                JIRA_CMT_STR+="splunk@"+node_fqdn+":~/etc/master-apps$  cp -pR "+str(k)+"/ /opt/splunk/tmp/"+JIRA_ID+"/\n"
                                JIRA_CMT_STR+="splunk@"+node_fqdn+":~/etc/master-apps$  ls -la /opt/splunk/tmp/"+JIRA_ID+"/\n"

                                with open('tempf.txt', 'w') as f:
                                    print(op, file=f)

                                with open("tempf.txt","r") as file_one:

                                    patrn = "Tab-completion"
                                    patrn4 = "closed"
                                    patrn1="No such file or directory"
                                    patrn3="mkdir: cannot create directory"
                                    patrn5="UTC"
                                    for line in file_one:

                                        if re.search(patrn, line):
                                            pass
                                        elif re.search(patrn3, line):
                                            pass
                                        elif re.search(patrn4, line):
                                            pass
                                        elif re.search(patrn5, line):
                                            DATE = line
                                        elif re.search(patrn1, line):
                                            JIRA_CMT_STR+="Package not found\n"
                                            break
                                        else:
                                            JIRA_CMT_STR+=line
                                JIRA_CMT_STR+="splunk@"+node_fqdn+":~/etc/master-apps$ date\n"
                                JIRA_CMT_STR+=DATE
                                JIRA_CMT_STR+="splunk@"+node_fqdn+":~/etc/master-apps$ \n"
                                JIRA_CMT_STR+="{code}\n"
        

                        else:
                            JIRA_CMT_STR+="*on "+node_fqdn+"*\n"
                            for k in package:
                                JIRA_CMT_STR+="{code:java}\n"
                                cmd = "sft ssh " + node_fqdn + " --command 'sudo su  - splunk -c \"date;cd /opt/splunk/;mkdir /opt/splunk/tmp/"+JIRA_ID+";cd;cd /opt/splunk/etc/apps/;cp -pR "+str(k)+"/ /opt/splunk/tmp/"+JIRA_ID+"/;ls -la /opt/splunk/tmp/"+JIRA_ID+"/\"'"  
                                op= os.popen(cmd).read()
                                JIRA_CMT_STR+="splunk@"+node_fqdn+":~/etc/apps$  cp -pR "+str(k)+"/ /opt/splunk/tmp/"+JIRA_ID+"/\n"
                                JIRA_CMT_STR+="splunk@"+node_fqdn+":~/etc/apps$  ls -la /opt/splunk/tmp/"+JIRA_ID+"/\n"

                                with open('tempf.txt', 'w') as f:
                                    print(op, file=f)

                                with open("tempf.txt","r") as file_one:

                                    patrn = "Tab-completion"
                                    patrn4 = "closed"
                                    patrn1="No such file or directory"
                                    patrn3="mkdir: cannot create directory"
                                    patrn5="UTC"

                                    for line in file_one:

                                        if re.search(patrn, line):
                                            pass
                                        elif re.search(patrn3, line):
                                            pass
                                        elif re.search(patrn4, line):
                                            pass
                                        elif re.search(patrn5, line):
                                            DATE = line
                                        elif re.search(patrn1, line):
                                            JIRA_CMT_STR+="Package not found\n"
                                            break
                                        else:
                                            JIRA_CMT_STR+=line
                                JIRA_CMT_STR+="splunk@"+node_fqdn+":~/etc/apps$ date\n"
                                JIRA_CMT_STR+=DATE
                                JIRA_CMT_STR+="splunk@"+node_fqdn+":~/etc/apps$ \n"
                                JIRA_CMT_STR+="{code}\n"

        choice = input("\n\nWant to continue with backup:\n1. Using EBTOOL\n2. App Specific\n3. Exit \n")
        if choice == '2':
            package = input("Enter Package ID : ").split(',')

    print(JIRA_CMT_STR)
    if query_yes_no("\n\nDo you want to add JIRA comment?", "yes"):     
    
        if JIRA_ID == "KRUSHI":
            sys.stdout.write(
                "\nEnter the app install JIRA issue id (CO-123456):")
            JIRA_ID = input()

        options = {'server': JIRA_SERVER}
        jira = JIRA(options=options, basic_auth=(EMAIL_ID, JIRA_TOKEN))
        issue = jira.issue(JIRA_ID)
        jira.add_comment(issue, JIRA_CMT_STR)
        print("Comment added successfully: " +
            JIRA_SERVER + "/browse/" + JIRA_ID)           

    print("\n")
    print("v1.0 @copyright Krushi Vasani")
    print("\n")
except Exception as e:
    print(e)
    quit()