import requests
import warnings
import argparse
import webbrowser
from urllib.parse import parse_qs, urlparse
warnings.filterwarnings(action="ignore", category=ResourceWarning)
warnings.filterwarnings(action='ignore', message='Unverified HTTPS request')

parser = argparse.ArgumentParser()

parser.add_argument('-s', '--stack',
                    required=True)
args = parser.parse_args()
STACK= args.stack
url='https://skynet-search.splunkcloud.com/en-GB/app/cloudops/stack_overview?form.stack='+STACK
webbrowser.open_new(url)
url='https://skynet-search.splunkcloud.com/en-GB/app/cloudops/stack_prechecks?form.packageid=075-cloudworks&form.uid=*&form.spec=metadata&form.stack='+STACK
webbrowser.open_new(url)
url='https://web.co2.lve.splunkcloud.systems/lve/stack/'+STACK+'/status'
webbrowser.open_new(url)
url='https://puppet-master.lve.splunkcloud.systems/#/enforcement/status'
webbrowser.open_new(url)
url='https://splunkcloud.okta.com/app/UserHome'
webbrowser.open_new(url)
url='https://app.us2.signalfx.com/#/muting/Eme50_jBEAA?query='+STACK
webbrowser.open_new(url)

