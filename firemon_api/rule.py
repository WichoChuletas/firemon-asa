

import requests
import json
import sys
import urllib3
import click
import tabulate
urllib3.disable_warnings()

def get_rule_by_id(server: str, domain: str, device: str, rule: str, token: str) -> list:
    path: str = "https://{}/securitymanager/api/domain/{}/device/{}/rule/{}"
    headers: dict = {'Content-Type': 'application/json', 'X-FM-Auth-Token': token}
    try:
        response=requests.get(url=path.format(server, domain, device, rule), headers=headers, verify=False)
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)
    if response.ok:
        json_data: str = response.text
        print(json_data)

        

    else:
        sys.exit()