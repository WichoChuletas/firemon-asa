
import requests
import json
import urllib3
urllib3.disable_warnings()


def get_token(username: str, password: str, server: str) -> str:
    path: str = "https://{}/securitymanager/api/authentication/login"
    headers: dict = {'Content-Type': 'application/json'}
    credentials: dict = {'username': username, 'password': password}
    try:
        response=requests.post(url=path.format(server), json=credentials, headers=headers, verify=False)
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)
    except Exception as e:
        print ("OOps: Something Else",err)
    if response.ok:
        json_data: str = response.text
        access_token: dict = json.loads(json_data)["token"]
        return access_token
    
