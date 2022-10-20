import requests
import json
import sys
import click
import tabulate

import urllib3
urllib3.disable_warnings()

def get_devices(server: str, domain: str, token: str) -> list:
    path: str = "https://{}/securitymanager/api/domain/{}/device?page=0&pageSize=100"
    headers: dict = {'Content-Type': 'application/json', 'X-FM-Auth-Token': token}
    try:
        response=requests.get(url=path.format(server, domain), headers=headers, verify=False)
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
        devices: dict = json.loads(json_data)["results"]
        table = list()

        for device in devices:
            tr = [device['name'], device['id']]
            table.append(tr)

        table_headers = ["name", "id"]
        try:
            click.echo(tabulate.tabulate(table, table_headers, tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, table_headers, tablefmt="grid"))

    else:
        sys.exit()
    