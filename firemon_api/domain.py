import requests
import json
import sys
import urllib3
import click
import tabulate
urllib3.disable_warnings()

def get_domains(server: str, token: str) -> list:
    path: str = "https://{}/securitymanager/api/domain?page=0&pageSize=100"
    headers: dict = {'Content-Type': 'application/json', 'X-FM-Auth-Token': token}
    try:
        response=requests.get(url=path.format(server), headers=headers, verify=False)
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
        domains: dict = json.loads(json_data)["results"]
        
        table = list()

        for domain in domains:
            tr = [domain['name'], domain['description'], domain['id']]
            table.append(tr)

        table_headers = ["name", "description", "id"]
        try:
            click.echo(tabulate.tabulate(table, table_headers, tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, table_headers, tablefmt="grid"))
    else:
        sys.exit()
    