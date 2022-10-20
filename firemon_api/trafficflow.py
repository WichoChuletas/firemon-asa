
import requests
import json
import sys
import urllib3
import click
import tabulate
from netaddr import IPNetwork
from netaddr import cidr_merge
from netaddr import IPAddress
urllib3.disable_warnings()

from .rule import get_rule_by_id

def get_traffic_flows(server: str, domain: str, device: str, token: str) -> list:
    path: str = "https://{}/securitymanager/api/domain/{}/device/{}/trafficflow?page=0&pageSize=100"
    headers: dict = {'Content-Type': 'application/json', 'X-FM-Auth-Token': token}
    try:
        response=requests.get(url=path.format(server, domain, device), headers=headers, verify=False)
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
        traffic_flows: dict = json.loads(json_data)["results"]
        table = list()
        
        for traffic_flow in traffic_flows:
            tr = [traffic_flow['id'], traffic_flow['name'], traffic_flow['size']]
            table.append(tr)
        table_headers = ["id", "name", "size"]
        try:
            click.echo(tabulate.tabulate(table, table_headers, tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, table_headers, tablefmt="grid"))
    else:
        sys.exit()

def get_ruleid(server: str, domain: str, trafficflow: str, token: str) -> list:
    path: str = "https://{}/securitymanager/api/domain/{}/trafficflow/{}"
    headers: dict = {'Content-Type': 'application/json', 'X-FM-Auth-Token': token}
    try:
        response=requests.get(url=path.format(server, domain, trafficflow), headers=headers, verify=False)
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
        results: dict = json.loads(json_data)['ruleId']
        return results

    else:
        sys.exit()
    
def get_traffic_flows_results(server: str, domain: str, device: str, trafficflow: str, token: str) -> list:
    path: str = "https://{}/securitymanager/api/domain/{}/device/{}/trafficflow/{}/results?page=0&pageSize=100"
    headers: dict = {'Content-Type': 'application/json', 'X-FM-Auth-Token': token}
    try:
        response=requests.get(url=path.format(server, domain, device, trafficflow), headers=headers, verify=False)
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
        results: dict = json.loads(json_data)['acceptFlows']
        table = list()
        table_headers = ["count", "sources", "destinations", "services"]

        for result in results:
            tr = [result['count'], list(result['sources'].keys()), list(result['destinations'].keys()), list(result['serviceMap'].keys())]
            table.append(tr)
            
        try:
            click.echo(tabulate.tabulate(table, table_headers, tablefmt="fancy_grid"))
        except UnicodeEncodeError:
            click.echo(tabulate.tabulate(table, table_headers, tablefmt="grid"))

    else:
        sys.exit()

def get_traffic_flows_report(server: str, domain: str, device: str, trafficflow: str, token: str) -> list:
    rule_id = get_ruleid(server, domain, trafficflow, token)
    get_rule_by_id(server, domain, device, rule_id, token)
    get_traffic_flows_results(server, domain, device, trafficflow, token)


def genconfig_asa_traffic_flows(server: str, domain: str, device: str, trafficflow: str, token: str) -> list:
    path_traffic_flow: str = "https://{}/securitymanager/api/domain/{}/device/{}/trafficflow?page=0&pageSize=100"
    path_traffic_flow_results: str = "https://{}/securitymanager/api/domain/{}/device/{}/trafficflow/{}/results?page=0&pageSize=100"
    headers: dict = {'Content-Type': 'application/json', 'X-FM-Auth-Token': token}
    try:
        response_traffic_flow=requests.get(url=path_traffic_flow.format(server, domain, device, trafficflow), headers=headers, verify=False)
        response_traffic_flow_results=requests.get(url=path_traffic_flow_results.format(server, domain, device, trafficflow), headers=headers, verify=False)
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)
    if response_traffic_flow.ok and response_traffic_flow_results.ok:
        json_data_traffic_flow: str = response_traffic_flow.text
        json_data_traffic_flow_results: str = response_traffic_flow_results.text
        results: dict = json.loads(json_data_traffic_flow_results)['acceptFlows']
        tflows: dict = json.loads(json_data_traffic_flow)['results']
        acl_name: str = None
        trafficflow_name: str = None
        for tflow in tflows:
            if tflow['id'] == int(trafficflow):
                acl_name = tflow['ruleName'].split("_")[0].upper()
                trafficflow_name = tflow["name"]  
        identifier_list = []
        with open("config_files/{}.txt".format(trafficflow_name), "w") as configfile:
            for result in results:
                print("count: {}".format(result['count']))
                configfile.write("!count {}\n".format(result['count']))
                ### OBJECT ID ###
                flag = True
                identifier: str = "" 
                while flag:
                    identifier_aux = str(hash(str(result))).replace("-", "")[:4] 
                    if identifier_aux not in identifier_list:
                        identifier_list.append(identifier_aux)
                        flag = False
                    identifier = identifier_aux
                ### SOURCE ADDRESS GENERATE ###
                src_name = "SRC_{}_GEN_{}".format(acl_name, identifier)
                configfile.write("object-group network {}\n".format(src_name))
                print("object-group network {}".format(src_name))
                for source in sum_networks(list(result['sources'].keys())):
                    if "/32" in str(source):
                        configfile.write("\tnetwork-object host {}\n".format(str(source).replace("/32", "")))
                        print("\tnetwork-object host {}".format(str(source).replace("/32", "")))
                    else:
                        source_obj = IPNetwork(source)
                        configfile.write("\tnetwork-object {} {}\n".format(source_obj.network, source_obj.netmask))
                        print("\tnetwork-object {} {}".format(source_obj.network, source_obj.netmask))
                ### DESTINATION ADDRESS GENERATE ###
                dst_name = "DST_{}_GEN_{}".format(acl_name, identifier)
                configfile.write("object-group network {}\n".format(dst_name))
                print("object-group network {}".format(dst_name))
                for destination in sum_networks(list(result['destinations'].keys())):
                    if "/32" in str(destination):
                        configfile.write("\tnetwork-object host {}\n".format(str(destination).replace("/32", "")))
                        print("\tnetwork-object host {}".format(str(destination).replace("/32", "")))
                    else:
                        destination_obj = IPNetwork(destination)
                        configfile.write("\tnetwork-object {} {}\n".format(destination_obj.network, destination_obj.netmask))
                        print("\tnetwork-object {} {}".format(destination_obj.network, destination_obj.netmask))

                ### SERVICE GENERATE ###
                if is_only_other_protocol(result['serviceMap'].keys()):
                    configfile.write("access-list {} line line-acl extended permit ip object-group {} object-group {} log notifications interval 300\n".format(acl_name, src_name, dst_name))
                    print("access-list {} line line-acl extended permit ip object-group {} object-group {} log notifications interval 300".format(acl_name, src_name, dst_name))
                    configfile.write("access-list {} line line-acl remark own:usrfiremon;tk:000000000;jst:{};\n".format(acl_name, trafficflow_name))
                    print("access-list {} line line-acl remark own:usrfiremon;tk:000000000;jst:{};".format(acl_name, trafficflow_name))
                    configfile.write("!\n")
                else:
                    sg_name = "SG_{}_GEN_{}".format(acl_name, identifier)
                    configfile.write("object-group service {}\n".format(sg_name))
                    print("object-group service {}".format(sg_name))
                    for service in list(result['serviceMap'].keys()):
                        if service.split("/")[0] != "other":    
                            if (service.split("/")[0] == "tcp") and int(service.split("/")[1]) > 0 and int(service.split("/")[1]) < 49152:
                                configfile.write("\tservice-object {} destination eq {}\n".format(service.split("/")[0], service.split("/")[1]))
                                print("\tservice-object {} destination eq {}".format(service.split("/")[0], service.split("/")[1]))
                            elif service.split("/")[0] == "udp": 
                                configfile.write("\tservice-object {} destination eq {}\n".format(service.split("/")[0], service.split("/")[1]))
                                print("\tservice-object {} destination eq {}".format(service.split("/")[0], service.split("/")[1]))                              
                    configfile.write("access-list {} line line-acl extended permit object-group {} object-group {} object-group {} log notifications interval 300\n".format(acl_name, sg_name, src_name, dst_name))
                    print("access-list {} line line-acl extended permit object-group {} object-group {} object-group {} log notifications interval 300".format(acl_name, sg_name, src_name, dst_name))
                    configfile.write("access-list {} line line-acl remark own:usrfiremon;tk:000000000;jst:{};\n".format(acl_name, trafficflow_name))
                    print("access-list {} line line-acl remark own:usrfiremon;tk:000000000;jst:{};".format(acl_name, trafficflow_name))
                    configfile.write("!\n")
            configfile.close()
            table = list()
            for result in results:
                tr = [result['count'], list(result['sources'].keys()), list(result['destinations'].keys()), list(result['serviceMap'].keys())]
                table.append(tr)
            return table

    else:
        sys.exit()

def is_only_other_protocol(services):
    protocol_filtred = []
    for service in services:
        if service.split("/")[0] == "other":
            protocol_filtred.append(service.split("/")[0])
    return True if len(protocol_filtred) == 1 and "other" in protocol_filtred else False

def get_filtred_services(services):
    services_filtred = []
    for service in services:
        if service.split("/")[0] != "other":
            if service.split("/")[0] == "tcp" and int(service.split("/")[1]) > 0 and int(service.split("/")[1]) < 49152:
                services_filtred.append(service.split("/")[0])
            elif service.split("/")[0] == "udp":
                services_filtred.append(service.split("/")[0])
    return services_filtred

def sum_networks(addresses):
    addresses_list = []
    for address in addresses:
        if "/" in address:
            addresses_list.append(IPNetwork(address))
        else:
            addresses_list.append(IPAddress(address))
    return cidr_merge(addresses_list)
    
