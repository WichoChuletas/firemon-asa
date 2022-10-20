import firemon_api.auth
import firemon_api.domain
import firemon_api.device
import firemon_api.trafficflow
import click
import os
import tabulate

firemon_server = os.environ.get("firemon_server")
firemon_username = os.environ.get("firemon_username")
firemon_password = os.environ.get("firemon_password")
firemon_access_token = None

if firemon_server is None or firemon_username is None or firemon_password is None:
    print("Username, password, and server are requiered")
    exit()
else:
    firemon_access_token = firemon_api.auth.get_token(username=firemon_username, password=firemon_password, server=firemon_server)

@click.group()
def firemon():
    """
    Command line tool for Firemon
    """
    pass

@click.command()
def domainlist():
    """
    Retrieve firemon domains
    Example command:
        ./firemon.py domains_list
    """
    click.secho("getting firemon domains...")
    firemon_api.domain.get_domains(firemon_server, firemon_access_token)


@click.command()
@click.option("--domain", help="ID of firemon domain")
def devicelist(domain):
    """
    Retrieve firemon domains
    Example command:
        ./firemon.py domains_list
    """
    click.secho("getting firemon devices on domain{}...".format(domain))
    firemon_api.device.get_devices(firemon_server, domain, firemon_access_token)


@click.command()
@click.option("--domain", help="ID of firemon domain")
@click.option("--device", help="ID of device on firemon")
def devicetrafficflowlist(domain, device):
    """
    Retrieve firemon domains
    Example command:
        ./firemon.py domains_list
    """
    click.secho("getting traffic flows of {} on domain{}...".format(device, domain))
    firemon_api.trafficflow.get_traffic_flows(firemon_server, domain, device, firemon_access_token)


@click.command()
@click.option("--domain", help="ID of firemon domain")
@click.option("--device", help="ID of device on firemon")
@click.option("--trafficflow", help="ID of device on firemon")
def devicetrafficflowreport(domain, device, trafficflow):
    """
    Retrieve firemon domains
    Example command:
        ./firemon.py domains_list
    """
    click.secho("getting results from traffic flows {} of {} on domain{}...".format(trafficflow, device, domain))
    firemon_api.trafficflow.get_traffic_flows_report(firemon_server, domain, device, trafficflow, firemon_access_token)


@click.command()
@click.option("--domain", help="ID of firemon domain")
@click.option("--device", help="ID of device on firemon")
@click.option("--trafficflow", help="ID of device on firemon")
def devicetrafficflowgenconfigasa(domain, device, trafficflow):
    """
    Retrieve firemon domains
    Example command:
        ./firemon.py domains_list   
    """
    click.secho("getting results from traffic flows {} of {} on domain{}...".format(trafficflow, device, domain))
    table = firemon_api.trafficflow.genconfig_asa_traffic_flows(firemon_server, domain, device, trafficflow, firemon_access_token)
    table_headers = ["count", "sources", "destinations", "services"]
    #try:
        #click.echo(tabulate.tabulate(table, table_headers, tablefmt="fancy_grid"))
    #except UnicodeEncodeError:
    #    click.echo(tabulate.tabulate(table, table_headers, tablefmt="grid"))

firemon.add_command(domainlist)  
firemon.add_command(devicelist)
firemon.add_command(devicetrafficflowlist)
firemon.add_command(devicetrafficflowreport)
firemon.add_command(devicetrafficflowgenconfigasa)

if __name__ == '__main__':
    firemon()
    
