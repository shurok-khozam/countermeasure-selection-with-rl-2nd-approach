import os
from mininet.log import info
import json

from mininet.term import makeTerm

# Intermed Imports
from intermed.OvsIntermediateMininet import *
from intermed.OvsIntermediate import *
from intermed import OvsIntermediateConstants as consts

# =========================================================================================
# =============================== Environment Variables ===================================
# =========================================================================================
PYTHON = os.getenv('PYTHON')
if PYTHON is None:
    PYTHON="python3"
print(f"WARNING: using python at {PYTHON}!")

XTERM_STDOUT_PATH = os.getenv('XTERM_STDOUT_PATH')
xterm_to_file = (XTERM_STDOUT_PATH is not None)
if xterm_to_file:
    if XTERM_STDOUT_PATH.endswith("/"):
        XTERM_STDOUT_PATH.rstrip("/")
    print(f"WARNING: xterm output would be only saved to files under the path: {XTERM_STDOUT_PATH}!")

# ==========================================================================================

class GlobalsHolder:
    def __init__(self, config):
        self.net = None
        self.cli = None
        self.max_host_bw = 3.1
        self.max_switch_bw = 9.1
        # self.max_server_bw = (self.max_host_bw - 0.1) * 3 + 0.1
        self.network_spec = {}
        self.network_dir = os.path.dirname(os.path.abspath(__file__))

        self.tcp_flows = {}
        self.tcp_flow_directory = f'{self.network_dir}/tcp'
        self.tcp_flow_server_file = f'{self.tcp_flow_directory}/TcpServer.py'
        self.tcp_flow_client_file = f'{self.tcp_flow_directory}/TcpClient.py'
        self.tcp_receivers = []
        self.nbr_controlled_switches = 4 # Default value
        if not ('nbr_controlled_switches' not in config or config['nbr_controlled_switches'] is None or config['nbr_controlled_switches'] == ''):
            self.nbr_controlled_switches = int(config['nbr_controlled_switches'])
        self.hosts_topo_file_name = 'hosts-toplogy-6hosts.json'
        if not ('hosts_topo_file' not in config or config['hosts_topo_file'] is None or config['hosts_topo_file'] == ''):
            self.hosts_topo_file_name = config['hosts_topo_file']
            if not self.hosts_topo_file_name.lower().endswith(".json"):
                self.hosts_topo_file_name += ".json"
        self.hosts_topo_file_directory = f'{self.network_dir}/../input-data'
        self.hosts_topo_file_path = f'{self.hosts_topo_file_directory}/{self.hosts_topo_file_name}'
        self.hosts_raw_topo = {}
        self.router_switches_list = []
        self.client_hosts_list = []
        self.host_default_switch_relation = {}
        self.router_to_host_relation = {}
        self.router_to_controlled_switch_relation = {}
        self.controlled_switch_to_router_relation = {}
        self.read_hosts_topology_file()

        self.ddos_flooding_attacks = {}
        self.ditg_flows = {}
        self.ditg_directory = f'{self.network_dir}/../../D-ITG-2.8.1-r1023-src/D-ITG-2.8.1-r1023/bin'
        self.ditg_receivers = []
        self.mhddos_start_path = f'{self.network_dir}/../../MHDDoS/start.py'
        self.tmp_dir = f"{self.network_dir}/../reinforcement/tmp"
        self.default_server = 'hs'
        self.servers = ['hs']
        if not (config['servers'] is None or config['servers'] == '' or config['servers'] == '[]'):
            self.servers = config['servers'].lstrip("[").rstrip("]").split(',')
        self.attackers = []
        if not (config['attackers'] is None or config['attackers'] == '' or config['attackers'] == '[]'):
            self.attackers = config['attackers'].lstrip("[").rstrip("]").split(',')
        self.manual_receivers = config['manuel_receivers']
        self.controlled_switches_list = []
        self.switch_interface_port_mapping = {}
        self.unified_host_bandwidth = None
        if not (config['unified_host_bandwidth'] is None or config['unified_host_bandwidth'] == ''):
            self.unified_host_bandwidth = float(config['unified_host_bandwidth'])
        self.unified_switch_bandwidth = None
        if not (config['unified_switch_bandwidth'] is None or config['unified_switch_bandwidth'] == ''):
            self.unified_switch_bandwidth = float(config['unified_switch_bandwidth'])
        self.ovs = None

        # Extended OVS
        self.ovs = None
        self.highest_priority = 65535
        self.server_switch_flood_priority = 2
        self.controlled_switch_flood_priority = 0
        self.controlled_switch_arp_priority = 499
        self.non_controlled_switch_arp_priority = 499

        self.s0_switch = "s0"
        self.server_host = self.servers[0]
        self.global_dns = "8.8.8.8"

        self.do_validity_controls()

    # Performs validation checks on the global network configuration.
    # - Ensures at least one server and attacker is specified.
    # - Checks for switch counts.
    # - Throws exceptions if the configuration is invalid.
    def do_validity_controls(self):
        # Server Controls
        if len(self.servers) == 0:
            raise Exception("No server has been set")
        if len(self.servers) > 1:
            raise Exception(f"More than one server has been set ({self.servers}), current solution accepts only a single server")
        if len(self.servers) == 1 and self.servers[0] != self.default_server:
            raise Exception(f"Current solution accepts only ({self.default_server}) as a server")
        # Attacker Controls
        if len(self.attackers) == 0:
            raise Exception("No attacker has been set")
        if len(self.attackers) > 1:
            raise Exception(f"More than one attacker has been set ({self.attackers}), current solution accepts only a single attacker")
        if self.attackers[0] not in self.client_hosts_list:
            raise Exception(f"Chosen attacker ({self.attackers[0]}) was not found in hosts list ({self.client_hosts_list})")
        if self.nbr_controlled_switches < 4:
            raise Exception(f"Number of controlled switches set to a ({self.nbr_controlled_switches}) which is lower than 4. Min value is 4!")
        if self.nbr_controlled_switches > 99:
            raise Exception(f"Number of controlled switches set to a ({self.nbr_controlled_switches}) which is more than 99. max value is 99!")

    def read_hosts_topology_file(self):
        print(f"-> Reading hosts from {self.hosts_topo_file_path}")
        with open(self.hosts_topo_file_path) as json_file:
            data = json.load(json_file)
            self.hosts_raw_topo = data

        for host in self.hosts_raw_topo:
            if not host.startswith("h"):
                raise Exception(f"Host name ({host}) is not valid, accepted format 'h' + (number), example: 'h76'")
            self.client_hosts_list.append(host)
            self.host_default_switch_relation[host] = {'default_path_switch': self.hosts_raw_topo[host]['default_path_switch']}
            router = self.hosts_raw_topo[host]['router_switch']
            self.router_to_host_relation[router] = {'host': host}
            self.router_switches_list.append(router)
            self.router_to_controlled_switch_relation[router] = {'controlled_switch': self.hosts_raw_topo[host]['default_path_switch']}
            if self.hosts_raw_topo[host]['default_path_switch'] in self.controlled_switch_to_router_relation:
                self.controlled_switch_to_router_relation[self.hosts_raw_topo[host]['default_path_switch']]['routers'].append(router)
            else:
                self.controlled_switch_to_router_relation[self.hosts_raw_topo[host]['default_path_switch']] = {'routers': [router]}


def init(config):
    global GLOBALS
    GLOBALS = GlobalsHolder(config)
    print("--> init called")
# Generates the output suffix for redirecting xterm output to a file.
# If the environment variable `XTERM_STDOUT_PATH` is set, logs will be stored there.
def get_output_suffix_for_xterm(nodeName):
    if not xterm_to_file:
        return ""
    else:
        return f" > {XTERM_STDOUT_PATH}/{nodeName}.log 2>&1"

def makeCustomTerm( node, title='Node', term='xterm', display=None, cmd='bash'):
    return makeTerm(node, title, term, display, f"{cmd}{get_output_suffix_for_xterm(node.name)}")
# Generates an Open vSwitch (OVS) command to activate a link between a host and a switch.
def get_host_switch_turn_on_link_command(host_ip, connected_switch, switch_port):
    return f'ovs-ofctl add-flow {connected_switch} ip,priority=2,nw_dst={host_ip},actions=output:{switch_port}'

def get_host_switch_turn_off_link_command(host_ip, connected_switch):
    return f'ovs-ofctl --strict del-flows {connected_switch} ip,priority=2,nw_dst={host_ip}'

def get_current_connected_switch_from_switch_dict(src_switch):
    global GLOBALS
    for dst_switch in GLOBALS.network_spec['switches'][src_switch]['connections'].keys():
        if GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['connected']:
            return dst_switch
# Disables a network link between two switches or a host and a switch.
# Uses the `ifconfig` command to bring the interfaces down.
def turn_down_link(src_switch, src_int, dst_switch, dst_int):
    info(f"*** Deactivate link {src_switch}({src_int}) --> {dst_switch}({dst_int})  ***\n")
    info(GLOBALS.net[src_switch].cmd(f'ifconfig {src_int} down'))
    info(GLOBALS.net[dst_switch].cmd(f'ifconfig {dst_int} down'))

def turn_up_link(src_switch, src_int, dst_switch, dst_int):
    info(f"*** Activate link {src_switch}({src_int}) --> {dst_switch}({dst_int})  ***\n")
    info(GLOBALS.net[src_switch].cmd(f'ifconfig {src_int} up'))
    info(GLOBALS.net[dst_switch].cmd(f'ifconfig {dst_int} up'))

def get_interface_name(src, dst):
    if dst.startswith("s"):
        return f'{src}-eth{dst.lstrip("s")}'
    if dst.startswith("h"):
        return f'{src}-eth{dst.lstrip("h")}'
    return f"{src}-eth{dst}"
# These functions generate Open vSwitch (OVS) flow rules for packet forwarding.
# They generate rules based on different criteria like:
# - Source IP
# - Destination IP
# - MAC Address
# - Input and Output Ports
# Used for configuring SDN flow rules in OpenFlow-enabled switches.
def get_ovs_flow_rule_with_src_ip_and_dst_ip(ip_src, ip_dst, output_port):
    return f'ip,priority=500,nw_src={ip_src},nw_dst={ip_dst},actions=output:{output_port}'

def get_ovs_flow_rule_with_src_mac(mac_src, output_port):
    return f'priority=500,dl_src={mac_src},actions=output:{output_port}'

def get_ovs_flow_rule_with_in_port_and_src_mac(in_port, mac_src, output_port):
    return f'priority=500,in_port={in_port},dl_src={mac_src},actions=output:{output_port}'

def get_ovs_flow_rule_with_src_ip(ip_src, output_port):
    return f'ip,priority=500,nw_src={ip_src},actions=output:{output_port}'

def get_ovs_flow_rule_with_in_port_and_src_ip(in_port,ip_src, output_port):
    return f'ip,in_port={in_port},priority=65535,nw_src={ip_src},actions=output:{output_port}'

def get_ovs_flow_rule_with_in_port_and_dst_ip(in_port, ip_dst, output_port):
    return f'ip,in_port={in_port},priority=65535,nw_dst={ip_dst},actions=output:{output_port}'

def get_ovs_flow_rule_with_in_port_and_dst_mac(in_port, mac_dst, output_port):
    return f'in_port={in_port},priority=65535,dl_dst={mac_dst},actions=output:{output_port}'

def get_ovs_flow_rule_with_in_port(in_port, output_port):
    return f'in_port={in_port},priority=65535,actions=output:{output_port}'

def get_ovs_flow_rule_with_dst_ip(ip_dst, output_port):
    return f'ip,priority=65535,nw_dst={ip_dst},actions=output:{output_port}'
def get_ovs_flow_rule_with_dst_mac(mac_dst, output_port):
    return f'priority=65535,dl_dst={mac_dst},actions=output:{output_port}'
def get_ovs_flow_rule_with_src_mac_and_dst_mac(mac_src, mac_dst, output_port):
    return f'priority=65535,dl_src={mac_src},dl_dst={mac_dst},actions=output:{output_port}'

def get_ovs_del_flow_rule_with_dst_mac(mac_dst):
    return f'dl_dst={mac_dst}'

def get_ovs_del_flow_rule_with_src_mac_and_dst_mac(mac_src, mac_dst):
    return f'dl_src={mac_src},dl_dst={mac_dst}'

def get_ovs_add_flow_cmd(switch, cmd):
    info(f'{switch} ==> ovs-ofctl add-flow {cmd}\n')
    return f'ovs-ofctl add-flow {switch} {cmd}'
def get_ovs_del_flow_cmd(switch, cmd):
    info(f'{switch} ==> ovs-ofctl del-flows {cmd}\n')
    return f'ovs-ofctl del-flows {switch} {cmd}'

def get_host_status(host_name):
    global GLOBALS
    return GLOBALS.network_spec['hosts'][host_name]

# Generates an OVS command to flood ARP packets for ICMP traffic on a specified switch.
# This ensures ARP requests can reach all relevant ports for network discovery.
def flood_arp_for_icmp_command(target: str, priority: int):
    return OvsOfctlAddFlowCommand(target, OvsOfctlCommandArguments(priority=priority,
                                                              ether_type=consts.OVS_INSTR_ARGS_ETHER_TYPE_VALUES_ARP,
                                                              net_protocol=consts.OVS_INSTR_ARGS_NET_PROTOCOL_VALUES_ICMP,
                                                              actions=[OvsCommandArgumentActionFlood()]))

# Generates OVS flow rules to allow ARP responses for ICMP traffic between specified ports.
def output_arp_for_icmp_from_port_to_port(target: str, priority: int, in_port, out_ports: []):
    return OvsOfctlAddFlowCommand(target, OvsOfctlCommandArguments(priority=priority,
                                                              ether_type=consts.OVS_INSTR_ARGS_ETHER_TYPE_VALUES_ARP,
                                                              net_protocol=consts.OVS_INSTR_ARGS_NET_PROTOCOL_VALUES_ICMP,
                                                              in_port=f"{in_port}",
                                                              actions=[OvsCommandArgumentActionOutput(f"{out_port}") for
                                                                       out_port in out_ports]))

# Initializes ARP handling rules for a controlled switch.
# ARP responses are configured to allow traffic between server ports and controlled/non-controlled ports
def init_arp_for_controlled_switch(target: str, priority: int, flood_priority: int, server_port: int,
                                   controlled_ports: [int], non_controlled_ports: [int]):
    commands = []
    commands.append(output_arp_for_icmp_from_port_to_port(target=target, priority=priority, in_port=server_port,
                                                          out_ports=non_controlled_ports))
    for port in non_controlled_ports:
        commands.append(output_arp_for_icmp_from_port_to_port(target=target, priority=priority, in_port=port,
                                                              out_ports=[server_port]))
    for port in controlled_ports:
        commands.append(output_arp_for_icmp_from_port_to_port(target=target, priority=priority, in_port=port,
                                                              out_ports=[server_port]))
    commands.append(flood_arp_for_icmp_command(target=target, priority=flood_priority))
    return commands

# Generates ARP rules for all controlled switches based on a priority configuration.
def init_arp_for_cotnrolled_switches(priority: int, flood_priority: int, switches_info: dict):
    commands = []
    for switch in switches_info.keys():
        server_port = switches_info[switch]["server_port"]
        controlled_ports = switches_info[switch]["controlled_ports"]
        non_controlled_ports = switches_info[switch]["non_controlled_ports"]
        commands.extend(init_arp_for_controlled_switch(target=switch, priority=priority,
                                                       flood_priority=flood_priority, server_port=server_port,
                                                       controlled_ports=controlled_ports,
                                                       non_controlled_ports=non_controlled_ports))
    return commands

# Generates ARP flooding rules for non-controlled switches.
def init_arp_for_non_controlled_switches(flood_priority, switches_names: [str]):
    commands = []
    for switch in switches_names:
        commands.append(flood_arp_for_icmp_command(target=switch, priority=flood_priority))
    return commands

# Configures flow rules for directing DNS traffic (targeting 8.8.8.8) from the server switch.
def init_flow_for_global_dns_from_server_switch(switch, priority: int, ip_dest: str, interface_name):
    return OvsOfctlAddFlowCommand(switch, OvsOfctlCommandArguments(
        protocol=consts.OVS_PROTOCOL_IP,
        priority=priority,
        ip_destination=ip_dest,
        actions=[
            OvsCommandArgumentActionOutput(f"{GLOBALS.switch_interface_port_mapping[switch][interface_name]}")]))

# Configures a flow rule for directing traffic from a switch to a host based on MAC address.
def init_flow_from_switch_to_direct_host_via_mac(switch, priority: int, host: str):
    return OvsOfctlAddFlowCommand(switch, OvsOfctlCommandArguments(
        priority=priority,
        mac_destination= GLOBALS.network_spec['hosts'][host]['mac'],
        actions=[OvsCommandArgumentActionOutput(
            f"{GLOBALS.switch_interface_port_mapping[switch][GLOBALS.network_spec['hosts'][host]['dst_int']]}")]))

def init_flow_from_server_switch_to_controlled_switch_for_hosts(switch, priority: int):
    commands = []
    for host in GLOBALS.client_hosts_list:
        controlled_switch = GLOBALS.network_spec['hosts'][host]['default_path_switch']
        s0_to_controlled_switch_src_interface = get_interface_name(switch, controlled_switch)

        commands.append(OvsOfctlAddFlowCommand(switch, OvsOfctlCommandArguments(
            priority=priority,
            mac_destination=GLOBALS.network_spec['hosts'][host]['mac'],
            actions=[OvsCommandArgumentActionOutput(
                f"{GLOBALS.switch_interface_port_mapping[switch][s0_to_controlled_switch_src_interface]}")])))
    return commands

# Constructs the switch information needed for ARP rule generation.
# Identifies server ports, controlled ports, and non-controlled ports for each switch.
def build_switch_info_for_arp():
    global GLOBALS
    switches_info = {}
    for switch in GLOBALS.controlled_switches_list:
        info = {
            "server_port": 0,
            "controlled_ports": [],
            "non_controlled_ports": []
        }
        ports = GLOBALS.network_spec['switches'][switch]["ports"]
        connections = GLOBALS.network_spec['switches'][switch]["connections"]
        for port_interface in ports:
            port = GLOBALS.switch_interface_port_mapping[switch][port_interface]
            if port_interface == connections[GLOBALS.s0_switch]["src_int"]:
                info["server_port"] = port
            elif port_interface in [connections[index]["src_int"] for index in connections]:
                info["controlled_ports"].append(port)
            else:
                info["non_controlled_ports"].append(port)
        switches_info[switch] = info
    return switches_info