# Mininet
import numpy as np
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, CPULimitedHost
from mininet.link import  Link,OVSLink
from mininet.term import makeTerm
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import random
from decimal import Decimal
import subprocess

from tensorflow.python.ops.numpy_ops import floor

import Shared as shared

# Intermed Imports
from intermed.OvsIntermediateMininet import *
from intermed.OvsIntermediate import *
from intermed import OvsIntermediateConstants as consts

class NetworkTopo( Topo ):

    # Calculates the maximum bandwidth for the server host.
    # The calculation is based on the number of client hosts connected to the server.
    def get_server_host_max_bw(self):
        global GLOBALS
        return (GLOBALS.max_host_bw - 0.1) * np.floor(len(GLOBALS.client_hosts_list) / 2) + 0.1

    # Generates the CPU allocation for a host.
    # - Servers and attackers are allocated higher CPU resources compared to normal hosts.
    def generate_host_cpu(self, host):
        global GLOBALS
        if host in GLOBALS.servers:
            return 3
        elif host in GLOBALS.attackers:
            return 3
        else:
            return 1

    # Dynamically generates the bandwidth allocation for a host based on its role.
    # - Servers receive higher bandwidth.
    # - Attackers are assigned dynamic bandwidth for testing DDoS scenarios.
    # - Other hosts get lower bandwidth with slight randomization for diversity.
    def generate_host_bw(self, host):
        global GLOBALS
        if host in GLOBALS.servers:
            return self.get_server_host_max_bw()
        else:
            r = 0
            if host in GLOBALS.attackers:
                r = float((Decimal(random.randint(15, 20)) * Decimal('0.3')) + Decimal('0.1'))
            elif (GLOBALS.unified_host_bandwidth is not None):
                r = GLOBALS.unified_host_bandwidth
            else:
                r = float((Decimal(random.randint(2, 10)) * Decimal('0.3')) + Decimal('0.1')) # 0.7 --> 3.1
            info(f"*** Init host {host} with bw = {r}  ***\n")
            return r

    # Generates bandwidth for a network switch based on its role and position in the network.
    # The core switch (s0) gets higher bandwidth compared to regular switches.
    def generate_switch_bw(self, switch, dst, attacker_default_switch=''):
        global GLOBALS
        r = 0
        if (GLOBALS.unified_switch_bandwidth is not None):
            r = GLOBALS.unified_switch_bandwidth
        else:
            if switch == 's0':
                if False and attacker_default_switch == dst:
                    return self.get_server_host_max_bw()
                else:
                    r = float((Decimal(random.randint(3, 10)) * Decimal('0.3')) + Decimal('0.1'))  # 1 --> 3.1
            else:
                r = float((Decimal(random.randint(16, 30)) * Decimal('0.3')) + Decimal('0.1'))  # 4.9 --> 9.1
        info(f"*** Init switch {switch} {dst} with bw = {r}  ***\n")
        return r

    # Retrieves the network connections for a controlled switch.
    # Provides information such as the connected switches, source and destination interfaces, and bandwidth.
    def get_controlled_switch_connections(self, switch, s0_bandwidthes, switches_bandwidthes):
        global GLOBALS
        connections = {}
        if switch != GLOBALS.s0_switch:
            connections[GLOBALS.s0_switch] = {
                'src_int': shared.get_interface_name(switch, GLOBALS.s0_switch),
                'dst_int': shared.get_interface_name(GLOBALS.s0_switch, switch),
                'bw': f'{s0_bandwidthes[f"{GLOBALS.s0_switch}-{switch}"]}'
            }
            for other_switch in GLOBALS.controlled_switches_list:
                if switch != other_switch:
                    connections[other_switch] = {
                        'src_int': shared.get_interface_name(switch, other_switch),
                        'dst_int': shared.get_interface_name(other_switch, switch),
                        'bw': f'{switches_bandwidthes[f"{switch}-{other_switch}"]}',
                    }
        else:
            for other_switch in GLOBALS.controlled_switches_list:
                connections[other_switch] = {
                    'src_int': shared.get_interface_name(GLOBALS.s0_switch, other_switch),
                    'dst_int': shared.get_interface_name(other_switch, GLOBALS.s0_switch),
                    'bw': f'{s0_bandwidthes[f"{GLOBALS.s0_switch}-{other_switch}"]}'
                }
        return connections


    def get_controlled_switch_interfaces(self, switch, special_interfaces=None):
        if special_interfaces is None:
            special_interfaces = []
        global GLOBALS
        interfaces = []
        if switch != GLOBALS.s0_switch:
            interfaces.append(shared.get_interface_name(switch, GLOBALS.s0_switch))
        for other_switch in GLOBALS.controlled_switches_list:
            if switch != other_switch:
                interfaces.append(shared.get_interface_name(switch, other_switch))
        if switch != GLOBALS.s0_switch:
            for router in GLOBALS.controlled_switch_to_router_relation[switch]['routers']:
                interfaces.append(shared.get_interface_name(switch, router))
        if len(special_interfaces) > 0:
            interfaces.extend(special_interfaces)
        return interfaces

    # Builds the network topology using Mininet's API.
    # Steps include:
    # - Adding switches (core, controlled, and routers).
    # - Assigning bandwidth values for each switch.
    # - Adding hosts with IP, MAC, and bandwidth settings.
    # - Establishing links between switches and hosts with specified bandwidth constraints.
    def build( self, **_opts ):
        global GLOBALS
        info( "*** Creating switches\n" )

        # Server switch (this switch should always be the first to be created)
        s0 = self.addSwitch(GLOBALS.s0_switch)

        GLOBALS.controlled_switches_list = [f's1{i:02d}' for i in range(1, GLOBALS.nbr_controlled_switches + 1)]
        for switch in GLOBALS.controlled_switches_list:
            switch_node = self.addSwitch(switch)

        for switch in GLOBALS.router_switches_list:
            switch_node = self.addSwitch(switch)

        attacker_default_switch = GLOBALS.host_default_switch_relation[GLOBALS.attackers[0]]['default_path_switch']

        s0_bandwidthes = {}
        for switch in GLOBALS.controlled_switches_list:
            s0_bandwidthes[f"{GLOBALS.s0_switch}-{switch}"] = self.generate_switch_bw(GLOBALS.s0_switch, switch, attacker_default_switch)

        switches_bandwidthes = {}
        for switch in GLOBALS.controlled_switches_list:
            for other_switch in GLOBALS.controlled_switches_list:
                if switch != other_switch:
                    key = f"{switch}-{other_switch}"
                    if not key in switches_bandwidthes:
                        switches_bandwidthes[key] = self.generate_switch_bw(switch, other_switch)
                        reversed_key = f"{other_switch}-{switch}"
                        switches_bandwidthes[reversed_key] = switches_bandwidthes[key]

        hosts_bandwidthes = {}
        hosts_bandwidthes[GLOBALS.default_server] = self.generate_host_bw(GLOBALS.default_server)
        for host in GLOBALS.client_hosts_list:
            hosts_bandwidthes[host] = self.generate_host_bw(host)

        GLOBALS.network_spec['switches'] = {
            's0': {
                'ports': self.get_controlled_switch_interfaces("s0", ["s0-eth0", f"s0-eth{GLOBALS.nbr_controlled_switches + 2}"]),
                'connections': self.get_controlled_switch_connections("s0", s0_bandwidthes, switches_bandwidthes)
            }
        }

        for switch in GLOBALS.controlled_switches_list:
            GLOBALS.network_spec['switches'][switch] = {
                'ports': self.get_controlled_switch_interfaces(switch),
                'connections': self.get_controlled_switch_connections(switch, s0_bandwidthes, switches_bandwidthes)
            }



        # Initializing router switches
        for router in GLOBALS.router_switches_list:
            controlled_switch = GLOBALS.router_to_controlled_switch_relation[router]['controlled_switch']
            GLOBALS.network_spec['switches'][router] = {
                'connections': {
                    controlled_switch: {
                        'src_int': shared.get_interface_name(router, controlled_switch),
                        'dst_int': shared.get_interface_name(controlled_switch, router),
                        'bw': f'{hosts_bandwidthes[GLOBALS.router_to_host_relation[router]["host"]]}',
                        'id': 1,
                        'connected': True,
                    }
                },
                'ports': [
                    shared.get_interface_name(router, "0"),
                    shared.get_interface_name(router, controlled_switch)
                ]
            }

        info( "*** Creating hosts\n" )

        GLOBALS.network_spec['hosts'] = {
            GLOBALS.default_server: {
                'ip': '10.0.1.101',
                'router_switch': 's0',
                'src_int': f'{GLOBALS.default_server}-eth0',
                'dst_int': 's0-eth0',
                'connected': True,
                'bw': f'{hosts_bandwidthes[GLOBALS.default_server]}',
                'mac': '00:00:00:00:01:00'
            }
        }

        for host in GLOBALS.client_hosts_list:
            data = {
                'ip': GLOBALS.hosts_raw_topo[host]['ip'],
                'router_switch': GLOBALS.hosts_raw_topo[host]['router_switch'],
                'src_int': host + '-eth0',
                'dst_int': GLOBALS.hosts_raw_topo[host]['router_switch'] + '-eth0',
                'connected': True,
                'bw': f'{hosts_bandwidthes[host]}',
                'mac': GLOBALS.hosts_raw_topo[host]['mac'],
                'current_path': {},
                'default_path_switch': GLOBALS.host_default_switch_relation[host]['default_path_switch']
            }
            for switch in GLOBALS.controlled_switches_list:
                if switch == data['default_path_switch']:
                    data['current_path'][switch] = True
                else:
                    data['current_path'][switch] = False
            GLOBALS.network_spec['hosts'][host] = data

        for host in GLOBALS.network_spec['hosts'].keys():
            ip = GLOBALS.network_spec['hosts'][host]['ip']
            cpu = self.generate_host_cpu(host)
            mac = GLOBALS.network_spec['hosts'][host]['mac']
            info(f"*** Init host {host}({cpu}, {ip}, {mac}) ***\n")
            self.addHost(host, ip=ip, cpu=cpu, mac=mac)

        info( "*** Creating links\n")

        max_switch_queue_size = 10000000
        max_host_queue_size = 10000000

        for src_switch in GLOBALS.controlled_switches_list:
            info(f"*** Init link {src_switch}({GLOBALS.network_spec['switches'][src_switch]['connections']['s0']['src_int']}) --> s0({GLOBALS.network_spec['switches'][src_switch]['connections']['s0']['dst_int']}) with bw = {float(GLOBALS.network_spec['switches'][src_switch]['connections']['s0']['bw'])}  ***\n")
            self.addLink(src_switch, s0, intfName1=GLOBALS.network_spec['switches'][src_switch]['connections']['s0']['src_int'], intfName2=GLOBALS.network_spec['switches'][src_switch]['connections']['s0']['dst_int'], bw=float(GLOBALS.network_spec['switches'][src_switch]['connections']['s0']['bw']), max_queue_size=max_switch_queue_size)

        for src_switch_index in range(len(GLOBALS.controlled_switches_list) - 1):
            for dst_switch_index in range(src_switch_index + 1, len(GLOBALS.controlled_switches_list)):
                src_switch = GLOBALS.controlled_switches_list[src_switch_index]
                dst_switch = GLOBALS.controlled_switches_list[dst_switch_index]
                src_interface = shared.get_interface_name(src_switch, dst_switch)
                dst_interface = shared.get_interface_name(dst_switch, src_switch)
                info(f"*** Init link {src_switch}({src_interface}) --> {dst_switch}({dst_interface}) with bw = {float(GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['bw'])}  ***\n")
                self.addLink(src_switch, dst_switch, intfName1=src_interface, intfName2=dst_interface, bw=float(GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['bw']), max_queue_size=max_switch_queue_size)

        for src_switch in GLOBALS.router_switches_list:
            for dst_switch in (GLOBALS.network_spec['switches'][src_switch]['connections']).keys():
                info(f"*** Init link {src_switch}({GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['src_int']}) --> {dst_switch}({GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['dst_int']}) with bw = {float(GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['bw'])}  ***\n")
                self.addLink(src_switch, dst_switch, intfName1=GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['src_int'], intfName2=GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['dst_int'], bw=float(GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['bw']), max_queue_size=max_switch_queue_size)

        info(f"*** Init link hs({GLOBALS.network_spec['hosts'][GLOBALS.default_server]['src_int']}) --> s0({GLOBALS.network_spec['hosts'][GLOBALS.default_server]['dst_int']}) with bw = {float(GLOBALS.network_spec['hosts'][GLOBALS.default_server]['bw'])}  ***\n")
        self.addLink(s0, GLOBALS.default_server, intfName1=GLOBALS.network_spec['hosts'][GLOBALS.default_server]['dst_int'], intfName2=GLOBALS.network_spec['hosts'][GLOBALS.default_server]['src_int'], params2={'ip': "10.0.1.101/16"}, bw=float(GLOBALS.network_spec['hosts'][GLOBALS.default_server]['bw']), max_queue_size=max_host_queue_size)

        for host in GLOBALS.client_hosts_list:
            router_switch = GLOBALS.network_spec['hosts'][host]['router_switch']
            info(f"*** Init link {host}({GLOBALS.network_spec['hosts'][host]['src_int']}) --> {router_switch}({GLOBALS.network_spec['hosts'][host]['dst_int']}) with bw = {float(GLOBALS.network_spec['hosts'][host]['bw'])}  ***\n")
            self.addLink(router_switch, host, intfName1=GLOBALS.network_spec['hosts'][host]['dst_int'], intfName2=GLOBALS.network_spec['hosts'][host]['src_int'], params2={'ip': f"{GLOBALS.network_spec['hosts'][host]['ip']}/16"}, bw=float(GLOBALS.network_spec['hosts'][host]['bw']), max_queue_size=max_host_queue_size)

# This function initializes and runs the Mininet network simulation.
# Steps include:
# - Cleaning up any existing Mininet configurations.
# - Creating a Mininet instance using the defined `NetworkTopo`.
# - Adding NAT for external internet connectivity.
# - Starting the network and testing connectivity.
# - Initializing flow rules for Open vSwitch (OVS).
# - Launching traffic generators and receivers if needed.
def run_mininet(_GLOBALS):
    global GLOBALS
    GLOBALS = _GLOBALS

    # Clean Mininet context
    process = subprocess.Popen("mn -c", shell=True, stdout=subprocess.PIPE)
    process.wait()

    topo = NetworkTopo()
    GLOBALS.net = Mininet(topo=topo, controller=None, switch=OVSSwitch, waitConnected=False, link=TCLink, host=CPULimitedHost)

    # Create a NAT network connected to s0 (first created switch)
    GLOBALS.net.addNAT().configDefault()

    GLOBALS.net.start()

    info("*** Testing network\n")
    # GLOBALS.net.pingAll()

    for src_switch in GLOBALS.router_switches_list:
        for dst_switch in (GLOBALS.network_spec['switches'][src_switch]['connections']).keys():
            if not GLOBALS.network_spec["switches"][src_switch]['connections'][dst_switch]["connected"]:
                shared.turn_down_link(src_switch, GLOBALS.network_spec['switches'][src_switch]['connections'][dst_switch]['src_int'],
                                      dst_switch, GLOBALS.network_spec["switches"][src_switch]['connections'][dst_switch]["dst_int"])

    if not GLOBALS.manual_receivers:
        host_name = GLOBALS.default_server
        # Creating DITG Receiver in Host -a {shared.get_host_status(host_name)['ip']}
        terminal = makeTerm(GLOBALS.net[host_name], title=f"Host {host_name} DITG-Receiver", cmd=f"nice -n -20 {GLOBALS.ditg_directory}/ITGRecv")
        GLOBALS.net.terms += terminal
        GLOBALS.ditg_receivers.append(terminal)

    for switch in GLOBALS.net.switches:
        print("Switch: ", switch.name)
        GLOBALS.switch_interface_port_mapping[switch.name] = {}
        print("port \t\t intf")
        for interface in switch.ports.keys():
            port = switch.ports[interface]
            print(switch.ports[interface], "\t\t", interface)
            GLOBALS.switch_interface_port_mapping[switch.name][f"{interface}"] = port
    print(GLOBALS.switch_interface_port_mapping)

    # Several Open vSwitch (OVS) flow rules are defined for network traffic management:
    # - ARP flooding rules for default path routing.
    # - Flow rules for controlled and non-controlled switches.
    # - Flow rules for directing traffic to servers.
    commands = []

    # ARP Rules
    # s0
    commands.append(shared.flood_arp_for_icmp_command(target=GLOBALS.s0_switch, priority=GLOBALS.server_switch_flood_priority))

    # ARP Rules - Controlled switches
    commands.extend(shared.init_arp_for_cotnrolled_switches(GLOBALS.controlled_switch_arp_priority,
                                                            GLOBALS.controlled_switch_flood_priority,
                                                            shared.build_switch_info_for_arp()))
    commands.extend(shared.init_arp_for_non_controlled_switches(GLOBALS.non_controlled_switch_arp_priority,
                                                    GLOBALS.router_switches_list))

    # s0 to 8.8.8.8
    commands.append(shared.init_flow_for_global_dns_from_server_switch(GLOBALS.s0_switch, GLOBALS.highest_priority,
                                                                       GLOBALS.global_dns, f"s0-eth{GLOBALS.nbr_controlled_switches + 2}"))

    # s0 to hs
    commands.append(shared.init_flow_from_switch_to_direct_host_via_mac(GLOBALS.s0_switch, GLOBALS.highest_priority,
                                                                        GLOBALS.server_host))

    # S0 -> controlled switch
    commands.extend(shared.init_flow_from_server_switch_to_controlled_switch_for_hosts(GLOBALS.s0_switch, GLOBALS.highest_priority))

    for host in GLOBALS.client_hosts_list:
        router_switch = GLOBALS.network_spec['hosts'][host]['router_switch']
        controlled_switch = GLOBALS.network_spec['hosts'][host]['default_path_switch']

        router_switch_to_host_src_side_interface = GLOBALS.network_spec['hosts'][host]['dst_int']
        router_switch_to_controlled_switch_src_side_interface = shared.get_interface_name(router_switch,
                                                                                          controlled_switch)

        # router switch --> 8.8.8.8 controlled switch
        commands.append(OvsOfctlAddFlowCommand(router_switch, OvsOfctlCommandArguments(
            protocol=consts.OVS_PROTOCOL_IP,
            in_port=f"{GLOBALS.switch_interface_port_mapping[router_switch][router_switch_to_host_src_side_interface]}",
            priority=GLOBALS.highest_priority,
            ip_destination=GLOBALS.global_dns,
            actions=[
                OvsCommandArgumentActionOutput(
                    f"{GLOBALS.switch_interface_port_mapping[router_switch][router_switch_to_controlled_switch_src_side_interface]}")])))

        # router switch --> hs controlled switch
        commands.append(OvsOfctlAddFlowCommand(router_switch, OvsOfctlCommandArguments(
            in_port=f"{GLOBALS.switch_interface_port_mapping[router_switch][router_switch_to_host_src_side_interface]}",
            priority=GLOBALS.highest_priority,
            mac_destination=GLOBALS.network_spec['hosts'][GLOBALS.server_host]['mac'],
            actions=[
                OvsCommandArgumentActionOutput(
                    f"{GLOBALS.switch_interface_port_mapping[router_switch][router_switch_to_controlled_switch_src_side_interface]}")])))

        # router switch -> host
        commands.append(OvsOfctlAddFlowCommand(router_switch, OvsOfctlCommandArguments(
            priority=GLOBALS.highest_priority,
            mac_destination=GLOBALS.network_spec['hosts'][host]['mac'],
            actions=[
                OvsCommandArgumentActionOutput(
                    f"{GLOBALS.switch_interface_port_mapping[router_switch][router_switch_to_host_src_side_interface]}")])))

        controlled_switch_to_router_switch_src_side_interface = shared.get_interface_name(controlled_switch,
                                                                                          router_switch)
        controlled_switch_to_s0_switch_src_side_interface = shared.get_interface_name(controlled_switch,
                                                                                      GLOBALS.s0_switch)

        # controlled switch -> 8.8.8.8 (passing through s0)
        commands.append(OvsOfctlAddFlowCommand(controlled_switch, OvsOfctlCommandArguments(
            protocol=consts.OVS_PROTOCOL_IP,
            priority=GLOBALS.highest_priority,
            ip_destination=GLOBALS.global_dns,
            actions=[
                OvsCommandArgumentActionOutput(
                    f"{GLOBALS.switch_interface_port_mapping[controlled_switch][controlled_switch_to_s0_switch_src_side_interface]}")])))

        # controlled switch -> server (passing through s0)
        commands.append(OvsOfctlAddFlowCommand(controlled_switch, OvsOfctlCommandArguments(
            priority=GLOBALS.highest_priority,
            mac_source=GLOBALS.network_spec['hosts'][host]['mac'],
            mac_destination=GLOBALS.network_spec['hosts'][GLOBALS.server_host]['mac'],
            actions=[
                OvsCommandArgumentActionOutput(
                    f"{GLOBALS.switch_interface_port_mapping[controlled_switch][controlled_switch_to_s0_switch_src_side_interface]}")])))

        # controlled switch -> router switch
        commands.append(OvsOfctlAddFlowCommand(controlled_switch, OvsOfctlCommandArguments(
            priority=GLOBALS.highest_priority,
            mac_destination=GLOBALS.network_spec['hosts'][host]['mac'],
            actions=[
                OvsCommandArgumentActionOutput(
                    f"{GLOBALS.switch_interface_port_mapping[controlled_switch][controlled_switch_to_router_switch_src_side_interface]}")])))

    GLOBALS.ovs = OvsIntermediateMininet(GLOBALS.net, True, True)
    for command in commands:
        GLOBALS.ovs.apply_command(command)

    info( "*** Running CLI\n" )
    GLOBALS.cli = CLI( GLOBALS.net )

    info( "*** Stopping network\n" )
    GLOBALS.net.stop()