import random
import csv
import time
import numpy as np
import json


from Configuration import Configuration
from HttpClient import HttpClient
from CmdManager import CmdManager
from decimal import Decimal
from Util import Util

import tensorflow as tf

class Environment():

    def __init__(self, config):
        print("(Reinforcement) Environment.__init__()")
        self.episodes = config.episodes
        self.steps = config.steps
        self.step_duration = 55 # seconds
        self.attack_duration = 30 # seconds
        self.tshark_processing_duration = 15 # seconds
        self.transmission_time = self.step_duration - self.tshark_processing_duration # = 40 seconds
        self.after_attack_duration = (self.step_duration - self.attack_duration) - self.tshark_processing_duration # = 10 seconds
        self.nbr_non_server_hosts = len(config.client_hosts_list)
        self.nbr_of_servers = 1
        self.nbr_hosts = self.nbr_non_server_hosts + self.nbr_of_servers
        self.hosts = []
        self.hosts_ips = {}
        self.normal_hosts_ips_array = []
        self.hosts_ordered = []
        self.non_server_hosts_ordered = []
        self.interfaces = []
        self.servers = []
        self.normal_hosts = []
        self.attacker_hosts = []
        self.victim_servers = []
        self.nbr_of_attackers = 1
        self.nbr_normal_hosts = self.nbr_hosts - (self.nbr_of_attackers + self.nbr_of_servers)
        self.router_switches_list = config.router_switches_list

        # FROM CONFIG
        self.host_default_switch_relation = config.host_default_switch_relation
        self.router_to_host_relation = config.router_to_host_relation
        self.router_to_controlled_switch_relation = config.router_to_controlled_switch_relation
        self.host_to_router_relation = config.host_to_router_relation


        # RL ENV
        #   # State
        self.nbr_controlled_switches = config.nbr_controlled_switches
        self.nbr_routing_switches = len(config.router_switches_list)
        self.nbr_central_switch = 1
        self.NBR_HOST_STATE_METRICS = 12
        self.nbr_of_network_metrics = 4
        self.arr_shape_data_per_routing_switch = (self.nbr_routing_switches, 1) # vector of bw between routing and controlled switches
        self.arr_shape_data_per_host = (self.nbr_hosts, self.NBR_HOST_STATE_METRICS)
        self.arr_shape_data_per_host_for_path = (self.nbr_hosts - 1, self.nbr_controlled_switches) # array of binary values for activated pathes
        self.arr_shape_data_per_host_for_network_metrics = (self.nbr_normal_hosts, self.nbr_of_network_metrics)
        self.arr_shape_data_per_controlled_switch_for_s0 = (self.nbr_controlled_switches, 1)
        self.arr_shape_data_per_controlled_switch_for_each_others = (int((self.nbr_controlled_switches-1) * self.nbr_controlled_switches / 2.0), 1)
        self.INPUT_SHAPE = int((self.arr_shape_data_per_routing_switch[0] * self.arr_shape_data_per_routing_switch[1]) \
                           + (self.arr_shape_data_per_host[0] * self.arr_shape_data_per_host[1]) \
                           + (self.arr_shape_data_per_host_for_path[0] * self.arr_shape_data_per_host_for_path[1]) \
                           + (self.arr_shape_data_per_host_for_network_metrics[0] * self.arr_shape_data_per_host_for_network_metrics[1]) \
                           + (self.arr_shape_data_per_controlled_switch_for_s0[0] * self.arr_shape_data_per_controlled_switch_for_s0[1]) \
                           + (self.arr_shape_data_per_controlled_switch_for_each_others[0] * self.arr_shape_data_per_controlled_switch_for_each_others[1]))
        self.routing_switches = []
        self.controlled_switches = []

        #   # Actions
        self.NBR_POSSIBLE_HOST_ACTIONS = 2
        self.NBR_POSSIBLE_CONTROLLED_SWITCH_BW_ACTIONS = 2
        self.DECREASE_BW = 0
        self.INCREASE_BW = 1
        self.OUTPUT_SHAPE = (self.nbr_controlled_switches * self.NBR_POSSIBLE_CONTROLLED_SWITCH_BW_ACTIONS) \
                            + ((((self.nbr_controlled_switches - 1) * self.nbr_controlled_switches)/2) * self.NBR_POSSIBLE_CONTROLLED_SWITCH_BW_ACTIONS) \
                            + (self.nbr_routing_switches * self.nbr_controlled_switches) \
                            + 1 # the additional 1 action for Do-Nothing
        self.ACTIONS = []
        self.MAX_DO_NOTHING_ACTION_BEFORE_PENALTY = 5
        self.DO_NOTHING_ACTION_SUCCESSIVE_COUNTER = 0

        # Bandwidth
        self.MIN_BW = 0.01
        self.MAX_BW = 3.1
        self.MAX_SWITCH_BW = 9.1
        self.DECREASING_FACTOR = 0.3
        self.INCREASING_FACTOR = 0.3

        # Reward related factors
        self.alpha_packet_loss = 0 # nullifying alpha 0.05
        self.beta_delay = 1 # concentrating on delay 0.45
        self.tolerable_PKT_loss_percentage = 0.01
        self.tolerable_delay_ms = 2.0  # TODO: Check 29
        self.tolerable_latency_s = 0.0002  # TODO: Check 29
        self.tolerable_jitter_s = 0.0002  # TODO: Check 29
        self.max_PKT_loss_percentage = 0.8
        self.max_delay_ms = 2000 # TODO: Check 29 # originally 400
        self.max_latency_s = 5.5 # TODO: Check 29
        self.max_jitter_s = 5.5 # TODO: Check 29

        # Episode scope variables
        self.last_recorded_delay = 0.0
        self.last_recorded_latency = 0.0
        self.last_recorded_jitter = 0.0
        self.before_last_recorded_delay = 0.0
        self.last_recorded_tx = {}
        self.host_last_recorded_interface_data = {}
        self.last_recorded_bandwidth_monitor = {}

        # TODO: Future improvement (composite action)
        # self.DECREASE_BW = 0
        # self.STAY_BW = 1
        # self.INCREASE_BW = 2

        # Logging
        self.episode_actions_text_list = []

    def update_hosts(self):
        self.hosts = []
        for i in range(1, self.nbr_hosts):
            self.hosts.append(f'h{i}')
        self.hosts.append(f'hs')
        print(f"(Reinforcement) ==> environment.hosts = {self.hosts}")

    # Retrieves and updates the IP addresses for all hosts using the provided HTTP client.
    # The IP addresses are stored in the `self.hosts_ips` dictionary and the normal hosts' IPs in a separate array.
    def update_hosts_ips(self, http_client):
        self.hosts_ips = {}
        self.normal_hosts_ips_array = []
        for host in self.hosts:
            self.hosts_ips[host] = http_client.get_ip_by_host_name(host).text
            print(f"Host {host} has IP {self.hosts_ips[host]}")
            if (host not in self.servers) and (host not in self.attacker_hosts):
                self.normal_hosts_ips_array.append(self.hosts_ips[host])
        print(f"(Reinforcement) ==> environment.hosts_ips = {self.hosts_ips}")

    # Updates the list of network interfaces available in the environment.
    # This is useful for network monitoring and traffic analysis using tools like TShark
    def update_interfaces(self, interfaces):
        self.interfaces = interfaces
        print(f"(Reinforcement) ==> environment.interfaces = {self.interfaces}")

    # Sets up the environment by defining servers, attackers, switches, and available actions.
    # Initializes the roles of hosts, elects attackers and servers, and generates a list of possible actions for the RL agent.
    # This function also prepares switches and links for use in the network simulation.
    def perform_setup(self, http_client, pre_set_attackers):
        self.servers = []
        self.normal_hosts = []
        self.attacker_hosts = []
        self.victim_servers = []

        self.server_election()
        self.attacker_election(pre_set_attackers)

        self.routing_switches = []
        for i in range(1, self.nbr_routing_switches + 1):
            self.routing_switches.append(f's{i}')

        self.controlled_switches = []
        for i in range(1, self.nbr_controlled_switches + 1):
            i_plus_100 = i + 100
            self.controlled_switches.append(f's{i_plus_100}')

        self.hosts_ordered = self.hosts.copy()
        self.ACTIONS = []
        for src_switch in self.controlled_switches:
            for bw_action in range(self.NBR_POSSIBLE_CONTROLLED_SWITCH_BW_ACTIONS):
                self.ACTIONS.append(Util.bw_action(src_switch, 's0', bw_action))
        for src_switch_index in range(0, len(self.controlled_switches) - 1):
            src_switch = self.controlled_switches[src_switch_index]
            for dst_switch_index in range(src_switch_index + 1, len(self.controlled_switches)):
                dst_switch = self.controlled_switches[dst_switch_index]
                for bw_action in range(self.NBR_POSSIBLE_CONTROLLED_SWITCH_BW_ACTIONS):
                    self.ACTIONS.append(Util.bw_action(src_switch, dst_switch, bw_action))
        for host in self.hosts:
            if host not in self.servers:
                for dst_switch in self.controlled_switches:
                    self.ACTIONS.append(Util.redirect_action(host, dst_switch))
        self.ACTIONS.append(Util.nothing_action())

        if(not self.OUTPUT_SHAPE == len(self.ACTIONS)):
            raise Exception(f"Output shape is {self.OUTPUT_SHAPE} but possible actions are {len(self.ACTIONS)}")

        print(f'(Reinforcement) ==> environment.ACTIONS = {self.ACTIONS}')
        print(f'(Reinforcement) ==> len(environment.ACTIONS) = {len(self.ACTIONS)}')

        self.DO_NOTHING_ACTION_SUCCESSIVE_COUNTER = 0
        self.last_recorded_delay = 0.0
        self.last_recorded_latency = 0.0
        self.last_recorded_jitter = 0.0
        self.before_last_recorded_delay = 0.0
        self.last_recorded_tx = {}
        self.last_recorded_rx = {}
        self.host_last_recorded_interface_data = {}
        self.last_recorded_bandwidth_monitor = {}
        self.episode_actions_text_list = []

    # General purpose:
    #   Assigns the server role to a specific host within the environment.
    #   The designated server will receive traffic from other hosts and potentially be a target for attacks.
    # Current behavior:
    #   Single server is present and pre-assigned in the network, which is the "hs" host.
    def server_election(self):
        server = 'hs'
        self.servers.append(server)
        for host in self.hosts:
            if host not in self.servers:
                self.normal_hosts.append(host)

    # Selects attackers and victim servers for a simulated cyber-attack scenario.
    # The selection can be random or based on a predefined list of attackers provided as input.
    # The method ensures that the number of attackers matches the specified configuration.
    # Current usage expects the attacker to be filled in the running command.
    def attacker_election(self, pre_set_attackers):
        found_attackers = 0
        # If attacker is set manually
        if len(pre_set_attackers) == self.nbr_of_attackers:
            for attacker in pre_set_attackers:
                if attacker not in self.attacker_hosts:
                    self.attacker_hosts.append(attacker)
                    self.normal_hosts.remove(attacker)
                    found_attackers = found_attackers + 1

                    victim_server_index = random.randint(0, len(self.servers) - 1)
                    victim_server = self.servers[victim_server_index]

                    if victim_server not in self.victim_servers:
                        self.victim_servers.append(victim_server)

                    print(f'(Reinforcement) ==> Setting attacker {attacker}')
        else:
            while found_attackers < self.nbr_of_attackers:

                attacker_index = random.randint(0, len(self.normal_hosts)-1)
                attacker = self.normal_hosts[attacker_index]

                if attacker not in self.attacker_hosts:
                    self.attacker_hosts.append(attacker)
                    self.normal_hosts.remove(attacker)
                    found_attackers = found_attackers + 1

                    victim_server_index = random.randint(0, len(self.servers) - 1)
                    victim_server = self.servers[victim_server_index]

                    if victim_server not in self.victim_servers:
                        self.victim_servers.append(victim_server)

                    print(f'(Reinforcement) ==> electing attacker {attacker}')

    # Retrieves the interface IDs required for TShark packet capturing.
    # This function maps the network interfaces available on the machine to their respective IDs for packet capturing.
    def get_tshark_interfaces_ids(self, cmd):
        tshark_interfaces = cmd.get_tshark_interfaces()
        tshark_interfaces_ids = ''
        for i in range(len(tshark_interfaces)):
            tshark_interface_components = tshark_interfaces[i].split('.')
            if len(tshark_interface_components) == 2:
                for j in range(len(self.interfaces)):
                    if self.interfaces[j] == tshark_interface_components[1].strip():
                        print(
                            f'(Reinforcement) ==> interface {self.interfaces[j]} has id {tshark_interface_components[0]}')
                        tshark_interfaces_ids = f'{tshark_interfaces_ids} -i {tshark_interface_components[0]}'
        return tshark_interfaces_ids

    # Reads network flow data from a CSV file generated by CICFlowMeter.
    # The data contains flow-level statistics such as packet count, byte count, and timestamps.
    def read_cic_flow_file(self, config):
        print(f'(Reinforcement) ==> Started reading PCAP file {config.cic_output_file_path}')
        data = []
        with open(config.cic_output_file_path, 'r', newline='') as csvfile:
            csv_reader = csv.DictReader(csvfile, delimiter=',')
            for row in csv_reader:
                data.append(row)
        print(f'(Reinforcement) <== Ended reading PCAP file')
        return data

    # Reads network performance metrics from a JSON file.
    # Metrics include delay, jitter, throughput, and packet loss for each host.
    def read_network_metrics_file(self, config):
        print(f'(Reinforcement) ==> Started reading Network metrics file {config.net_metrics_result_file_path}')
        data = {}
        with open(config.net_metrics_result_file_path) as json_file:
            data = json.load(json_file)
        print(f'(Reinforcement) <== Ended reading Network metrics file')
        return data

    # Collects the current state of the network environment by:
    # - Resetting TCP connections
    # - Starting packet sniffing using TShark
    # - Initiating traffic flows and attacks
    # - Collecting data on traffic metrics and network performance
    # This state data is crucial for reinforcement learning decision-making.
    def get_state(self, config, cmd, http_client, tshark_interfaces_ids, sender_receiver_relation,
                  attacker_victim_relation, attack_types):
        http_client.reset_tcp_receivers()
        time.sleep(2)

        cmd.start_tshark_sniffing(tshark_interfaces_ids)

        # Start hosts sending
        for host in sender_receiver_relation:
            server = sender_receiver_relation[host]
            print(f'(Reinforcement) ==> Host {host} sending to server {server}')
            http_client.start_tcp_flow(host, server, self.transmission_time * 1000)
        time.sleep(1)
        # Start attacks
        for attacker in attacker_victim_relation:
            victim_server = attacker_victim_relation[attacker]
            attack_type = attack_types[attacker]
            print(
                f'(Reinforcement) ==> attacker {attacker} is attacking victim {victim_server} with {attack_type} attack')
            http_client.start_mhddos_attack(attacker, victim_server, attack_type)

        time.sleep(self.attack_duration)

        # End attacks
        for attacker in attacker_victim_relation:
            http_client.stop_mhddos_attack(attacker, attacker_victim_relation[attacker])

        time.sleep(self.after_attack_duration)

        http_client.stop_all_tcp_flows()

        # End hosts sending

        time.sleep(self.tshark_processing_duration)

        cmd.stop_tshark_sniffing()

        http_client.stop_tcp_receivers()

        cmd.run_cic()

        cmd.run_network_metrics_calculator(self.hosts_ips[self.servers[0]], 80, self.normal_hosts_ips_array, self.transmission_time, 512)

        # cmd.read_ditg_logs()

        cic_data = self.read_cic_flow_file(config)

        network_metrics = self.read_network_metrics_file(config)

        data_per_host = {}

        for host in self.hosts:  # All hosts (normal hosts, attackers and servers)
            host_data = {'tx_bytes': 0, 'rx_bytes': 0, 'bandwidth': 0,
                         'tx_packets': 0, 'rx_packets': 0, 'tx_packets_len': 0, 'rx_packets_len': 0,
                         'delivered_pkts': 0.0, 'loss_pct': 0.0, 'is_connected': 0,
                         'pkts_s': 0.0, 'bytes_s': 0.0,
                         'non_server_data': {
                             'switches_along_the_path': [],
                             'network_metrics': {}
                         }
                         }
            host_data['is_connected'] = 1 if http_client.get_host_status_connected(host).text == "True" else 0
            switch_interface_statistics = http_client.get_host_interface_statistics(host).text.replace("{", "").replace(
                "}", "").split(",")

            host_data['bandwidth'] = Decimal(http_client.get_host_bw(host).json()['bw'])

            if host not in self.host_last_recorded_interface_data.keys():
                self.host_last_recorded_interface_data[host] = {'tx_bytes': 0, 'rx_bytes': 0}
            for stat in switch_interface_statistics:
                item = stat.strip().split('=')
                key = item[0]
                value = item[1]
                if key == 'rx_bytes':
                    old_tx_bytes = self.host_last_recorded_interface_data[host]['tx_bytes']
                    host_data['tx_bytes'] = int(value) - old_tx_bytes
                    self.host_last_recorded_interface_data[host]['tx_bytes'] = int(value)
                elif key == 'tx_bytes':
                    old_rx_bytes = self.host_last_recorded_interface_data[host]['rx_bytes']
                    host_data['rx_bytes'] = int(value) - old_rx_bytes
                    self.host_last_recorded_interface_data[host]['rx_bytes'] = int(value)
            host_ip = self.hosts_ips[host]
            fwd_host_flow_count = 0  # Counter for flows sent (forwarder) from host/attacker
            for cic_line in cic_data:
                line_pkts_s = float(cic_line['Flow Pkts/s'])
                line_bytes_s = float(cic_line['Flow Byts/s'])
                if (cic_line['Dst Port'] in ['0', '80', '8999']) and line_pkts_s >= 0 and line_bytes_s >= 0 \
                        and (not np.isinf(line_pkts_s)) and (not np.isinf(line_bytes_s)):
                    if cic_line['Src IP'] == host_ip:
                        fwd_host_flow_count = fwd_host_flow_count + 1
                        host_data['tx_packets'] = host_data['tx_packets'] + int(float(cic_line['Tot Fwd Pkts']))
                        host_data['rx_packets'] = host_data['rx_packets'] + int(float(cic_line['Tot Bwd Pkts']))
                        host_data['tx_packets_len'] = host_data['tx_packets_len'] + int(
                            float(cic_line['TotLen Fwd Pkts']))
                        host_data['rx_packets_len'] = host_data['rx_packets_len'] + int(
                            float(cic_line['TotLen Bwd Pkts']))
                        # percentage of transmitted PKTS to total NBR PKTS
                        tx_packets_to_all = float(cic_line['Tot Fwd Pkts']) / (
                                    float(cic_line['Tot Fwd Pkts']) + float(cic_line['Tot Bwd Pkts']))
                        host_data['delivered_pkts'] = host_data['delivered_pkts'] + (
                                    float(cic_line['ACK Flag Cnt']) * tx_packets_to_all)
                    elif cic_line['Dst IP'] == host_ip:
                        # When the host is the Destination, his fwd packets are flow's bwd packets
                        host_data['tx_packets'] = host_data['tx_packets'] + int(float(cic_line['Tot Bwd Pkts']))
                        host_data['rx_packets'] = host_data['rx_packets'] + int(float(cic_line['Tot Fwd Pkts']))
                        host_data['tx_packets_len'] = host_data['tx_packets_len'] + int(
                            float(cic_line['TotLen Bwd Pkts']))
                        host_data['rx_packets_len'] = host_data['rx_packets_len'] + int(
                            float(cic_line['TotLen Fwd Pkts']))
                        rx_packets_to_all = float(cic_line['Tot Bwd Pkts']) / (
                                    float(cic_line['Tot Fwd Pkts']) + float(cic_line['Tot Bwd Pkts']))
                        host_data['delivered_pkts'] = host_data['delivered_pkts'] + (
                                    float(cic_line['ACK Flag Cnt']) * rx_packets_to_all)
            if fwd_host_flow_count > 0:
                # Only if the current host is a sender (normal host/attacker)
                dur = self.transmission_time if host in self.normal_hosts else self.attack_duration
                host_data['pkts_s'] = host_data['tx_packets'] / dur
                host_data['bytes_s'] = host_data['tx_packets_len'] / dur
                host_data['loss_pct'] = (host_data['tx_packets'] - host_data['delivered_pkts']) / host_data['tx_packets']
                if host_data['loss_pct'] <= 0:
                    host_data['loss_pct'] = 0.001

            if host not in self.servers:
                host_path_data = http_client.get_host_path(host).json()
                default_path = host_path_data["default"]
                switches_along_the_path = host_path_data['current']
                router_switch = host_path_data['router']
                host_data['non_server_data']['switches_along_the_path'] = switches_along_the_path
                host_data['non_server_data']['default_path_switch'] = default_path
                host_data['non_server_data']['router_switch'] = router_switch
                if host not in self.attacker_hosts:
                    host_network_metrics = network_metrics[self.hosts_ips[host]]
                    host_data['non_server_data']['network_metrics'] = host_network_metrics
            data_per_host[host] = host_data

        for server in self.servers:
            data_per_host[server]['pkts_s'] = data_per_host[server]['rx_packets'] / (
                        self.attack_duration + self.after_attack_duration)
            data_per_host[server]['bytes_s'] = data_per_host[server]['rx_packets_len'] / (
                        self.attack_duration + self.after_attack_duration)
            data_per_host[server]['loss_pct'] = (data_per_host[server]['rx_packets'] - data_per_host[server][
                'delivered_pkts']) / data_per_host[server]['rx_packets']
            if data_per_host[server]['loss_pct'] <= 0:
                data_per_host[server]['loss_pct'] = 0.001

        data_per_routing_switch = {}
        for src_switch in self.routing_switches:
            data_per_routing_switch[src_switch] = {}
            dst_switches_connected = http_client.get_switch_status_connected(src_switch).json()
            for dst_switch in dst_switches_connected.keys():
                switch_bw = Decimal(http_client.get_switch_bw(src_switch,dst_switch).json()['bw'])
                data_per_routing_switch[src_switch][dst_switch] = {'bw': switch_bw}

        data_per_controlled_switches = {}
        for src_switch in self.controlled_switches:
            dst_switches = http_client.get_dst_switches(src_switch).json()['dst_switches']
            data_per_controlled_switches[src_switch] = {}
            for dst_switch in dst_switches:
               link_information = http_client.get_link_information(src_switch, dst_switch).json()
               switch_bw = Decimal(link_information['bw'])
               data_per_controlled_switches[src_switch][dst_switch] = {'bw': float(switch_bw)}
        return {'host': data_per_host,
                'routing': data_per_routing_switch,
                'controlled': data_per_controlled_switches}

    # Converts the bandwidth data for each controlled switch connected to the central switch (s0) from dictionary into an  array.
    # The array representation is used as input for the reinforcement learning model.
    def transform_state_data_per_controlled_switch_for_s0_dict_to_array(self, data_per_controlled_switches):
        #                               s0
        #                              ----
        #    s101       |  bw_value |  bw, link congestion     |
        #                   :::::::::::::::::::::
        #                   :::::::::::::::::::::
        #                   :::::::::::::::::::::
        #    s104  I        :::::::::::::::::::::
        #
        #   size= 4 * 2

        arr_data_per_controlled_switches_for_s0 = np.zeros(self.arr_shape_data_per_controlled_switch_for_s0)

        switch_index = 0
        for src_switch in self.controlled_switches:
            dst_switch = 's0'
            metric_index = 0
            for metric_name in data_per_controlled_switches[src_switch][dst_switch]:
                arr_data_per_controlled_switches_for_s0[switch_index, metric_index] = data_per_controlled_switches[src_switch][dst_switch][metric_name]
                metric_index = metric_index + 1
            switch_index = switch_index + 1

        return arr_data_per_controlled_switches_for_s0

    # Converts data representing the bandwidth usage between each pair of controlled switches into an array.
    def transform_state_data_per_controlled_switch_for_each_others_to_array(self, data_per_controlled_switches):
        #                           s102                                       s103                          s104
        #         #                   ----
        #         #    s101    |  bw, link congestion|                  |  bw, link congestion|        |  bw, link congestion|
        #         #    s102               x                             |  bw, link congestion|        |  bw, link congestion|
        #         #     ::::::::::::::::::::
        #         #    s103              x                                       x                     |  bw, link congestion|
        #         #    s104  I           x                                         x                            x
        #
        #   size= 6 * 2 (after passing through the upper part of the matrix would be:)

        #    s101    |  bw, link congestion|
        #    s101
        #    s101    ::::::::::::::::::::
        #    s102
        #    s102
        #    s103
        #
        arr_data_per_controlled_switches_for_each_others = np.zeros(self.arr_shape_data_per_controlled_switch_for_each_others)

        arr_line_index = 0
        for src_switch_index in range(len(self.controlled_switches) - 1): # 0 to 2 (included)
            src_switch = self.controlled_switches[src_switch_index]
            for dst_switch_index in range(src_switch_index + 1, len(self.controlled_switches)):
                dst_switch = self.controlled_switches[dst_switch_index]
                metric_index = 0
                for metric_name in data_per_controlled_switches[src_switch][dst_switch].keys():
                    arr_data_per_controlled_switches_for_each_others[arr_line_index, metric_index] = data_per_controlled_switches[src_switch][dst_switch][metric_name]
                    metric_index = metric_index + 1
                arr_line_index = arr_line_index + 1

        return arr_data_per_controlled_switches_for_each_others

    # Converts host-related data such as transmitted packets, received packets, bandwidth usage, and packet loss
    #   from dictionary into array.
    # This  format is used for feeding data into the reinforcement learning model.
    def transform_state_data_per_host_dict_to_data_per_host_array(self, data_per_host):

        arr_data_per_host = np.zeros(self.arr_shape_data_per_host)
        # current state is a dictionary of 14 value for 4 variables
        # DDQN Input:
        # nn_input: Array of 6 * 13

        #                       1                 2           3           4          5           6              7               8             9       10            11        12
        #                       tx_bytes        rx_bytes   bandwidth    tx_packets  rx_packets   tx_packets_len  rx_packets_len  delivered_pkts  loss_pct  is_connected  pkts_s  bytes_s
        #                   --------------- -------------- -----------  --------   ---------   --------    --------------   -------------    -------   -------   ---------   -----    -------   -----------------------------------
        #    h1     |          |           |                |           |           |           |          |           |                   |           |           |           |               |           |
        #
        #    h2  I          --------------- -------------- -----------  --------   ---------   --------    --------------   -------------    -------   -------   ---------   -----    -------   ---------------------
        #                   - |           |                |           |           |           |          |           |                   |           |           |           |               |           |
        #    :              --------------- -------------- -----------  --------   ---------   --------    --------------   -------------    -------   -------   ---------   -----    -------   ---------------------
        #                    |           |                |           |           |           |          |           |                   |           |           |           |               |           |
        #    :              --------------- -------------- -----------  --------   ---------   --------    --------------   -------------    -------   -------   ---------   -----    -------   ---------------------
        #                    |           |                |           |           |           |          |           |                   |           |           |           |               |           |
        #    hn            --------------- -------------- -----------  --------   ---------   --------    --------------   -------------    -------   -------   ---------   -----    -------   ---------------------
        #
        host_index = 0
        for host in self.hosts_ordered:
            metric_index = 0
            for metric in data_per_host[host]:
                if metric != 'non_server_data':
                    arr_data_per_host[host_index, metric_index] = data_per_host[host][metric]
                    metric_index = metric_index + 1
            host_index = host_index + 1
        return arr_data_per_host.astype(np.float64)

    # Converts host path data into a binary array indicating which controlled switches are used along the network path for each host.
    def transform_state_data_per_host_dict_to_data_per_host_for_path_array(self, data_per_host):
        # 6*4
        arr_data_per_host_for_path = np.zeros(self.arr_shape_data_per_host_for_path)
        host_index = 0
        for host in self.hosts_ordered:
            if host not in self.servers:
                switch = data_per_host[host]['non_server_data']['switches_along_the_path'][0]
                for j in range(0, self.nbr_controlled_switches):
                    if switch == self.controlled_switches[j]:
                        arr_data_per_host_for_path[host_index, j] = 1
                    else:
                        arr_data_per_host_for_path[host_index, j] = 0
                host_index = host_index + 1
        return arr_data_per_host_for_path.astype(np.float64)


    def transform_state_data_per_host_dict_to_data_per_host_for_network_metrics_array(self, data_per_host):
        # 6*4
        arr_data_per_host_for_network_metrics = np.zeros(self.arr_shape_data_per_host_for_network_metrics)
        host_index = 0
        for host in self.hosts_ordered:
            if (host not in self.servers) and (host not in self.attacker_hosts):
                metrics = data_per_host[host]['non_server_data']['network_metrics']
                i = 0
                for metric_key in metrics.keys():
                    arr_data_per_host_for_network_metrics[host_index][i] = metrics[metric_key]
                    i += 1
                host_index = host_index + 1
        return arr_data_per_host_for_network_metrics.astype(np.float64)

    # Converts routing switch data (bandwidth and link congestion) from dictionary into an array.
    def transform_state_data_per_routing_switch_dict_to_data_per_routing_switch_array(self, data_per_routing_switch):
        # 6*1
        arr_data_per_routing_switch = np.zeros(self.arr_shape_data_per_routing_switch)

        routing_switch_index = 0
        for src_routing_switch in self.routing_switches:
            dst_switch = list(data_per_routing_switch[src_routing_switch].keys())[0]
            bandwidth = Decimal(data_per_routing_switch[src_routing_switch][dst_switch]['bw'])
            arr_data_per_routing_switch[routing_switch_index, 0] = bandwidth
            routing_switch_index = routing_switch_index + 1

        return arr_data_per_routing_switch.astype(np.float64)

    # Applies fixed normalization to input data using specified ranges for each feature.
    def fixed_normalization(self, features_transposed, current_range, normed_range):
        # Source https://stackoverflow.com/questions/50346017/how-to-normalize-input-data-for-models-in-tensorflow
        current_min, current_max = tf.expand_dims(current_range[:, 0], 1), tf.expand_dims(current_range[:, 1], 1)
        normed_min, normed_max = tf.expand_dims(normed_range[:, 0], 1), tf.expand_dims(normed_range[:, 1], 1)
        x_normed = (features_transposed - current_min) / (current_max - current_min)
        x_normed = x_normed * (normed_max - normed_min) + normed_min
        return x_normed

    # Normalizes and scales the host state data to ensure it fits within a consistent range of [0, 1].
    # This is crucial for effective training of the reinforcement learning model
    def normalize_and_scale_state_data_per_host_array(self, data_per_host):
        features = tf.transpose(data_per_host)
        max_tx_bytes = 400000000.0
        max_rx_bytes = 400000000.0
        max_tx_packets = max_tx_bytes / 512  # mean packet size to be 512
        max_rx_packets = max_rx_bytes / 512  # mean packet size to be 512
        min_duration_s = self.attack_duration
        max_pkts_s = max(max_tx_packets, max_rx_packets) / min_duration_s
        max_bytes_s = max_pkts_s * 512
        feature_ranges = np.array([[0.0, max_tx_bytes], # tx_bytes
                          [0.0, max_rx_bytes], # rx_bytes
                          [self.MIN_BW, self.MAX_BW * 6], # bandwidth
                          [0.0, max_tx_packets], # tx_packets
                          [0.0, max_rx_packets], # rx_packets
                          [0.0, max_tx_bytes], # tx_packets_len
                          [0.0, max_rx_bytes], # rx_packets_len
                          [0.0, max_rx_packets], # delivered_pkts
                          [0.0, 1.0], # loss_pct
                          [0.0, 1.0], # is_connected
                          [0.0, max_pkts_s], # pkts_s
                          [0.0, max_bytes_s] # bytes_s
                          ])
        features = self.fixed_normalization(features, feature_ranges, np.array([[0.0, 1.0]]))
        print(np.max(features))
        if np.max(features) > 1:
            print(features)
            raise Exception("normalization problem in (normalize_and_scale_state_data_per_host_array)")
        return tf.transpose(features)

    def normalize_and_scale_state_data_per_host_for_path_array(self, data_per_host_for_path_array):
        features = tf.transpose(data_per_host_for_path_array)

        feature_ranges = np.array([[0.0, 1.0]] * self.nbr_controlled_switches)
        features = self.fixed_normalization(features, feature_ranges, np.array([[0.0, 1.0]]))
        print(np.max(features))
        if np.max(features) > 1:
            print(features)
            raise Exception("normalization problem in (normalize_and_scale_state_data_per_host_for_path_array)")
        return tf.transpose(features)

    def normalize_and_scale_state_data_per_host_for_network_metrics_array(self, data_per_host_for_path_array):
        features = tf.transpose(data_per_host_for_path_array)
        feature_ranges = np.array([[0.0, 30.0],
                          [0.0, 30.0],
                          [0.0, 4000000.0],
                          [0.0, 30.0]
                          ])
        features = self.fixed_normalization(features, feature_ranges, np.array([[0.0, 1.0]]))
        print(np.max(features))
        if np.max(features) > 1:
            print(features)
            raise Exception("normalization problem in (normalize_and_scale_state_data_per_host_for_network_metrics_array)")
        return tf.transpose(features)

    def normalize_and_scale_data_per_routing_switch_array(self, data_per_routing_switch):
        features = tf.transpose(data_per_routing_switch)
        feature_ranges = np.array([[self.MIN_BW, self.MAX_SWITCH_BW]])
        features = self.fixed_normalization(features, feature_ranges, np.array([[0.0, 1.0]]))
        print(np.max(features))
        if np.max(features) > 1:
            print(features)
            raise Exception("normalization problem in (normalize_and_scale_data_per_routing_switch_array)")
        return tf.transpose(features)

    def normalize_and_scale_data_per_controlled_switch_for_s0_array(self, arr_data_per_controlled_switch_for_s0):
        features = tf.transpose(arr_data_per_controlled_switch_for_s0)  # 2 * 4
        feature_ranges = np.array([[self.MIN_BW, self.MAX_SWITCH_BW],
                                   # [0.0, 1.0]]) # link congestion
                                   ]) # link congestion
        features = self.fixed_normalization(features, feature_ranges, np.array([[0.0, 1.0]]))
        print(np.max(features))
        if np.max(features) > 1:
            print(features)
            raise Exception("normalization problem in (normalize_and_scale_data_per_controlled_switch_for_s0_array)")
        return tf.transpose(features)

    def normalize_and_scale_data_per_controlled_switch_for_each_others_array(self, arr_data_per_controlled_switch_for_each_others):
        features = tf.transpose(arr_data_per_controlled_switch_for_each_others) # 2 * 6
        feature_ranges = np.array([[self.MIN_BW, self.MAX_SWITCH_BW],
                                   # [0.0, 1.0]]) # link congestion
                                   ]) # link congestion
        features = self.fixed_normalization(features, feature_ranges, np.array([[0.0, 1.0]]))
        print(np.max(features))
        if np.max(features) > 1:
            print(features)
            raise Exception("normalization problem in (normalize_and_scale_data_per_controlled_switch_for_each_others_array)")
        return tf.transpose(features)

    def calculate_max_scale(self, max_attackers, max_hosts, max_servers):
        return max(max_attackers, max_hosts, max_servers)


    def transform_state_dict_to_normalized_vector(self, state):
        print("\narr_data_per_host")
        arr_data_per_host = self.transform_state_data_per_host_dict_to_data_per_host_array(state['host'])
        print(f"{arr_data_per_host}\n")
        normalized_arr_data_per_host = self.normalize_and_scale_state_data_per_host_array(arr_data_per_host)

        print("\narr_data_per_host_for_path")
        arr_data_per_host_for_path = self.transform_state_data_per_host_dict_to_data_per_host_for_path_array(state['host'])
        print(f"{arr_data_per_host_for_path}\n")
        normalized_arr_data_per_host_for_path = self.normalize_and_scale_state_data_per_host_for_path_array(arr_data_per_host_for_path)

        print("\narr_data_per_host_for_network_metrics")
        arr_data_per_host_for_network_metrics = self.transform_state_data_per_host_dict_to_data_per_host_for_network_metrics_array(state['host'])
        print(f"{arr_data_per_host_for_network_metrics}\n")
        normalized_arr_data_per_host_for_network_metrics = self.normalize_and_scale_state_data_per_host_for_network_metrics_array(arr_data_per_host_for_network_metrics)

        print("\ndata_per_routing_switch")
        data_per_routing_switch = self.transform_state_data_per_routing_switch_dict_to_data_per_routing_switch_array(state['routing'])
        print(f"{data_per_routing_switch}\n")
        normalized_data_per_routing_switch = self.normalize_and_scale_data_per_routing_switch_array(data_per_routing_switch)

        print("\narr_data_per_controlled_switch_for_s0")
        arr_data_per_controlled_switch_for_s0 = self.transform_state_data_per_controlled_switch_for_s0_dict_to_array(state['controlled'])
        print(f"{arr_data_per_controlled_switch_for_s0}\n")
        normalized_arr_data_per_controlled_switch_for_s0 = self.normalize_and_scale_data_per_controlled_switch_for_s0_array(arr_data_per_controlled_switch_for_s0)

        print("\narr_data_per_controlled_switch_for_each_others")
        arr_data_per_controlled_switch_for_each_others = self.transform_state_data_per_controlled_switch_for_each_others_to_array(state['controlled'])
        print(f"{arr_data_per_controlled_switch_for_each_others}\n")
        normalized_arr_data_per_controlled_switch_for_each_others = self.normalize_and_scale_data_per_controlled_switch_for_each_others_array(arr_data_per_controlled_switch_for_each_others )

        return np.concatenate((normalized_arr_data_per_host.numpy().flatten(),
                              normalized_arr_data_per_host_for_path.numpy().flatten(),
                              normalized_arr_data_per_host_for_network_metrics.numpy().flatten(),
                              normalized_data_per_routing_switch.numpy().flatten(),
                              normalized_arr_data_per_controlled_switch_for_s0.numpy().flatten(),
                              normalized_arr_data_per_controlled_switch_for_each_others.numpy().flatten()))

    # Applies a selected action to the controlled switches in the network.
    # Depending on the action, it may adjust bandwidth, redirect traffic, or do nothing.
    # The function also calculates the reward based on the effects of the action.
    def apply_action_controlled_switches(self, config: Configuration, cmd: CmdManager, http_client: HttpClient,
                                         tshark_interfaces_ids, sender_receiver_relation, attacker_victim_relation,
                                         attack_types, action: int, is_predicted):
        predicted_or_random_label = "predicted" if is_predicted else "random"
        ACTION = self.ACTIONS[action]
        print(f"(Reinforcement) ==> Applying {predicted_or_random_label} action: {action} <==> {ACTION}")
        action_can_be_taken = False
        self.DO_NOTHING_ACTION_SUCCESSIVE_COUNTER = 0
        ACTIONS_splitted = ACTION.split(':')

        action_message = "none"
        if ACTIONS_splitted[0] == "bw":
            src_switch = ACTIONS_splitted[1]
            dst_switch = ACTIONS_splitted[2]
            action_number = int(ACTIONS_splitted[3])
            switch_bw = Decimal(http_client.get_switch_bw(src_switch, dst_switch).json()['bw'])
            print(f"(Reinforcement) ==> link {src_switch}<->{dst_switch} has BW={switch_bw}")
            if action_number == self.DECREASE_BW and switch_bw - Decimal(self.DECREASING_FACTOR) >= Decimal( f'{self.MIN_BW}'):
                http_client.decrease_switch_bw(src_switch, dst_switch, self.DECREASING_FACTOR)
                action_can_be_taken = True
                action_message = f"Applying {predicted_or_random_label} action: {action} => DECREASE_BW: {src_switch} ==> {dst_switch} ==> Applied"
                print(f"(Reinforcement) ==> {action_message}")
            elif action_number == self.INCREASE_BW and switch_bw + Decimal(self.INCREASING_FACTOR) <= Decimal(f'{self.MAX_SWITCH_BW}'):
                http_client.increase_switch_bw(src_switch, dst_switch, self.INCREASING_FACTOR)
                action_can_be_taken = True
                action_message = f"Applying {predicted_or_random_label} action: {action} => INCREASE_BW: {src_switch} ==> {dst_switch} ==> Applied"
                print(f"(Reinforcement) ==> {action_message}")
            elif action_number == self.DECREASE_BW or action_number == self.INCREASE_BW:
                action_can_be_taken = False
                action_message = f"Action {predicted_or_random_label}: {action} cannot be taken because link {src_switch}<->{dst_switch} has already BW={switch_bw}"
                print(f"(Reinforcement) ==> {action_message}")
            else:
                raise Exception(f"Unknown action number {action_number}=int({ACTIONS_splitted[3]})!!")
        elif ACTIONS_splitted[0] == "redirect":
            host_name = ACTIONS_splitted[1]
            dst_switch = ACTIONS_splitted[3]
            host_path_response = http_client.get_host_path(host_name).json()
            current_path = host_path_response['current']
            if dst_switch in current_path:
                action_can_be_taken = False
                action_message = f"Action {predicted_or_random_label}: {action} cannot be taken for {host_name} as {dst_switch} is already in the path"
            else:
                action_can_be_taken = True
                http_client.redirect_switch_flow(host_name, dst_switch)
                action_message = f"Applying {predicted_or_random_label} action: {action} => REDIRECT: {host_name} ==> {dst_switch} ==> Applied"
            print(f"(Reinforcement) ==> {action_message}")
        elif ACTIONS_splitted[0] == Util.nothing_action():
            self.DO_NOTHING_ACTION_SUCCESSIVE_COUNTER += 1
            action_message = f"Applying {predicted_or_random_label} action: {action} => DO Nothing"
            print(f"(Reinforcement) ==> {action_message}")
        else:
            action_can_be_taken = False
        new_state = self.get_state(config, cmd, http_client, tshark_interfaces_ids, sender_receiver_relation,
                  attacker_victim_relation, attack_types)

        reward, done, avg_PKT_loss_percentage, avg_real_delay, avg_latency, avg_jitter = self.calculate_reward(new_state, action_can_be_taken)
        self.episode_actions_text_list.append([ACTION, action_message])
        return (new_state, reward, done, avg_PKT_loss_percentage, avg_real_delay, avg_latency, avg_jitter)

    # Calculates the average packet loss percentage across all hosts.
    def calculate_loss(self, state):
        print("(Reinforcement) ==> Calculating loss")
        total_loss_pct = 0
        for host in self.normal_hosts:
            total_loss_pct = total_loss_pct + state['host'][host]['loss_pct']
        avg_PKT_loss_percentage = total_loss_pct / self.nbr_normal_hosts
        print(f'(Reinforcement) ====> Calculated avg_loss = {avg_PKT_loss_percentage} %')
        return avg_PKT_loss_percentage

    # Delay is measured as the time taken for packets to reach their destination.
    def calculate_delay(self, state):
        print("(Reinforcement) ==> Calculating delay")
        sum_real_delay = 0
        transmission_time_ms = (self.transmission_time * 1000)
        for host in self.normal_hosts:
            host_delay = 0
            if state['host'][host]['delivered_pkts'] == 0:
                host_delay = transmission_time_ms
            else:
                host_delay = (transmission_time_ms / state['host'][host]['delivered_pkts'])
            print(f'(Reinforcement) ====> Host {host} has real delay of {host_delay} ms')
            sum_real_delay = sum_real_delay + host_delay

        max_real_delay = self.max_delay_ms  # transmission_time_ms 30000 ms => 600 ms
        avg_real_delay = sum_real_delay / self.nbr_normal_hosts  # ms (for packet)
        print(f'(Reinforcement) ====> Calculated avg_real_delay = {avg_real_delay} ms')

        return avg_real_delay

    # Calculates the average throughput across all hosts in bits per second (bps).
    def calculate_throughput(self, state):
        print("(Reinforcement) ==> Calculating throughput")
        sum_throughput = 0
        for host in self.normal_hosts:
            host_throughput = state['host'][host]['non_server_data']['network_metrics']['throughput_bps']
            print(f'(Reinforcement) ====> Host {host} has throughput of {host_throughput} bps')
            sum_throughput = sum_throughput + host_throughput
        avg_throughput = sum_throughput / self.nbr_normal_hosts
        print(f'(Reinforcement) ====> Calculated avg_throughput = {avg_throughput} bps')
        return avg_throughput

    # This function measures the time it takes for a packet to travel through the network and go back to its source
    def calculate_latency(self, state):
        print("(Reinforcement) ==> Calculating latency")
        sum_latency = 0
        for host in self.normal_hosts:
            host_latency = state['host'][host]['non_server_data']['network_metrics']['avg_latency_s']
            print(f'(Reinforcement) ====> Host {host} has latency of {host_latency} s')
            sum_latency = sum_latency + host_latency
        avg_latency = sum_latency / self.nbr_normal_hosts
        print(f'(Reinforcement) ====> Calculated avg_latency = {avg_latency} s')
        return avg_latency

   # This metric indicates the average of inter-arrival times of packets to their destinations
    def calculate_jitter(self, state):
        print("(Reinforcement) ==> Calculating jitter")
        sum_jitter = 0
        for host in self.normal_hosts:
            host_jitter = state['host'][host]['non_server_data']['network_metrics']['avg_jitter_s']
            print(f'(Reinforcement) ====> Host {host} has jitter of {host_jitter} s')
            sum_jitter = sum_jitter + host_jitter
        avg_jitter = sum_jitter / self.nbr_normal_hosts
        print(f'(Reinforcement) ====> Calculated avg_jitter = {avg_jitter} s')
        return avg_jitter

    def calculate_real_delay_reward(self, action_can_be_taken, avg_real_delay):
        done = False
        if avg_real_delay >= self.max_delay_ms:
            reward = -3  # -2.5 (original value)
            done = True
        elif avg_real_delay <= self.tolerable_delay_ms:
            reward = 3  # +2.5 (original value)
            done = True
        elif self.DO_NOTHING_ACTION_SUCCESSIVE_COUNTER > self.MAX_DO_NOTHING_ACTION_BEFORE_PENALTY:
            reward = -0.5  # -0.5 (original value)
            done = False
        elif not action_can_be_taken:
            reward = -2
            done = False
        else:
            if avg_real_delay - 0.2 >= self.last_recorded_delay:
                reward = -1
            elif avg_real_delay + 0.2 <= self.last_recorded_delay:
                reward = 1
            else:
                reward = -0.1
            done = False
        self.last_recorded_delay = avg_real_delay
        return reward, done

    def calculate_latency_reward(self, action_can_be_taken, avg_latency):
        done = False
        if avg_latency >= self.max_latency_s:
            reward = -3  # -2.5 (original value)
            done = True
        elif avg_latency <= self.tolerable_latency_s:
            reward = 3  # +2.5 (original value)
            done = True
        elif self.DO_NOTHING_ACTION_SUCCESSIVE_COUNTER > self.MAX_DO_NOTHING_ACTION_BEFORE_PENALTY:
            reward = -0.5  # -0.5 (original value)
            done = False
        elif not action_can_be_taken:
            reward = -1
            done = False
        else:
            if avg_latency - 0.002 >= self.last_recorded_latency:
                reward = -1
            elif avg_latency + 0.002 <= self.last_recorded_latency:
                reward = 1
            else:
                reward = -0.1
            done = False
        self.last_recorded_latency = avg_latency
        print(f"(Reinforcement) =====> Calculated latency reward as {reward} (done=>{done})")
        return reward, done

    def calculate_jitter_reward(self, action_can_be_taken, avg_jitter):
        done = False
        if avg_jitter >= self.max_jitter_s:
            reward = -3  # -2.5 (original value)
            done = True
        elif avg_jitter <= self.tolerable_jitter_s:
            reward = 3  # +2.5 (original value)
            done = True
        elif self.DO_NOTHING_ACTION_SUCCESSIVE_COUNTER > self.MAX_DO_NOTHING_ACTION_BEFORE_PENALTY:
            reward = -0.5  # -0.5 (original value)
            done = False
        elif not action_can_be_taken:
            reward = -1
            done = False
        else:
            if avg_jitter - 0.002 >= self.last_recorded_jitter:
                reward = -1
            elif avg_jitter + 0.002 <= self.last_recorded_jitter:
                reward = 1
            else:
                reward = -0.1
            done = False
        self.last_recorded_jitter = avg_jitter
        print(f"(Reinforcement) =====> Calculated jitter reward as {reward} (done=>{done})")
        return reward, done

    # Calculates the reward for the reinforcement learning agent based on multiple network performance metrics.
    # Rewards are calculated using latency and jitter to guide the agent's learning process.
    def calculate_reward(self, state, action_can_be_taken):
        print("(Reinforcement) ==> Calculating reward")

        avg_PKT_loss_percentage = self.calculate_loss(state)
        avg_real_delay = self.calculate_delay(state)
        avg_throughput = self.calculate_throughput(state)
        avg_latency = self.calculate_latency(state)
        avg_jitter = self.calculate_jitter(state)

        # TODO: clean if delay not needed at all
        # r1, d1 = self.calculate_real_delay_reward(action_can_be_taken, avg_real_delay)
        r1 = 0
        d1 = False
        r2, d2 = self.calculate_latency_reward(action_can_be_taken, avg_latency)
        r3, d3 = self.calculate_jitter_reward(action_can_be_taken, avg_jitter)

        reward = r1 + r2 + r3
        # Set (done) to False in order to calibrate the system
        # done = False
        done = d1 or d2 or d3

        print(f"(Reinforcement) <-----> result after calculating reward = {reward} (done={done})")
        return reward, done, avg_PKT_loss_percentage, avg_real_delay, avg_latency, avg_jitter

    # Resets the environment to its initial state, clearing all episode data and network configurations.
    def reset(self):
        print("----> Environment reset")

    # Prints a human-readable description of the selected action for debugging purposes.
    def print_action(self, action):
        if action is not None:
            if action == self.DECREASE_BW:
                print("### Choosing Decrease")
            elif action == self.INCREASE_BW:
                print("### Choosing Increase")
            else:
                print("### Choosing Same")