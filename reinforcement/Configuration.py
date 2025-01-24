from datetime import datetime
import json
import os

class Configuration():

    def __init__(self, hosts_topo_file_name, episodes, steps, epsilon_decay, nbr_controlled_switches):
        print("(Reinforcement) Configuration.__init__()")
        # API
        self.api_link = "http://localhost:5000"

        # Network
        self.network_dir = os.getcwd() + "/../network"
        self.network_entrypoint = f'{self.network_dir}/EntryPoint.py'
        self.network_command = f'python3 {self.network_entrypoint} --servers [SERVERS] --attackers [ATTACKERS] --hosts-topo-file [HOSTS_FILE] --nbr-controlled-switches [NBR_CONTROLLED_SWITCHES] --manuel-receivers'

        # Temp directory
        self.tmp_dir = os.getcwd() + "/tmp"

        # TShark Config
        self.tshark_interfaces_command = 'tshark -D'
        self.tshark_pcap_file_name = 'tshark_out.pcap'
        self.tshark_pcap_file_path = f'{self.tmp_dir}/{self.tshark_pcap_file_name}'
        self.tshark_sniffing_command = f'tshark [INTERFACES] -w {self.tshark_pcap_file_path}'  # INTERFACES to be replaced e.g: -i 1 -i 2

        # CIC Flow Meter Configuration
        self.cic_output_dir = f'{self.tmp_dir}/cic_out'
        self.cic_dir = "/home/mininet-user/CIC/CICFlowMeter"
        self.cic_command = f'gradle --settings-file {self.cic_dir}/settings.gradle exeCMD -Psource="{self.tshark_pcap_file_path}" -Pdestination="{self.cic_output_dir}"'
        self.cic_output_file_path = f'{self.cic_output_dir}/{self.tshark_pcap_file_name}_Flow.csv'

        # DITG logs
        self.ditg_directory = '/home/mininet-user/D-ITG-2.8.1-r1023-src/D-ITG-2.8.1-r1023/bin'
        self.ditg_logs_file_path = f'{self.tmp_dir}/ITGRecv.log'
        self.ditg_logs_command = f'{self.ditg_directory}/ITGDec {self.ditg_logs_file_path}'

        # Network PCAP metrics calculator
        self.net_metrics_calculator_path = f'{os.getcwd()}/NetMetricsCalculator.py'
        self.net_metrics_result_file_path = f'{self.tmp_dir}/metrics.json'
        self.net_metrics_command = f'python3 {self.net_metrics_calculator_path} -s [SERVER_IP] -p [SERVER_PORT] -hip [HOSTS_IPS] -t [DURATION] -b [BYTES]'

        # Results folder
        self.results_folder = os.getcwd() + "/results"
        if not os.path.exists(self.results_folder):
            os.makedirs(self.results_folder)
        self.running_time = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        self.current_train_folder = f"{self.results_folder}/train_{self.running_time}"
        if not os.path.exists(self.current_train_folder):
            os.makedirs(self.current_train_folder)
        # Figures
        self.figures_folder = self.current_train_folder + "/figs"
        if not os.path.exists(self.figures_folder):
            os.makedirs(self.figures_folder)
        print(f"(Reinforcement) ==> All figures will be saved in {self.figures_folder}")

        # information about attacker, server, normal hosts
        self.data_folder = self.current_train_folder + "/data"
        if not os.path.exists(self.data_folder):
            os.makedirs(self.data_folder)
        print(f"(Reinforcement) ==> All data will be saved in {self.data_folder}")

        # CIC results
        self.cic_folder = self.current_train_folder + "/cic"
        if not os.path.exists(self.cic_folder):
            os.makedirs(self.cic_folder)
        print(f"(Reinforcement) ==> All CIC results will be saved in {self.cic_folder}")

        # RL Models
        self.rl_models_folder = self.current_train_folder + "/models"
        if not os.path.exists(self.rl_models_folder):
            os.makedirs(self.rl_models_folder)
        print(f"(Reinforcement) ==> All RL Models will be saved in {self.rl_models_folder}")

        # Prefilled actions file
        self.prefilled_actions_file = os.getcwd() + "/prefilled-actions.txt"
        print(f"(Reinforcement) ==> If actions are prefilled, they will be read from {self.prefilled_actions_file}")

        # Rewards
        self.rl_stats_folder = self.current_train_folder + "/rl_stats"
        if not os.path.exists(self.rl_stats_folder):
            os.makedirs(self.rl_stats_folder)
        print(f"(Reinforcement) ==> All RL Stats (rewards, etc...) will be saved in {self.rl_stats_folder}")

        # Configs
        self.configs_folder = self.current_train_folder + "/configs"
        if not os.path.exists(self.configs_folder):
            os.makedirs(self.configs_folder)
        print(f"(Reinforcement) ==> All Configs will be saved in {self.configs_folder}")

        # Network Hosts
        self.hosts_topo_file_name = hosts_topo_file_name
        self.hosts_topo_file_directory = f'{os.getcwd()}/../input-data'
        self.hosts_topo_file_path = f'{self.hosts_topo_file_directory}/{self.hosts_topo_file_name}'
        self.client_hosts_list = []
        self.host_default_switch_relation = {}
        self.router_to_host_relation = {}
        self.host_to_router_relation = {}
        self.router_switches_list = []
        self.router_to_controlled_switch_relation = {}
        self.controlled_switch_to_router_relation = {}
        self.read_hosts_topology_file()

        # Inputs configs
        self.episodes = episodes
        self.steps = steps
        self.epsilon_decay = epsilon_decay
        self.nbr_controlled_switches = nbr_controlled_switches

    def read_hosts_topology_file(self):
        print(f"(Reinforcement) ==> Reading hosts from {self.hosts_topo_file_path}")
        with open(self.hosts_topo_file_path) as json_file:
            data = json.load(json_file)
            self.hosts_raw_topo = data

        for host in self.hosts_raw_topo:
            if not host.startswith("h"):
                raise Exception(f"Host name ({host}) is not valid, accepted format 'h' + (number), example: 'h76'")
            self.client_hosts_list.append(host)
            self.host_default_switch_relation[host] = {
                'default_path_switch': self.hosts_raw_topo[host]['default_path_switch']}
            router = self.hosts_raw_topo[host]['router_switch']
            self.router_to_host_relation[router] = {'host': host}
            self.host_to_router_relation[host] = {'router': router}
            self.router_switches_list.append(router)
            self.router_to_controlled_switch_relation[router] = {
                'controlled_switch': self.hosts_raw_topo[host]['default_path_switch']}
            if self.hosts_raw_topo[host]['default_path_switch'] in self.controlled_switch_to_router_relation:
                self.controlled_switch_to_router_relation[self.hosts_raw_topo[host]['default_path_switch']][
                    'routers'].append(router)
            else:
                self.controlled_switch_to_router_relation[self.hosts_raw_topo[host]['default_path_switch']] = {
                    'routers': [router]}
