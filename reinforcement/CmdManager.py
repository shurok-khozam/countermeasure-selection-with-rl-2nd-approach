import time
import os
import signal
import subprocess

class CmdManager:

    # Initializes the CmdManager class responsible for managing command-line interactions for network simulations.
    # - Stores the configuration object for accessing command templates and file paths.
    # - Initializes subprocess handles for network and TShark sniffing processes.
    def __init__(self, config):
        print("(Reinforcement) CmdManager.__init__()")
        self.config = config
        self.network_subprocess = None
        self.tshark_sniffing_subprocess = None

    # Starts the network simulation in the background using a shell command.
    # The command is built dynamically by replacing placeholders with the provided server, attacker, and topology information.
    # A delay is added to allow the network to stabilize before continuing.
    def start_network_in_background(self, servers, attackers, hosts_topo_file_name, nbr_controlled_switches):
        cmd = self.config.network_command
        cmd = cmd.replace('[SERVERS]', f'{servers}') \
            .replace('[ATTACKERS]', f'{attackers}') \
            .replace('[HOST_BW]', '3.1') \
            .replace('[NBR_CONTROLLED_SWITCHES]', f'{nbr_controlled_switches}') \
            .replace('[HOSTS_FILE]', hosts_topo_file_name)
        print(f"(Reinforcement) ----> Executing {cmd}")
        self.network_subprocess = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE)
        time.sleep(15)
        print("(Reinforcement) --> Network started")

    # Stops the running network simulation by sending an "exit" command to the running process.
    # A short delay is included to ensure the process has time to shut down completely.
    # Notice that timeout can be decreased for small topologies, or increased for larger ones.
    def stop_network(self):
        self.network_subprocess.communicate(input="exit\n".encode('ascii'), timeout=30)
        print(f"(Reinforcement) ----> Executing exit")
        time.sleep(4)
        print("(Reinforcement) <-- Network stopped")

    # Retrieves a list of available network interfaces on the system using the TShark command.
    # The output is parsed from the command line response and returned as a list of interface names.
    def get_tshark_interfaces(self):
        print(f"(Reinforcement) ----> Executing {self.config.tshark_interfaces_command}")
        return subprocess.Popen(self.config.tshark_interfaces_command, shell=True, stdout=subprocess.PIPE).stdout.read().decode("ascii").split('\n')

    # Starts packet sniffing with TShark on the specified network interfaces.
    # Deletes any existing capture file before starting a new capture session.
    # TShark runs as a background process, capturing network traffic for later analysis
    def start_tshark_sniffing(self, interfaces_ids):
        try:
            os.remove(self.config.tshark_pcap_file_path)
        except FileNotFoundError:
            pass
        cmd = self.config.tshark_sniffing_command.replace('[INTERFACES]', interfaces_ids)
        print(f"(Reinforcement) ----> Executing {cmd}")
        self.tshark_sniffing_subprocess = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, preexec_fn=os.setsid)
        time.sleep(2)
        print("(Reinforcement) --> TShark sniffing started")
    def stop_tshark_sniffing(self):
        os.killpg(os.getpgid(self.tshark_sniffing_subprocess.pid), signal.SIGTERM)
        time.sleep(2)
        print("(Reinforcement) <-- TShark sniffing stopped")

    # Runs the CICFlowMeter tool to analyze network traffic and extract flow-level statistics.
    # The output is saved to a specified CSV file, which is deleted before each run to avoid data conflicts.
    # The command output and any errors are printed for debugging purposes.
    def run_cic(self):
        print('(Reinforcement) --> Running CIC started')
        try:
            os.remove(self.config.cic_output_file_path)
        except FileNotFoundError:
            pass
        print(f"(Reinforcement) ----> Executing {self.config.cic_command}")
        out, err = subprocess.Popen(self.config.cic_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        print(f"(Reinforcement) ----> Out: {out.decode('ascii')}")
        print(f"(Reinforcement) ----> Error: {err.decode('ascii')}")
        print('(Reinforcement) <-- Running CIC finished')

    def read_ditg_logs(self):
        print('(Reinforcement) --> Running DITG ITGDec started')
        print(f"(Reinforcement) ----> Executing {self.config.ditg_logs_command}")
        subprocess.Popen(self.config.ditg_logs_command, shell=True, stdin=subprocess.PIPE).communicate()
        print('(Reinforcement) <-- Running DITG ITGDec ended')

    def run_network_metrics_calculator(self, server_ip, server_port, hosts_ips, duration_s, packet_bytes):
        print('(Reinforcement) --> Running NetMetricsCalculator started')
        try:
            os.remove(self.config.net_metrics_result_file_path)
        except FileNotFoundError:
            pass
        cmd = self.config.net_metrics_command.replace('[SERVER_IP]', server_ip)\
            .replace('[SERVER_PORT]', str(server_port))\
            .replace('[HOSTS_IPS]', str(hosts_ips).replace('\'', '').replace(' ', ''))\
            .replace('[DURATION]', str(duration_s))\
            .replace('[BYTES]', str(packet_bytes))
        print(f"(Reinforcement) ----> Executing {cmd}")
        subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE).communicate()
        print('(Reinforcement) <-- Running NetMetricsCalculator ended')
