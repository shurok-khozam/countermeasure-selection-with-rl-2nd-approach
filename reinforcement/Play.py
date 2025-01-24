import numpy as np
import matplotlib.pyplot as plt
import Environment
import random
import time
from datetime import datetime
import os
from DdqnAgent import DoubleDeepQNetwork
from Configuration import Configuration
from HttpClient import HttpClient
from CmdManager import CmdManager


def get_attack_type():
    available_attacks = ["ICMP", "NESTEA", "SYN"]
    attack_type_index = random.randint(0, len(available_attacks) - 1)
    return available_attacks[attack_type_index]
def play(self):
    print("--> Started playing function")
    env = Environment()
    ddqn_agent = DoubleDeepQNetwork(env)
    config = Configuration()
    cmd = CmdManager(config)
    http_client = HttpClient(config)
    episodes = 1
    print("----> Input starting state:")
    steps = int(input("------> Please enter number of steps:\n"))
    steps = env.steps
    ddqn_agent.load_model('model')
    ddqn_agent.epsilon = 0
    ddqn_agent.epsilon_min = 0
    tshark_interfaces_ids = env.get_tshark_interfaces_ids(cmd)

    sender_receiver_relation = {}
    for host in env.normal_hosts:
        server_index = random.randint(0, len(env.servers) - 1)
        server = env.servers[server_index]
        sender_receiver_relation[host] = server

    attacker_victim_relation = {}
    attack_types = {}
    for attacker in env.attacker_hosts:
        victim_server_index = random.randint(0, len(env.victim_servers) - 1)
        victim_server = env.victim_servers[victim_server_index]
        attacker_victim_relation[attacker] = victim_server
        attack_types[attacker] = get_attack_type()
    current_state=env.get_state(self, config, cmd, http_client, tshark_interfaces_ids, sender_receiver_relation,
                  attacker_victim_relation, attack_types)
    env.update_hosts()

    env.perform_setup()

    cmd.start_network_in_background(env.servers, env.attacker_hosts)
    for step in range(steps):

        action = ddqn_agent.action(env.transform_state_dict_to_normalized_vector(current_state))

        new_state, reward, done = env.apply_action(config, cmd, http_client, tshark_interfaces_ids,
                                                   sender_receiver_relation,
                                                   attacker_victim_relation, attack_types, action)
        cur_state = new_state

    cmd.stop_network()