import os
import argparse
import json

PWD = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = f"{PWD}/../../input-data"
IP_BASE = "10.0.1"
MAC_BASE = "00:00:00:00:00"
CURRENT_SUPPORTED_SWITCHES = []
SWITCHES = {}
current_config = {
    'file_path': '',
    'filename': '',
    'dry_run': False
}


def host_template() -> dict:
    return {
        "ip": "",
        "router_switch": "",
        "mac": "",
        "default_path_switch": ""
    }


def get_host(host_num: int, switch: str) -> dict:
    template = host_template()
    template['ip'] = get_ip(host_num)
    template['router_switch'] = get_router_switch(host_num)
    template['mac'] = get_mac(host_num)
    template['default_path_switch'] = switch
    return template


def append_host(hosts: dict, host_num: int, switch: str) -> None:
    hosts[get_host_name(host_num)] = get_host(host_num, switch)


def get_host_name(host_num: int) -> str:
    return f"h{host_num}"


def get_router_switch(host_num: int) -> str:
    return f"s{host_num}"


def get_ip(host_num: int) -> str:
    return f"{IP_BASE}.{str(host_num)}"


def get_mac(host_num: int) -> str:
    return f"{MAC_BASE}:{str(host_num).zfill(2)}"


def validate_input(config: dict):
    all_hosts_count = 0
    switches_count = len(config["switch_connected_hosts"])
    if switches_count < 4:
        raise Exception(f"Please provide switches' hosts count for at least 4 switches!")
    if switches_count > 99:
        raise Exception(f"Please provide switches' hosts count for at most 99 switches!")
    for i in range(switches_count):
        switch_name = "s1" + ("0" + str(i + 1)) if i < 10 else str(i + 1)
        CURRENT_SUPPORTED_SWITCHES.append(switch_name)
        SWITCHES[switch_name] = config["switch_connected_hosts"][i]
        if config["switch_connected_hosts"][i] <= 0:
            raise Exception(f"The value ({config['switch_connected_hosts'][i]}) of switch ({switch_name}) is not valid!")
        all_hosts_count += int(config['switch_connected_hosts'][i])
    if all_hosts_count > 99:
        raise Exception(
            f"The given values result in ({all_hosts_count}) generated host, which is more than actual limitation of "
            f"(99) hosts!")
    if 'filename' not in config or config['filename'] is None or len(config['filename']) == 0:
        print("*** No filename provided, this is considered as a dry-run, results will be printed ***")
        current_config['dry_run'] = True
    else:
        current_config['dry_run'] = False
        filename = config['filename']
        if not filename.lower().endswith(".json"):
            filename += ".json"
        current_config['filename'] = filename
        file_path = f"{OUTPUT_DIR}/{filename}"
        current_config['file_path'] = file_path
        if os.path.isfile(file_path) and not config['force']:
            raise Exception(f"File {filename} already exists in the output directory!")
    print(current_config)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Hosts Topology Generator",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-sn', '--switch-connected-hosts', type=lambda s: [int(item) for item in s.split(',')], help='Number of hosts connected to each switch. E.g: 3,6,9,3,1 will create switches s101 to s105 with corresponding count of hosts.', required=True)
    parser.add_argument("-f", "--filename", help="File name to be used for the generated file with hosts (if empty, "
                                                 "no file will be generated and the script will be executed in "
                                                 "dry-run mode)", required=False, default="")
    parser.add_argument("-force", "--force", action="store_true",
                        help="When used and --filename is provided, if the file already exists, it will be overwritten",
                        required=False, default=False)

    config = vars(parser.parse_args())

    validate_input(config)

    hosts = {}

    print(f"*** Detected ({len(CURRENT_SUPPORTED_SWITCHES)}) switch ***")
    for switch_name in CURRENT_SUPPORTED_SWITCHES:
        print(f"   > Detected {switch_name} with hosts count {SWITCHES[switch_name]}")

    current_host_number = 1
    for switch in CURRENT_SUPPORTED_SWITCHES:
        print(f"*** Processing switch ({switch}) ==> ({SWITCHES[switch]}) hosts connected ***")
        first_host = ""
        last_host = ""
        for i in range(int(SWITCHES[switch])):
            host_name = get_host_name(current_host_number)
            append_host(hosts, host_num=current_host_number, switch=switch)
            print(f"   > Adding host {host_name} to switch {switch}")
            if len(first_host) == 0:
                first_host = host_name
            last_host = host_name
            current_host_number += 1
        if first_host == last_host:
            print(f" => Switch {switch} has host ({first_host})")
        else:
            print(f" => Switch {switch} has hosts in range ({first_host} ... {last_host})")

    if current_config['dry_run']:
        print(json.dumps(hosts, sort_keys=False, indent=2))
    else:
        file_path = current_config['file_path']
        if os.path.isfile(file_path) and not config['force']:
            raise Exception(f"File {current_config['filename']} already exists in the output directory!")
        with open(file_path, 'w') as f:
            json.dump(hosts, f, sort_keys=False, indent=2)
