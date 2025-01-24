# Hosts Topology Generator
***********
**V1.0.0**

A python script to generate a JSON topology file for hosts.

The generated file has the following format:

```json5
{
  "h1": {
    "ip": "10.0.1.1",
    "router_switch": "s1",
    "mac": "00:00:00:00:00:01",
    "default_path_switch": "s101"
  },
  // ...
}
```

## The file contains:
- The `key` for each object is the name of the host (hostname).
- The `ip` and `mac` for each host.
- The router switch connected directly to the host.
- The controlled switch connected to the host's router switch.

## Run arguments:
- `-sn` (`--switch-connected-hosts`): Number of hosts connected to each switch. E.g: 3,6,9,3,1 will create switches s101 to s105 with corresponding count of hosts.
- `-f` (`--filename`): File name to be used for the generated file with hosts (if empty, no file will be generated and the script will be executed in `dry-run` mode.
- `--force`: When used, and `--filename` is provided, if the file already exists, it will be overwritten.

## Validations:
- Hosts count: remember that the total number of hosts connected to all controlled switches should be less or equal (`<=`) `99` host.
- Supported controlled switches count: the number of controlled switches should not surpass `87` switch.

## Commands

**Run in dry-run mode**
******

Go to `tools/hoststopo` directory and execute:
```shell
sudo python3 HostsTopoGenerator.py -sn 2,3,3,1
```

**Run with no file replacement if exists**
******

Go to `tools/hoststopo` directory and execute:
```shell
sudo python3 HostsTopoGenerator.py -sn 1,2,2,1 -f test
```

**Run and replace file if exists**
******

Go to `tools/hoststopo` directory and execute:
```shell
sudo python3 HostsTopoGenerator.py -sn 1,2,2,1 -f test --force
```