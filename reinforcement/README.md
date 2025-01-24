# Reinforcement
***********
**V2.1.0**

## Short Description
This project implements a reinforcement learning environment where a DDQN agent interacts with a network simulation. It's designed to test various network strategies and responses dynamically, supporting both automated and manual control over network conditions.

## Table of contents

- [Reinforcement](#reinforcement)
  * [Short Description](#short-description)
  * [Table of contents](#table-of-contents)
  * [Composition](#composition)
  * [Run arguments:](#run-arguments-)
  * [Configuration](#configuration)
  * [Documentation](#documentation)
  * [Possible manual actions](#possible-manual-actions)
  * [Commands](#commands)
  * [DDQN parameters](#ddqn-parameters)

## Composition
The network is basically composed of:
- A DDQN agent with customizable environment properties.
- HTTP client to connect to Network.
- CMD client to execute commands.
- `tmp` and `results` folders used for storing intermediate and final results.

## Run arguments:
- `-a`/`--attackers`: Attacker hosts names. E.g: `[h1]`.
- `-e`/`--episodes`: Number of episodes. E.g: 50.
- `-s`/`--steps`: Number of steps. E.g: 100.
- `-ed`/`--epsilon-decay`: Epsilon decay. E.g: 0.999.
- `-ncs`/`--nbr-controlled-switches`: The number of controlled switches in the network.
- `-c`/`--controlled`: When used, at each decision taking, the user would be asked to enter the action to be taken, see [possible manual actions](#manual-actions) below (*used only for testing purposes*).
- `-pfa`/`--prefilled-actions`: When used, the agent will read the action to be taken from a `prefilled-actions.txt` file, see [possible manual actions](#manual-actions) below (*used only for testing purposes*).
- `-htf`/`--hosts-topo-file`: When given, the provided JSON file in the `input-data` folder will be used. E.g: `hosts-topology-6hosts`.

## Configuration
Configuration details and DDQN model parameters can be adjusted in Configuration.py 
and DdqnAgent.py respectively.

## Documentation
Documentation regarding the purpose and functionality of each script is present at 
the top of each file. For specific model configurations and adjustments, refer to DdqnAgent.py.

## Possible manual actions
**(This section is intended to be reviewed for testing purposes only)**

Contents of `prefilled-actions.txt` or user-prompted actions could be one of the following:
- `NOTHING` for do nothing action.
- `bw:[target_switch]:[destination_switch]:[decrease/increase]` for bandwidth changing where:
  - `[target_switch]` is the target switch
  - `[destination_switch]` is the destination switch
  - `[decrease/increase]` where `0` is for decrease, `1` for increase
- `redirect:[host_name]:through:[switch_name]` for flow redirection where:
  - `[host_name]` is the host whose the flow needs to be redirected
  - `[switch_name]` is the switch that the flow needs to pass through (in addition to default switch)

## Commands

**Run the whole project**
******

Go to `reinforcement` directory and execute:
```shell
sudo python3 Main.py
```

**Run with custom attacker**
******

For example, `h3` here is the attacker:
```shell
sudo python3 Main.py -a [h3]
```

**Run with manually controlled actions**
******

A prompt would ask the user to enter action's index at each step.
```shell
sudo python3 Main.py -c
```

**Run with manually prefilled actions**
******

Prefilled actions file `prefilled-actions.txt` should be filled in advance:
```shell
sudo python3 Main.py -pfa
```

**Run with predefined actions**
******

```shell
sudo python3 Main.py -pfa -a [h5]
```

**Run with custom hosts topology**
******

```shell
sudo python3 Main.py -a [h5] -htf hosts-topology-10hosts-2_3_2_3
```

**Run with custom number of steps and episodes**
******

```shell
sudo python3 Main.py -a [h5] -e 50 -s 100
```

## DDQN parameters

It is possible to tune the DDQN model as needed using variables in the `DdqnAgent.py` class.

Available parameters:
- Gamma (`self.gamma`): in range `]0, 1[`.
- Epsilon (`self.epsilon`): in range `]0, 1]`.
- Minimum value of Epsilon (`self.epsilon_min`): in range `]0, 1[`.
- Epsilon decay (`self.epsilon_decay`): in range `]0, 1[`.
- Learning rate (`self.learning_rate`): in range `]0, 1[`.
- Batch samples size (`self.batch_size`): in range `[2, self.experience_reply_size[`
- Experience replay memory size (`self.experience_reply_size`): constraint `> self.batch_size`
- Number of steps after which the target model should be updated (`self.update_target_each`): in range `]1, Steps[`
- Number of training epochs (`self.epoch_count`)