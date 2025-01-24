from . import OvsIntermediateConstants as consts


class OvsCommandOptions:

    def __init__(self, strict: bool = None):
        self.strict = strict

    def to_ovs_string(self) -> str:
        options = ""
        options = self._append_if(options, consts.OVS_INSTR_OPTION_STRICT, (self.strict is not None) and self.strict)
        return options

    def _append_if(self, current: str, addition: str, condition: bool) -> str:
        return self._append(current, addition) if condition else current

    def _append(self, current: str, addition: str) -> str:
        return current + (" " if (len(current) > 0) else "") + addition


class OvsCommandArgumentAction:

    def __init__(self, name: str, value: str = None, ignore_value: bool = False):
        self.name = name
        self.value = value
        self.ignore_value = ignore_value

    def to_ovs_string(self) -> str:
        if self.ignore_value:
            return f"{self.name}"
        return f"{self.name}:{self.value}"


class OvsCommandArgumentActionOutput(OvsCommandArgumentAction):

    def __init__(self, value: str):
        super().__init__(consts.OVS_INSTR_ARGS_ACTION_OUTPUT_NAME, value=value)


class OvsCommandArgumentActionFlood(OvsCommandArgumentAction):

    def __init__(self):
        super().__init__(consts.OVS_INSTR_ARGS_ACTION_FLOOD_NAME, ignore_value=True)


class OvsCommandArguments:

    def to_ovs_string(self) -> str:
        pass


class OvsCommand:

    def __init__(self, base: str, target: str, action: str, args: OvsCommandArguments,
                 options: OvsCommandOptions = None):
        self.base = base
        self.target = target
        self.action = action
        self.args = args
        self.options = options

    def to_ovs_string(self, cmd_logger=None) -> str:
        instr = self.base
        if self.options is not None:
            instr += " " + self.options.to_ovs_string()
        instr += " " + self.action
        instr += " " + self.target
        if self.args is not None:
            instr += " " + self.args.to_ovs_string()
        if cmd_logger is not None:
            cmd_logger(f"{self.target} ==> {instr}\n")
        return instr


# OFCTL
class OvsOfctlCommandArguments(OvsCommandArguments):

    def __init__(self,
                 protocol: str = None,
                 net_protocol: str = None,
                 priority: int = None,
                 in_port: str = None, out_port: str = None,
                 ip_source: str = None, ip_destination: str = None,
                 mac_source: str = None, mac_destination: str = None,
                 ether_type: str = None,
                 actions: [OvsCommandArgumentAction] = None):
        super().__init__()
        self.protocol: str = protocol
        self.net_protocol: str = net_protocol
        self.priority: int = priority
        self.in_port: str = in_port
        self.out_port: str = out_port
        self.ip_source: str = ip_source
        self.ip_destination: str = ip_destination
        self.mac_source: str = mac_source
        self.mac_destination: str = mac_destination
        self.ether_type: str = ether_type
        if actions is None:
            actions = []
        self.actions: [OvsCommandArgumentAction] = actions

    def to_ovs_string(self) -> str:
        args = ""
        # Start
        #   ->  Protocol
        args = self._append_if_protocol(args)
        #   -> Network Protocol (net_proto)
        args = self._append_if_net_protocol(args)
        # Middle
        #   ->  Priority
        args = self._append_if_priority(args)
        #   ->  Port
        #       -> Source (in_port)
        args = self._append_if_in_port(args)
        #       -> Destination (out_port)
        args = self._append_if_out_port(args)
        #   ->  Network
        #       -> Source IP (net_src)
        args = self._append_if_ip_source(args)
        #       -> Destination IP (net_dst)
        args = self._append_if_ip_destination(args)
        #   ->  MAC
        #       -> Source (dl_src)
        args = self._append_if_mac_source(args)
        #       -> Destination (dl_dst)
        args = self._append_if_mac_destination(args)
        #       -> Ether type (dl_type)
        args = self._append_if_ether_type(args)
        # End
        #   ->  Actions
        args = self._append_if_actions(args)
        return args

    def _append(self, current: str, addition: str) -> str:
        return current + ("," if len(current) > 0 else "") + f"{addition}"

    def _append_if_protocol(self, args: str) -> str:
        if self.protocol is not None:
            return self._append(args, f"{self.protocol}")
        return args

    def _append_if_net_protocol(self, args: str) -> str:
        if (self.net_protocol is not None) and (len(self.net_protocol) > 0):
            net_protocol = self.net_protocol
            if net_protocol in consts.OVS_INSTR_ARGS_NET_PROTOCOL_VALUES.keys():
                net_protocol = consts.OVS_INSTR_ARGS_NET_PROTOCOL_VALUES[net_protocol]
            if net_protocol not in consts.OVS_INSTR_ARGS_NET_PROTOCOL_VALUES.values():
                raise Exception(f"{net_protocol} is not recognized as nw_proto")
            return self._append(args, f"{consts.OVS_INSTR_ARGS_NET_PROTOCOL_NAME}={net_protocol}")
        return args

    def _append_if_priority(self, args: str) -> str:
        if self.priority is not None:
            return self._append(args, f"{consts.OVS_INSTR_ARGS_PRIORITY_NAME}={self.priority}")
        return args

    def _append_if_in_port(self, args: str) -> str:
        if (self.in_port is not None) and (len(self.in_port) > 0):
            return self._append(args, f"{consts.OVS_INSTR_ARGS_IN_PORT_NAME}={self.in_port}")
        return args

    def _append_if_out_port(self, args: str) -> str:
        if (self.out_port is not None) and (len(self.out_port) > 0):
            return self._append(args, f"{consts.OVS_INSTR_ARGS_OUT_PORT_NAME}={self.out_port}")
        return args

    def _append_if_ip_source(self, args: str) -> str:
        if (self.ip_source is not None) and (len(self.ip_source) > 0):
            return self._append(args, f"{consts.OVS_INSTR_ARGS_IP_SOURCE_NAME}={self.ip_source}")
        return args

    def _append_if_ip_destination(self, args: str) -> str:
        if (self.ip_destination is not None) and (len(self.ip_destination) > 0):
            return self._append(args, f"{consts.OVS_INSTR_ARGS_IP_DESTINATION_NAME}={self.ip_destination}")
        return args

    def _append_if_mac_source(self, args: str) -> str:
        if (self.mac_source is not None) and (len(self.mac_source) > 0):
            return self._append(args, f"{consts.OVS_INSTR_ARGS_MAC_SOURCE_NAME}={self.mac_source}")
        return args

    def _append_if_mac_destination(self, args: str) -> str:
        if (self.mac_destination is not None) and (len(self.mac_destination) > 0):
            return self._append(args, f"{consts.OVS_INSTR_ARGS_MAC_DESTINATION_NAME}={self.mac_destination}")
        return args

    def _append_if_ether_type(self, args: str) -> str:
        if (self.ether_type is not None) and (len(self.ether_type) > 0):
            ether_type = self.ether_type
            if ether_type in consts.OVS_INSTR_ARGS_ETHER_TYPE_VALUES.keys():
                ether_type = consts.OVS_INSTR_ARGS_ETHER_TYPE_VALUES[ether_type]
            if ether_type not in consts.OVS_INSTR_ARGS_ETHER_TYPE_VALUES.values():
                raise Exception(f"{ether_type} is not recognized as ether_type")
            return self._append(args, f"{consts.OVS_INSTR_ARGS_ETHER_TYPE_NAME}={ether_type}")
        return args

    def _append_if_actions(self, args: str) -> str:
        if (self.actions is not None) and (len(self.actions) > 0):
            acts = ",".join([act.to_ovs_string() for act in self.actions])
            return self._append(args, f"{consts.OVS_INSTR_ARGS_ACTIONS_NAME}={acts}")
        return args


class OvsOfctlCommand(OvsCommand):

    def __init__(self, target: str, action: str, args: OvsOfctlCommandArguments,
                 options: OvsCommandOptions = None):
        super().__init__(consts.OVS_ISNTR_OFCTL, target, action, args, options)


class OvsOfctlDelFlowsCommand(OvsOfctlCommand):

    def __init__(self, target: str, args: OvsOfctlCommandArguments,
                 options: OvsCommandOptions = None):
        super().__init__(target, consts.OVS_INSTR_DEL_FLOWS, args, options)


class OvsOfctlAddFlowCommand(OvsOfctlCommand):

    def __init__(self, target: str, args: OvsOfctlCommandArguments,
                 options: OvsCommandOptions = None):
        super().__init__(target, consts.OVS_INSTR_ADD_FLOW, args, options)

# Base Class #############################################################################

class OvsIntermediate:

    def __init__(self):
        print("Executing OvsIntermediate.__init__")

    def _apply_command(self, subject: any, command: OvsCommand):
        print("Warning: _do_apply is not implemented")
        return None
