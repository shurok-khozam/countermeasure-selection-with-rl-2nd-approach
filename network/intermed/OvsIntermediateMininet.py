from mininet.log import info
from .OvsIntermediate import OvsIntermediate, OvsCommand


class OvsIntermediateMininet(OvsIntermediate):
    def __init__(self, net, mn_logs_active: bool = True, cmd_logging_active: bool = True,
                 custom_cmd_logging_function = None):
        super().__init__()
        self.net = net
        self.activate_mn_logs = mn_logs_active
        self.cmd_logging_active = cmd_logging_active
        self.custom_cmd_logging_function = custom_cmd_logging_function

    def apply_command(self, command: OvsCommand):
        self._apply_command(command.target, command)

    def _apply_command(self, subject: str, command: OvsCommand):
        if self.activate_mn_logs:
            if hasattr(command, "return_result"):
                return self.net[subject].cmd(command.to_ovs_string((info if self.custom_cmd_logging_function is None else self.custom_cmd_logging_function) if self.cmd_logging_active else None))
            return info(self.net[subject].cmd(command.to_ovs_string((info if self.custom_cmd_logging_function is None else self.custom_cmd_logging_function) if self.cmd_logging_active else None)))
        return self.net[subject].cmd(command.to_ovs_string())
