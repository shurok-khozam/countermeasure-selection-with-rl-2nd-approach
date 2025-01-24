class Util():

    @staticmethod
    def nothing_action():
        return 'NOTHING'

    @staticmethod
    def bw_action(src_switch, dst_switch, bw_action):
        # bw_action: 0 => Decrease, 1 => Increase
        return f'bw:{src_switch}:{dst_switch}:{bw_action}'

    @staticmethod
    def redirect_action(host, dst_switch):
        return f'redirect:{host}:through:{dst_switch}'
