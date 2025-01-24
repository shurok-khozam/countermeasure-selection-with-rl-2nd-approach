# OVS Protocols
OVS_PROTOCOL_IP = "ip"

# OVS Instruction Base
OVS_ISNTR_OFCTL = "ovs-ofctl"
OVS_ISNTR_VSCTL = "ovs-vsctl"

# OVS Command Actions
OVS_INSTR_DEL_FLOWS = "del-flows"
OVS_INSTR_ADD_FLOW = "add-flow"
OVS_INSTR_VSCTL_GET = "get"

# OVS Command Options
OVS_INSTR_OPTION_STRICT = "--strict"

# OVS Command Arguments
OVS_INSTR_ARGS_PRIORITY_NAME = "priority"
OVS_INSTR_ARGS_NET_PROTOCOL_NAME = "nw_proto"
OVS_INSTR_ARGS_IP_SOURCE_NAME = "nw_src"
OVS_INSTR_ARGS_IP_DESTINATION_NAME = "nw_dst"
OVS_INSTR_ARGS_IN_PORT_NAME = "in_port"
OVS_INSTR_ARGS_OUT_PORT_NAME = "out_port"
OVS_INSTR_ARGS_MAC_SOURCE_NAME = "dl_src"
OVS_INSTR_ARGS_MAC_DESTINATION_NAME = "dl_dst"
OVS_INSTR_ARGS_ETHER_TYPE_NAME = "dl_type"
OVS_INSTR_ARGS_ACTIONS_NAME = "actions"

# OVS Command Arguments Actions
OVS_INSTR_ARGS_ACTION_OUTPUT_NAME = "output"
OVS_INSTR_ARGS_ACTION_FLOOD_NAME = "flood"

# OVS Command Arguments Network Protocol Values
OVS_INSTR_ARGS_NET_PROTOCOL_VALUES = {
    "HOPOPT": "0",
    "ICMP": "1",
    "IGMP": "2",
    "GGP": "3",
    "IP": "4",
    "ST": "5",
    "TCP": "6",
    "CBT": "7",
    "EGP": "8",
    "IGP": "9",
    "BBN-RCC-MON": "10",
    "NVP-II": "11",
    "PUP": "12",
    "ARGUS": "13",
    "EMCON": "14",
    "XNET": "15",
    "CHAOS": "16",
    "UDP": "17",
    "MUX": "18",
    "DCN-MEAS": "19",
    "HMP": "20",
    "PRM": "21",
    "XNS-IDP": "22",
    "TRUNK-1": "23",
    "TRUNK-2": "24",
    "LEAF-1": "25",
    "LEAF-2": "26",
    "RDP": "27",
    "IRTP": "28",
    "ISO-TP4": "29",
    "NETBLT": "30",
    "MFE-NSP": "31",
    "MERIT-INP": "32",
    "SEP": "33",
    "3PC": "34",
    "IDPR": "35",
    "XTP": "36",
    "DDP": "37",
    "IDPR-CMTP": "38",
    "TP++": "39",
    "IL": "40",
    "IPv6": "41",
    "SDRP": "42",
    "IPv6-Route": "43",
    "IPv6-Frag": "44",
    "IDRP": "45",
    "RSVP": "46",
    "GRE": "47",
    "MHRP": "48",
    "BNA": "49",
    "ESP": "50",
    "AH": "51",
    "I-NLSP": "52",
    "SWIPE": "53",
    "NARP": "54",
    "MOBILE": "55",
    "TLSP": "56",
    "SKIP": "57",
    "IPv6-ICMP": "58",
    "IPv6-NoNxt": "59",
    "IPv6-Opts": "60",
    "CFTP": "62",
    "SAT-EXPAK": "64",
    "KRYPTOLAN": "65",
    "RVD": "66",
    "IPPC": "67",
    "SAT-MON": "69",
    "VISA": "70",
    "IPCV": "71",
    "CPNX": "72",
    "CPHB": "73",
    "WSN": "74",
    "PVP": "75",
    "BR-SAT-MON": "76",
    "SUN-ND": "77",
    "WB-MON": "78",
    "WB-EXPAK": "79",
    "ISO-IP": "80",
    "VMTP": "81",
    "SECURE-VMTP": "82",
    "VINES": "83",
    "TTP": "84",
    "NSFNET-IGP": "85",
    "DGP": "86",
    "TCF": "87",
    "EIGRP": "88",
    "OSPFIGP": "89",
    "Sprite-RPC": "90",
    "LARP": "91",
    "MTP": "92",
    "AX.25": "93",
    "IPIP": "94",
    "MICP": "95",
    "SCC-SP": "96",
    "ETHERIP": "97",
    "ENCAP": "98",
    "GMTP": "100",
    "IFMP": "101",
    "PNNI": "102",
    "PIM": "103",
    "ARIS": "104",
    "SCPS": "105",
    "QNX": "106",
    "A/N": "107",
    "IPComp": "108",
    "SNP": "109",
    "Compaq-Peer": "110",
    "IPX-in-IP": "111",
    "VRRP": "112",
    "PGM": "113",
    "L2TP": "115",
    "DDX": "116",
    "IATP": "117",
    "STP": "118",
    "SRP": "119",
    "UTI": "120",
    "SMP": "121",
    "SM": "122",
    "PTP": "123",
    "ISIS over IPv4": "124",
    "FIRE": "125",
    "CRTP": "126",
    "CRUDP": "127",
    "SSCOPMCE": "128",
    "IPLT": "129",
    "SPS": "130",
    "PIPE": "131",
    "SCTP": "132",
    "FC": "133",
    "RSVP-E2E-IGNORE": "134",
    "Mobility Header": "135",
    "UDPLite": "136",
    "MPLS-in-IP": "137",
    "Experimental": "253",
    "Experimental(254)": "254",
    "Reserved": "255",
}

OVS_INSTR_ARGS_NET_PROTOCOL_VALUES_ICMP = OVS_INSTR_ARGS_NET_PROTOCOL_VALUES["ICMP"]
OVS_INSTR_ARGS_NET_PROTOCOL_VALUES_IP = OVS_INSTR_ARGS_NET_PROTOCOL_VALUES["IP"]

# OVS Command Arguments Ethernet Type Values
OVS_INSTR_ARGS_ETHER_TYPE_VALUES = {
    "XEROX_PUP": "0x200",
    "PUP_Addr_Trans": "0x201",
    "Nixdorf": "0x400",
    "XEROX_NS_IDP": "0x600",
    "DLOG": "0x660",
    "DLOG2": "0x661",
    "Internet_IP": "0x800",
    "X.75_Internet": "0x801",
    "NBS_Internet": "0x802",
    "ECMA_Internet": "0x803",
    "Chaosnet": "0x804",
    "X.25_Level_3": "0x805",
    "ARP": "0x806",
    "XNS_Compatibility": "0x807",
    "Frame_Relay_ARP": "0x808",
    "RARP": "0x8035",
    "IPv6": "0x86DD",
    "PPP": "0x880B",
    "Slow_Protocol": "0x8809",
    "MPLS_Unicast": "0x8847",
    "MPLS_Multicast": "0x8848",
    "PPPoE_Discovery": "0x8863",
    "PPPoE_Session": "0x8864",
    "PBB": "0x88E7",
    "FCoE": "0x8906",
    "FIP": "0x8914"
}

OVS_INSTR_ARGS_ETHER_TYPE_VALUES_ARP = OVS_INSTR_ARGS_ETHER_TYPE_VALUES["ARP"]