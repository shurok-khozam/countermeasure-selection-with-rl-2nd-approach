from scapy.all import *
from scapy.layers.inet import IP, TCP, Ether
import argparse
import os
import json

VERBOSE = False
MAX_PERIOD = 30.0
MIN_BPS = 0.01

def debug(msg):
    if VERBOSE:
        print(f'(NetMetricsCalculator) --> {msg}')

##############################################################################
##########               Latency (Packet delivery time)             ##########
##############################################################################
def get_fwd_timestamps(packets, src, dst, dest_port):
    timestamps = []
    for packet in packets:
        if IP in packet and TCP in packet:
            if packet[IP].src != src:
                continue  # Skip packets not matching the source host
            if packet[IP].dst != dst or packet[IP].payload.dport != dest_port:
                continue  # Skip packets not matching the destination host
            timestamps.append((packet.time, packet[IP].payload.seq))
    timestamps.sort(key=lambda x: (x[1], x[0]))  # order by #Seq
    i = 1
    while i < len(timestamps):
        if timestamps[i][1] == timestamps[i - 1][1]:
            debug(f"{timestamps[i - 1]} and {timestamps[i]} are same, deleting second!")
            del timestamps[i]
        else:
            i = i + 1
    return timestamps

def get_bwd_timestamps(packets, src, dst, source_port):
    timestamps = []
    already_found_ack = []
    already_found_ack_index = []    # array to store the index in the timestamps array where to store the element
    index = 0
    for packet in packets:
        do_append = True
        reuse_index = 0
        if IP in packet and TCP in packet:
            if packet[IP].src != src or packet[IP].payload.sport != source_port:
                continue  # Skip packets not matching the source host
            if packet[IP].dst != dst:
                continue  # Skip packets not matching the destination host
            curr_ack = packet[IP].payload.ack
            if curr_ack == 0:
                continue  # Skip Pure ACK
            if already_found_ack.count(curr_ack) > 0:
                #   If packet already sniffed (by receiver's interface), reuse its index to store sender's interface information
                reuse_index = already_found_ack_index[already_found_ack.index(curr_ack)]
                do_append = False
            if do_append:
                #   If first sniffing
                already_found_ack.append(curr_ack)
                already_found_ack_index.append(index)
                timestamps.append((packet.time, curr_ack))
                index += 1
            else:
                #   If second sniffing
                if timestamps[reuse_index][0] < packet.time:
                    timestamps[reuse_index] = (packet.time, curr_ack)
    timestamps.sort(key=lambda x: (x[1], x[0]))  # order by #Ack
    return timestamps

def calculate_latency(packets, host=None, server=None, server_port=None):
    total_latency_ms = 0

    fwd_timestamps = get_fwd_timestamps(packets, host, server, server_port)
    fwd_packet_count = len(fwd_timestamps)

    bwd_timestamps = get_bwd_timestamps(packets, server, host, server_port)
    bwd_packet_count = len(bwd_timestamps)

    packet_count = min(fwd_packet_count, bwd_packet_count)

    packets_latencies = []

    if fwd_packet_count > 0:
        j = 0
        i = 0
        while i < bwd_packet_count:
            if j >= fwd_packet_count:
                debug('Break')
                break
            debug(f'Packet {i}: {bwd_timestamps[i]} - {fwd_timestamps[j]} = {bwd_timestamps[i][0] - fwd_timestamps[j][0]}')
            if i == 0:
                latency_ms = bwd_timestamps[i][0] - fwd_timestamps[j][0]
                packets_latencies.append(latency_ms)
                debug('Calculated')
                i = i + 1
            else:
                if bwd_timestamps[i - 1][1] == fwd_timestamps[j][1]:
                    latency_ms = bwd_timestamps[i][0] - fwd_timestamps[j][0]
                    packets_latencies.append(latency_ms)
                    debug('Calculated')
                    i = i + 1
                else:
                    debug('Skipped')
            j = j+1
        total_latency_ms = sum(packets_latencies)

    if packet_count > 0:
        average_latency_ms = total_latency_ms / packet_count
        average_latency_s = (total_latency_ms/1000.0) / packet_count
        print(f"(NetMetricsCalculator) --> Average latency: {average_latency_s} seconds ({average_latency_ms} ms) for {packet_count} packets")
        return min(average_latency_s, MAX_PERIOD)
    else:
        print("(NetMetricsCalculator) --> No relevant packets found in the PCAP file.")
    return MAX_PERIOD

##############################################################################
##########          Average Packet Transmission Time (APTT)         ##########
##############################################################################
def calculate_average_packet_transmission_time(packets, src, dst, dest_port, avg_packet_size_bytes, period_s):
    packet_count = 0
    total_sent_packets_bytes = 0
    already_found_seq = []
    for packet in packets:
        if IP in packet and TCP in packet:
            if packet[IP].src != src:
                continue  # Skip packets not matching the source host
            if packet[IP].dst != dst or packet[IP].payload.dport != dest_port:
                continue  # Skip packets not matching the destination host
            curr_seq = packet[IP].payload.seq
            if already_found_seq.count(curr_seq) > 0:
                continue  # Skip repeated packets
            packet_count = packet_count + 1
            already_found_seq.append(curr_seq)
            total_sent_packets_bytes = total_sent_packets_bytes + len(packet)
    if packet_count > 0:
        debug(f'Total sent bytes = {total_sent_packets_bytes}')
        avg_packet_transmission_time_s = avg_packet_size_bytes / (total_sent_packets_bytes / period_s)
        print(f"(NetMetricsCalculator) --> Average Packet Transmission Time (APTT): {avg_packet_transmission_time_s} seconds ({avg_packet_transmission_time_s * 1000} ms) for {period_s} seconds")
        return min(avg_packet_transmission_time_s, MAX_PERIOD)
    else:
        print("(NetMetricsCalculator) --> No relevant packets found in the PCAP file.")
    return MAX_PERIOD

##############################################################################
##########                  Throughput                              ##########
##############################################################################
def calculate_throughput(packets, src, dst, dest_port, period_s):
    packet_count = 0
    total_sent_packets_bytes = 0
    already_found_seq = []
    for packet in packets:
        if IP in packet and TCP in packet:
            if packet[IP].src != src:
                continue  # Skip packets not matching the source host
            if packet[IP].dst != dst or packet[IP].payload.dport != dest_port:
                continue  # Skip packets not matching the destination host
            curr_seq = packet[IP].payload.seq
            if already_found_seq.count(curr_seq) > 0:
                continue  # Skip repeated packets
            packet_count = packet_count + 1
            already_found_seq.append(curr_seq)
            total_sent_packets_bytes = total_sent_packets_bytes + len(packet)
    if packet_count > 0:
        debug(f'Total sent bytes = {total_sent_packets_bytes}')
        throughput_bps = (total_sent_packets_bytes * 8) / period_s
        print(f"(NetMetricsCalculator) --> Throughput: {throughput_bps} bps for {period_s} seconds")
        return max(throughput_bps, MIN_BPS)
    else:
        print("(NetMetricsCalculator) --> No relevant packets found in the PCAP file.")
    return MIN_BPS

##############################################################################
##########                      Jitter                              ##########
##############################################################################
def get_fwd_repeated_timestamps(packets, src, dst, dest_port):
    timestamps = []
    for packet in packets:
        if IP in packet and TCP in packet:
            if packet[IP].src != src:
                continue  # Skip packets not matching the source host
            if packet[IP].dst != dst or packet[IP].payload.dport != dest_port:
                continue  # Skip packets not matching the destination host
            curr_seq = packet[IP].payload.seq
            timestamps.append((packet.time, packet[IP].payload.seq))
    timestamps.sort(key=lambda x: (x[1], x[0]))  # order by #Seq
    return timestamps

def calculate_jitter(packets, src, dst, dest_port):
    fwd_timestamps = get_fwd_repeated_timestamps(packets, src, dst, dest_port)
    packet_count = len(fwd_timestamps)

    if packet_count > 0:
        total_jitter_ms = 0
        i = 1
        while i < packet_count:
            if fwd_timestamps[i][1] != fwd_timestamps[i - 1][1]:
                # In case of a packet captured by interface if-sender but not in if-receiver (and vice-vesa)
                debug(f'Ignoring packet {i}')
                i += 1
                continue
            time_between_packets = fwd_timestamps[i][0] - fwd_timestamps[i - 1][0]
            debug(f'Packet {i}: {fwd_timestamps[i]} - {fwd_timestamps[i - 1]} = {time_between_packets}  ms')
            total_jitter_ms = total_jitter_ms + time_between_packets
            i += 2
        avg_jitter_ms = total_jitter_ms / (packet_count / 2)
        avg_jitter_s = avg_jitter_ms / 1000
        print(f"(NetMetricsCalculator) --> Average jitter: {avg_jitter_s} seconds ({avg_jitter_ms} ms) for {packet_count} packets")
        return min(avg_jitter_s, MAX_PERIOD)
    else:
        print("(NetMetricsCalculator) --> No relevant packets found in the PCAP file.")
    return MAX_PERIOD

def calculate_metrics(data, packets, ip, server_ip, server_port, packet_size_bytes, sending_duration_seconds):
    print(f"(NetMetricsCalculator) --> Host {ip} started")
    data[ip] = {}
    data[ip]["avg_latency_s"] = calculate_latency(packets, ip, server_ip, server_port)
    data[ip]["avg_packet_transmission_time_s"] = calculate_average_packet_transmission_time(packets, ip, server_ip,
                                                                                            server_port,
                                                                                            packet_size_bytes,
                                                                                            sending_duration_seconds)
    data[ip]["throughput_bps"] = calculate_throughput(packets, ip, server_ip, server_port, sending_duration_seconds)
    data[ip]["avg_jitter_s"] = calculate_jitter(packets, ip, server_ip, server_port)
    print(f"(NetMetricsCalculator) <-- Host {ip} finished")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="PCAP Parser",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--server-ip", help="Server IP. E.g: 10.0.1.101", required=True)
    parser.add_argument("-p", "--server-port", help="Server Port. E.g: 80", required=True)
    parser.add_argument("-hip", "--hosts-ips", help="Hosts IPs. E.g: [10.0.1.1,10.0.1.2]", required=True)
    parser.add_argument("-t", "--sending-duration-seconds", help="Sending duration in seconds. E.g: 40", required=True)
    parser.add_argument("-b", "--packet-size-bytes", help="Average packet size in bytes. E.g: 512", required=True)
    parser.add_argument("-aux", "--auxiliary-file", action="store_true", help="Whether to use testing file or not")
    parser.add_argument("-nr", "--no-results", action="store_true", help="Whether to ignore generating JSON results file")

    config = vars(parser.parse_args())

    server_ip = config['server_ip']
    server_port = int(config['server_port'])
    hosts_ips = config['hosts_ips'].lstrip("[").rstrip("]").split(',')
    sending_duration_seconds = int(config['sending_duration_seconds'])
    packet_size_bytes = int(config['packet_size_bytes'])


    pcap_file = '/home/mininet-user/mainproject/reinforcement/tmp/tshark_out.pcap'
    if config['auxiliary_file']:
        pcap_file = '/home/mininet-user/tshark-out/backup_test.pcap'

    print(f"(NetMetricsCalculator) --> Reading pcap file at {pcap_file}")

    packets = rdpcap(pcap_file)

    data = {}

    threads = []
    for ip in hosts_ips:
        t = threading.Thread(name=f'thr-{ip}',
                            target=calculate_metrics,
                            args=(data, packets, ip, server_ip, server_port, packet_size_bytes, sending_duration_seconds))
        threads.append(t)
        t.start()
    for thread in threads:
        thread.join()
    print(data)

    tmp_dir = os.path.dirname(os.path.abspath(__file__)) + '/tmp'
    metrics_file = f'{tmp_dir}/metrics.json'

    # Serializing json
    json_object = json.dumps(data, indent=2)

    if not config['no_results']:
        # Writing to sample.json
        with open(metrics_file, "w") as outfile:
            outfile.write(json_object)
        print(f'(NetMetricsCalculator) <--> File {metrics_file} created...')