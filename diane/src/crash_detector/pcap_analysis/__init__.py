import os
import dpkt
import socket

CONNECTION_DROPPED_RETR_THR = 1

class PCAPAnalyzer:
    def __init__(self, pcap_file):
        self.target_pcap_file = pcap_file

    def inet_to_str(self, inet):
        """Convert inet object to a string

            Args:
                inet (inet struct): inet network address
            Returns:
                str: Printable/readable IP address
        """
        # First try ipv4 and then ipv6
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)

    def filter_packets(self, phone_ip, device_ip):
        """
            filter the packets based on the phone ip and device ip
        :param phone_ip: IP of the phone
        :param device_ip: IP of the target device
        :return: pair of lists of transmitted and received packets.
        """
        transmit_pkts = []
        received_pkts = []
        if os.path.exists(self.target_pcap_file):
            for ts, pkt in dpkt.pcap.Reader(open(self.target_pcap_file, "r")):
                if not pkt:
                    continue
                eth = dpkt.ethernet.Ethernet(pkt)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue

                ip_data = eth.data

                # get source ip
                src_ip = self.inet_to_str(ip_data.src)
                # get dst ip
                dst_ip = self.inet_to_str(ip_data.dst)
                if src_ip == phone_ip and dst_ip == device_ip:
                    transmit_pkts.append((ip_data, ip_data.data))
                if src_ip == device_ip and src_ip == phone_ip:
                    received_pkts.append((ip_data, ip_data.data))

        return transmit_pkts, received_pkts

    def get_transport_protocols(self, phone_ip, device_ip):
        tcp_c = 0
        udp_c = 0
        unk_c = 0

        if os.path.exists(self.target_pcap_file):
            for ts, pkt in dpkt.pcap.Reader(open(self.target_pcap_file, "r")):
                if not pkt:
                    continue

                eth = dpkt.ethernet.Ethernet(pkt)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue

                ip_data = eth.data

                # get source ip
                src_ip = self.inet_to_str(ip_data.src)
                # get dst ip
                dst_ip = self.inet_to_str(ip_data.dst)

                to_consider = False
                if src_ip == phone_ip and dst_ip == device_ip:
                    to_consider = True
                if src_ip == device_ip and src_ip == phone_ip:
                    to_consider = True

                if to_consider:
                    if ip_data.p == dpkt.ip.IP_PROTO_TCP:
                        tcp_c += 1
                    elif ip_data.p == dpkt.ip.IP_PROTO_UDP:
                        udp_c += 1
                    else:
                        unk_c += 1

        to_ret = []
        if tcp_c > 0:
            to_ret.append('tcp')
        if udp_c > 0:
            to_ret.append('udp')
        if unk_c > 0:
            to_ret.append('unknown')

        return to_ret

    def is_retransmission(self, a, b):
        return a.flags == b.flags and a.seq == b.seq \
                    and a.sport == b.sport and a.dport == b.dport

    def is_connection_dropped(self, tcp_data):
        # check for FIN -> SYN and SYN retransmission
        indexes = [tcp_data.index(p) for p in tcp_data if p.flags & dpkt.tcp.TH_FIN != 0]
        for i in indexes:
            tmp = tcp_data[i + 1:]
            if tmp and tmp[0].flags & dpkt.tcp.TH_SYN != 0:
                retr_thr = CONNECTION_DROPPED_RETR_THR
                if len(tmp) <= retr_thr:
                    retr_thr = len(tmp) - 1
                if retr_thr > 0 and \
                        all([self.is_retransmission(tmp[0], tmp[j + 1])
                             for j in xrange(retr_thr)]):
                    return True

        # check for RST
        return any([(p.flags & dpkt.tcp.TH_RST) != 0 for p in tcp_data])