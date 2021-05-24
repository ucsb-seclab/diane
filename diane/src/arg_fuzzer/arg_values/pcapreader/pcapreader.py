import pyshark

import http


class PcapReader():
    def __init__(self, pcapfile):
        self.pcapfile = pcapfile
        self.packets = pyshark.FileCapture(pcapfile)
        self.http_packets = []

    def get_http_packets(self):
        if not self.http_packets:
            for pkt in self.packets:
                if "HTTP" in str(pkt.layers):
                    self.http_packets.append(http.HttpPacket(pkt))
        return self.http_packets

    def get_http_responses(self):
        ret_lst = []
        if not self.http_packets:
            self.get_http_packets()

        for pkt in self.http_packets:
            if pkt.is_response():
                ret_lst.append(pkt)

        return ret_lst

    def get_http_requests(self):
        ret_lst = []
        if not self.http_packets:
            self.get_http_packets()

        for pkt in self.http_packets:
            if pkt.is_request():
                ret_lst.append(pkt)

        return ret_lst