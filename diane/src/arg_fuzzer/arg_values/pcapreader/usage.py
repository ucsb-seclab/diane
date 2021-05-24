#!/usr/bin/env python
import sys

import pcapreader


def main():
    if len(sys.argv) != 2:
        print("Usage: {} <pcap>".format(sys.argv[0]))
        return

    pcap_path = sys.argv[1]

    reader = pcapreader.PcapReader(pcap_path)
    for p in reader.get_http_packets():
        print(p.get_parameters())


if __name__ == "__main__":
    main()
