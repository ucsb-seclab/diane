from base_detector import DefaultCrashDetector
import os
import random
import string
from pcap_analysis import PCAPAnalyzer

import logging
logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s')
log = logging.getLogger("PcapBasedDetector")
log.setLevel(logging.DEBUG)

ANOMALY_THRESHOLD = 0.5


class PcapBasedDetector(DefaultCrashDetector):
    """
    This detector is based on pcap size.
    """
    def __init__(self, config, sniffer=None):
        DefaultCrashDetector.__init__(self, config, sniffer=sniffer)

        self.pcap_work_dir = os.path.join("/tmp", config["proc_name"] + "_pcap_dir")
        if "fuzz_pcap_path" in config:
            self.pcap_work_dir = config["fuzz_pcap_path"]
        else:
            log.info("Using :" + self.pcap_work_dir + " as the pcap working directory.")

        if not os.path.exists(self.pcap_work_dir):
            os.makedirs(self.pcap_work_dir)

        self.normal_pcap_path = os.path.join(self.pcap_work_dir, "default_sane_pcap.pcap")
        self.normal_transmit_pkts = []
        self.normal_received_pkts = []
        self.normal_transmit_data_size = 0
        self.normal_receive_data_size = 0
        self.run_pcap_map = {}

    def start_normal_run(self):
        """
            start normal run.
        :return: None
        """
        self.sniffer.terminate()
        self.sniffer.dump_all_traffic_to_pcap(self.normal_pcap_path)

    def stop_normal_run(self):
        """
            stop normal run.
        :return: True if everything is fine else False
        """
        self.sniffer.terminate()
        if os.path.getsize(self.normal_pcap_path) == 0:
            log.critical("Unable to capture normal pcap. "
                         "Make sure that the router is working fine.")
            self.normal_run_registered = False
            return False
        new_panal = PCAPAnalyzer(self.normal_pcap_path)
        trs_pkts, rec_pkts = new_panal.filter_packets(self.phone_ip, self.device_ip)
        self.normal_transmit_pkts = trs_pkts
        self.normal_received_pkts = rec_pkts

        for _, curr_d in trs_pkts:
            self.normal_transmit_data_size += len(curr_d)

        for _, curr_d in rec_pkts:
            self.normal_receive_data_size += len(curr_d)

        self.normal_run_registered = True
        return True

    def start_reg_run(self):
        """
            Start regular run
        :return: return a unique id
        """
        new_regid = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        new_pcap_file = os.path.join(self.pcap_work_dir, new_regid + ".pcap")
        self.run_pcap_map[new_regid] = new_pcap_file
        self.sniffer.dump_all_traffic_to_pcap(new_pcap_file)
        return new_regid

    def stop_reg_run(self, run_regid):
        """
            Stop the regular run.
        :param run_regid: id corresponding to the run.
        :return: True if the pcap capturing was successful.
        """
        assert ((run_regid in self.run_pcap_map) and "Provided id doesn't exist.")
        self.sniffer.terminate()
        target_pcap_file = self.run_pcap_map[run_regid]
        return os.path.getsize(target_pcap_file) > 0

    def verify_size(self, run_regid):
        """
            Verify that the run identified by the provided id is fine.
        :param run_regid: id of the normal run to verify
        :return: True if everything is fine else False
        """
        assert((run_regid in self.run_pcap_map) and "Provided id doesn't exist.")
        target_pcap_file = self.run_pcap_map[run_regid]
        # verify pcap file
        if os.path.getsize(target_pcap_file) == 0:
            return False

        new_pcapanal = PCAPAnalyzer(target_pcap_file)
        trs_pkts, recv_pkts = new_pcapanal.filter_packets(self.phone_ip, self.device_ip)

        transmit_data_size = 0
        received_data_size = 0

        for _, curr_d in trs_pkts:
            transmit_data_size += len(curr_d)

        for _, curr_d in recv_pkts:
            received_data_size += len(curr_d)

        if self.normal_transmit_data_size > 0:
            transmit_bammed_up = (transmit_data_size / float(self.normal_transmit_data_size)) >= ANOMALY_THRESHOLD
        else:
            transmit_bammed_up = transmit_data_size > 0

        if self.normal_receive_data_size > 0:
            receive_bammed_up = (received_data_size / float(self.normal_receive_data_size)) >= ANOMALY_THRESHOLD
        else:
            receive_bammed_up = received_data_size > 0

        if transmit_bammed_up:
            log.info("Looks like there is mis-match between normal transmit size:" +
                     str(self.normal_transmit_data_size) + " and current transmit size:" + str(transmit_data_size))

        if receive_bammed_up:
            log.info("Looks like there is mis-match between normal receive size:" +
                     str(self.normal_receive_data_size) + " and current receive size:" + str(received_data_size))

        return not(transmit_bammed_up or receive_bammed_up)

    def get_transport_protocols(self, run_regid):
        assert((run_regid in self.run_pcap_map) and "Provided id doesn't exist.")
        target_pcap_file = self.run_pcap_map[run_regid]
        # verify pcap file
        if os.path.getsize(target_pcap_file) == 0:
            return []

        new_pcapanal = PCAPAnalyzer(target_pcap_file)
        return new_pcapanal.get_transport_protocols(self.phone_ip, self.device_ip)

    def tcp_connection_dropped(self, run_regid):
        assert((run_regid in self.run_pcap_map) and "Provided id doesn't exist.")
        target_pcap_file = self.run_pcap_map[run_regid]
        # verify pcap file
        if os.path.getsize(target_pcap_file) == 0:
            return False

        new_pcapanal = PCAPAnalyzer(target_pcap_file)
        trs_pkts, _ = new_pcapanal.filter_packets(self.phone_ip, self.device_ip)
        return new_pcapanal.is_connection_dropped([x[1] for x in trs_pkts if 'TCP' in repr(x[1])])

    def verify_reg_run(self, run_regid):
        is_conn_ok = True
        is_size_ok = True
        prots = self.get_transport_protocols(run_regid)

        if self.normal_run_registered:
            is_size_ok = self.verify_size(run_regid)
        if 'tcp' in prots:
            is_conn_ok = not self.tcp_connection_dropped(run_regid)
        if 'udp' in prots:
            pass

        return is_size_ok & is_conn_ok

if __name__ == '__main__':
    from ui.core import ADBDriver
    from frida_hooker.frida_hooker import FridaHooker
    import sys
    import json


    try:
        config_path = sys.argv[1]
    except:
        print "Usage: {} [config path]".format(sys.argv[0])
        sys.exit(1)

    with open(config_path) as fp:
        config = json.load(fp)

    # build objs
    fh = FridaHooker(config)
    pbd = PcapBasedDetector(config)
    reran_record_path = config["reran_record_path"]
    adbd = ADBDriver(f_path=reran_record_path, device_id=config['device_id'])

    fh.start()
    pbd.start_normal_run()
    adbd.replay_ui()
    assert pbd.stop_normal_run()

    unique_key = pbd.start_reg_run()
    adbd.replay_ui()
    pbd.verify_reg_run(unique_key)
    raw_input()
