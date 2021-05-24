# FIXME: find send_function above the compress (if any)
# our approach might find a send function which is below a compress (in the trace)

import itertools
import time
import signal
import sys
import os

from multiprocessing import Process
from os.path import dirname, abspath
sys.path.append(dirname(dirname(abspath(__file__))))

from frida_hooker.frida_hooker import FridaHooker, ApkExploded, ApkKilled, ApkStuck, FridaRunner

from sniffer.sniffer import Sniffer
from sniffer.bltlog_analyzer import BltLogAnalyzer
from clusterizer import *

from ui.core import ADBDriver

import logging

logging.basicConfig()
log = logging.getLogger("SendFinder")
log.setLevel(logging.DEBUG)

N_PACKETS = 50

@FridaRunner
class SendFinder:
    def __init__(self, config, hooker=None, sniffer=None, bltlog_analyzer=None):
        self.hooker = hooker if hooker else FridaHooker(config)
        self.sniffer = sniffer if sniffer else Sniffer(config)
        self.bltlog_analyzer = bltlog_analyzer if bltlog_analyzer else BltLogAnalyzer()
        self.time_stats = {}
        self.senders = None
        self.running = True
        self.superset_senders = []
        self.run_fun = None
        self.proc_reran = None
        self.adb_driver = ADBDriver()

    def terminate(self):
        self.hooker.terminate()
        self.sniffer.terminate()
        self.running = False

    def collect_time_stats_sender(self, cls, m, params, ret):
        log.info("Running reran")
        found = False
        self.proc_reran = self.run_fun()
        with self.sniffer as sn:
            for _ in sn.sniff_packets(n_packets=N_PACKETS, sniffing_time=60*5):
                if self.hooker.methods_called:
                    elapsed = time.time() - self.hooker.methods_call_time
                    method = (cls, m, tuple(params), ret)
                    log.info('{} was called {} sec before the packet was sent'.format(str(method), str(elapsed)))
                    if method not in self.time_stats:
                        self.time_stats[method] = []
                    self.time_stats[method].append(elapsed)
                    found = True
                else:
                    log.info("Method was not called prior packets being sent")

                # clear the registered called methods
                self.hooker.clear_methods_called_cache()
        os.killpg(os.getpgid(self.proc_reran.pid), signal.SIGTERM)
        self.proc_reran = None
        return found

    def collect_time_stats_sender_blt(self, cls, m, params, ret):
        log.info("Running reran")
        self.proc_reran = self.run_fun()
        found = False
        for i in range(N_PACKETS):
            if self.hooker.methods_called:
                start_ts = self.hooker.methods_call_time
                if not start_ts:
                    continue

                packet_ts = self.bltlog_analyzer.get_new_sent_packet_ts(start_ts)
                if packet_ts is None:
                    continue
                elapsed = packet_ts - start_ts

                method = (cls, m, tuple(params), ret)
                log.info('{} was called {} sec before the packet was sent'.format(str(method), str(elapsed)))
                if method not in self.time_stats:
                    self.time_stats[method] = []
                self.time_stats[method].append(elapsed)
                found = True
            else:
                time.sleep(2)
                continue

            # clear the registered called methods
            self.hooker.clear_methods_called_cache()

        os.killpg(os.getpgid(self.proc_reran.pid), signal.SIGTERM)
        self.proc_reran = None
        return found

    def find_superset_senders(self):
        # sniff packets and retrieve the methods being called
        # right before a packet is registered
        self.proc_reran = self.run_fun()
        senders = []
        with self.sniffer as sn:
            for _ in sn.sniff_packets(n_packets=N_PACKETS, sniffing_time=60*5):
                log.debug('Packet sniffed')
                senders += self.hooker.methods_called
        os.killpg(os.getpgid(self.proc_reran.pid), signal.SIGTERM)
        try:
            self.hooker.terminate()
        except ApkKilled as ak:
            pass
        self.proc_reran = None
        senders.sort()
        self.superset_senders = list(k for k, _ in itertools.groupby(senders))
        log.debug("Superset senders: " + str(self.superset_senders))

    def get_blt_log_size(self):
        #return int(self.adb_driver.adb_cmd(['shell', 'ls', '-l',
        #                                    '/sdcard/btsnoop_hci.log'])[0].split(' ')[4])
        return int(self.adb_driver.adb_su_cmd('ls -l /data/misc/bluetooth/logs/btsnoop_hci.log')[0].split(' ')[4])

    def find_superset_senders_blt(self):
        self.proc_reran = self.run_fun()
        senders = []

        ts = time.time()

        for i in range(N_PACKETS):
            # did the phone send a new BT packet afer ts?
            if self.bltlog_analyzer.get_new_sent_packet_ts(ts) is not None:
                senders += self.hooker.methods_called
            # new start_ts
            ts = time.time()

        os.killpg(os.getpgid(self.proc_reran.pid), signal.SIGTERM)
        try:
            self.hooker.terminate()
        except ApkKilled as ak:
            pass
        self.proc_reran = None
        senders.sort()
        self.superset_senders = list(k for k, _ in itertools.groupby(senders))
        log.debug("Superset senders: " + str(self.superset_senders))

    def refine_senders(self):

        for cls, m, params, ret in self.superset_senders:
            try:
                log.info("Hooking {}:{}".format(cls, m))
                self.hooker.start([[cls, m, params, ret]], force_hook=True)
                self.collect_time_stats_sender(cls, m, params, ret)
            except Exception as e:
                log.error(str(e))
                import ipdb; ipdb.set_trace()

        avg_times = [sum(self.time_stats.values()[i])/len(self.time_stats.values()[i])
                     for i in range(len(self.time_stats.values()))]
        if max(avg_times) - min(avg_times) <= 2:
            # we account for network delays: if the delta between the slowest response and the fastest is within
            # couple of seconds, we return the superset senders as possible senders.
            self.senders = self.superset_senders
        else:
            # otherwise we find the most promising sender functions.
            self.vote_sender()

    def refine_senders_blt(self):
        for cls, m, params, ret in self.superset_senders:
            for _ in range(0, 3):
                try:
                    log.info("Hooking {}:{}".format(cls, m))
                    self.hooker.start([[cls, m, params, ret]], force_hook=True)
                    found = self.collect_time_stats_sender_blt(cls, m, params, ret)
                    if not found:
                        method = (cls, m, tuple(params), ret)
                        if method in self.time_stats:
                            self.time_stats[method] = []
                            break
                except Exception as e:
                    log.error(str(e))
                    import ipdb; ipdb.set_trace()

        try:
            avg_times = [sum(map(lambda x: x * (N_PACKETS - len(self.time_stats.values()[i]) + 1), self.time_stats.values()[i]))/len(self.time_stats.values()[i])
                         for i in range(len(self.time_stats.values()))]
            if max(avg_times) - min(avg_times) <= 2:
                # we account for network delays: if the delta between the slowest response and the fastest is within
                # couple of seconds, we return the superset senders as possible senders.
                self.senders = self.superset_senders
            else:
                # otherwise we find the most promising sender functions.
                self.vote_sender()
        except:
            import ipdb;ipdb.set_trace()

    def vote_sender(self):
        if len(self.time_stats.keys()) >= 2:
            senders = select_funcs(self.time_stats)
        else:
            senders = [self.time_stats.keys()[0] if self.time_stats else []]

        # we gotta use lists as frida does not kown tutples
        self.senders = [[s[0], s[1], list(s[2]), s[3]] for s in senders]

    def start(self, ran_fun=lambda *args: None, lifter=None, ignore=None):
        self.running = True
        self.run_fun = ran_fun
        while self.running:
            try:
                # hook all APK leafs
                self.hooker.start(leaves=True, fast_hook=True, ignore=ignore)
                # get possible senders:
                self.find_superset_senders_blt()
                self.refine_senders_blt()
                log.debug("Filtered senders: " + str(self.senders))
                return self.senders
            except Exception as ae:
                # FIXME do something to recover from constant
                # crashes
                log.error(str(ae))
                if self.proc_reran:
                    os.killpg(os.getpgid(self.proc_reran.pid), signal.SIGTERM)
                log.error("Something bad happened, re-hooking")

if __name__ == '__main__':
    import json
    from ui.core import ADBDriver
    import sys

    try:
        config_path = sys.argv[1]
    except:
        print "Usage: {} [config path]".format(sys.argv[0])
        sys.exit(1)

    with open(config_path) as fp:
        config = json.load(fp)

    reran_record_path = config["reran_record_path"]
    adbd = ADBDriver(f_path=reran_record_path, device_id=config['device_id'])

    start_time = time.time()
    senders = SendFinder(config).start(ran_fun=adbd.replay_ui_async)
    print str(senders)
    elapsed_time = time.time() - start_time
    print "Time: " + str(elapsed_time)

    print "Done"
