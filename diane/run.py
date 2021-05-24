import sys
import json
import time
import signal
from enum import Enum
from src.sniffer.sniffer import Sniffer
from src.sniffer.bltlog_analyzer import BltLogAnalyzer
from src.methods_finder import SendFinder, SweetSpotFinder
from src.frida_hooker.frida_hooker import FridaHooker, FridaRunner
from src.ui.core import ADBDriver
from src.arg_fuzzer.arg_fuzzer import ArgFuzzer
from pysoot.lifter import Lifter
from node_filter.node_filter import NodeFilter


import logging

logging.basicConfig()
log = logging.getLogger("ApkFuzzer")
log.setLevel(logging.DEBUG)

RERAN_RECORD_PATH = '/tmp/reran.log'


class Phase(Enum):
    SETUP = 0
    RERAN = 1
    KEEPALIVE = 2
    MESSAGE_SENDER = 3
    FUZZING_CANDIDATES = 4
    FUZZING = 5

    def __lt__(self, other):
        return self.value < other.value

    def __le__(self, other):
        return self.values <= other.value

    def __gt__(self, other):
        return self.value > other.value

    def __ge__(self, other):
        return self.value >= other.value

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return not self.value == other.value


@FridaRunner
class IoTFuzzer:
    def __init__(self, config):
        self.config = config
        self.reran_record_path = config['reran_record_path']
        self.senders = config['send_functions'] if 'send_functions' in config else []
        self.automated_senders = []
        self.fuzzing_candidates = config['fuzzing_candidates'] if 'fuzzing_candidates' in config else []
        self.sp = config['sweet_spots'] if 'sweet_spots' in config else []
        self.phase = Phase.SETUP

        self.lifter = None
        if not config['leaf_pickle']:
            log.debug("Building lifter")
            self.create_lifter()

        log.debug("Building node filter")
        self.nf = NodeFilter(self.config, lifter=self.lifter)

        log.debug("Building Reran Object")
        self.adbd = ADBDriver(device_id=config['device_id'])
        log.debug("Done.")

        log.debug("Building Sniffer")
        self.sniffer = Sniffer(config)
        log.debug("Done.")

        log.debug("Building BltLogAnalyzer")
        self.bltlog_analyzer = BltLogAnalyzer()
        log.debug("Done.")

        log.debug("Building Hooker")
        self.hooker = FridaHooker(config, node_filter=self.nf)
        log.debug("Done.")

        log.debug("Building SendFinder")
        self.send_finder = SendFinder(config, sniffer=self.sniffer, hooker=self.hooker, bltlog_analyzer=self.bltlog_analyzer)
        log.debug("Done.")

        log.debug("Building SweetSpotFinder")
        self.sp_finder = SweetSpotFinder(config, hooker=self.hooker, node_lifter=self.nf)
        log.debug("Done.")

        log.debug("Building ArgFuzzer")
        self.arg_fuzzer = ArgFuzzer(config, hooker=self.hooker)
        log.debug("Done.")


        signal.signal(signal.SIGINT, self.signal_handler)

    def create_lifter(self):
        log.info("Creating Lifter")
        self.lifter = Lifter(self.config['apk_path'], input_format="apk", android_sdk=self.config['android_sdk_platforms'])

    def run_reran(self):
        if not self.reran_record_path:
            self.hooker.spawn_apk_in_device()
            self.adbd.record_ui(RERAN_RECORD_PATH)
            self.reran_record_path = RERAN_RECORD_PATH
            self.hooker.terminate()
        self.adbd.translate_events_log(self.reran_record_path)

    def detect_keep_alive(self):
        self.hooker.start()#leaves=True)
        self.sniffer.detect_keepalive()
        # FIXME: enable if we want to ignore automatically called functions
        #called_methods = self.hooker.last_methods_called
        #[self.automated_senders.append(c) for c in called_methods if c not in self.automated_senders]
        self.hooker.terminate()
        self.bltlog_analyzer.detect_keep_alives()


    def signal_handler(self, sig, _):
        if sig == signal.SIGINT:
            self.terminate()

    def terminate(self):
        log.info("Terminating...")
        if self.phase == Phase.KEEPALIVE:
            self.sniffer.terminate()
        elif self.phase == Phase.MESSAGE_SENDER:
            self.send_finder.terminate()
        elif self.phase == Phase.FUZZING:
            self.arg_fuzzer.terminate()

    def run(self, phase=Phase.FUZZING):
        # reran run
        eval_stats = open('/tmp/stats_' + self.config['proc_name'], 'w')
        replay_ui_async = self.adbd.replay_ui_async

        if phase >= Phase.RERAN:
            log.info("Recording user interactions")
            self.phase = Phase.RERAN
            self.run_reran()

        # if phase >= Phase.KEEPALIVE:
        #     log.info("Detecting keep-alive messages")
        #     self.phase = Phase.KEEPALIVE
        #     self.detect_keep_alive()

        if not self.senders and phase >= Phase.MESSAGE_SENDER:
            starting_time = time.time()
            log.info("Finding send-message method")
            self.phase = Phase.MESSAGE_SENDER
            self.senders = self.send_finder.start(ran_fun=replay_ui_async, lifter=self.lifter,
                                                  ignore=self.automated_senders)
            elapsed_time = time.time() - starting_time
            eval_stats.write('Time (s): {}\nSenders: {}\n'.format(str(elapsed_time), str(self.senders)))
            log.debug("Possible senders {}".format(str(self.senders)))

        if not self.sp and phase >= Phase.FUZZING_CANDIDATES:
            if not self.lifter:
                self.create_lifter()
            starting_time = time.time()
            self.phase = Phase.FUZZING_CANDIDATES
            sp = [self.sp_finder.start(s, lifter=self.lifter, ran_fun=replay_ui_async) for s in self.senders]
            self.sp = [x for l in sp for x in l if x]
            elapsed_time = time.time() - starting_time
            eval_stats.write('Time (s): {}\nsweet spots: {}\n'.format(str(elapsed_time), str(self.sp)))
            log.debug("Sweet spots: {}".format(str(self.sp)))

        if phase >= Phase.FUZZING:
            self.phase = Phase.FUZZING
            # send functions
            map(lambda v: self.arg_fuzzer.start(v, fast_fuzz=True, ran_fun=replay_ui_async, lifter=self.lifter),
                self.senders)

            # send functions not fast
            map(lambda v: self.arg_fuzzer.start(v, ran_fun=replay_ui_async, lifter=self.lifter),
                self.senders)

            # sweet spots
            map(lambda v: self.arg_fuzzer.start(v, ran_fun=replay_ui_async, lifter=self.lifter), self.sp)

            # automated senders
            map(lambda v: self.arg_fuzzer.start(v, ran_fun=replay_ui_async, lifter=self.lifter), self.automated_senders)

            log.info("Fuzzing done!")


if __name__ == "__main__":
    config_path = sys.argv[1]
    phase = Phase.FUZZING
    if len(sys.argv) > 2:
        phase = [value for name, value in vars(Phase).items() if name == sys.argv[2]]
        if not phase:
            print "Invalid phase, options are: " + str([x[6:] for x in list(map(str, Phase))])
            sys.exit(0)
        phase = phase[0]

    with open(config_path) as fp:
        config = json.load(fp)

    #test_compress(config)
    IoTFuzzer(config).run(phase)
