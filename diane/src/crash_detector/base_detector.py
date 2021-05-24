import signal
import os
import re
import sys
from os.path import dirname, abspath

sys.path.append(dirname(dirname(abspath(__file__))))
from multiprocessing import Process
from sniffer.sniffer import Sniffer
from frida_hooker.frida_hooker import FridaHooker, ApkExploded

import logging
logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s')
log = logging.getLogger("CrashDetector")
log.setLevel(logging.DEBUG)

ANOMALY_THRESHOLD = 0.5


"""
This is the crash detector class.
How to use it:
first you run normal run:
obj.start_normal_run() => start the normal run.
...do normal run..
retval = obj.stop_normal_run() => make sure that this returns true

unique_key = obj.start_reg_run()
...do regular fuzzing run..
retval = obj.stop_reg_run(unique_key) => check this is true
obj.verify_reg_run(unique_key) => if this is true, then no crash else crash
 
"""


class DefaultCrashDetector:
    def __init__(self, config, sniffer=None):
        self.len_normal_run = 0
        self.sniffer = sniffer if sniffer else Sniffer(config)
        self.ran_fun = None
        self.normal_run_registered = False
        self.phone_ip = config["android_ip"]
        self.device_ip = config["device_ip"]

    def start_normal_run(self):
        raise NotImplementedError()

    def stop_normal_run(self):
        raise NotImplementedError()

    def start_reg_run(self):
        raise NotImplementedError()

    def stop_reg_run(self, normal_regid):
        raise NotImplementedError()

    def verify_reg_run(self, normal_regid):
        raise NotImplementedError()

