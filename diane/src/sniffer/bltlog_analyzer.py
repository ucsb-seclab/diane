import pyshark
import logging
import sys
import os
from os.path import dirname, abspath
sys.path.append(dirname(dirname(abspath(__file__))))

from ui.core import ADBDriver


logging.basicConfig()
log = logging.getLogger("BltLogAnalyzer")
log.setLevel(logging.DEBUG)


LOCAL_LOGFILE_PATH = '/tmp/diane_log_bluetooth.log'
REMOTE_LOGFILE_PATH = '/data/misc/bluetooth/logs/btsnoop_hci.log'


class BltLogAnalyzer:

    def __init__(self):
        self._keep_alives = {}
        self.adb_driver = ADBDriver()

    def _pull_log(self):
        self.adb_driver.adb_su_cmd('cp {} /sdcard/my_blt_log'.format(REMOTE_LOGFILE_PATH))
        self.adb_driver.adb_cmd(['pull', '/sdcard/my_blt_log', LOCAL_LOGFILE_PATH])
        return LOCAL_LOGFILE_PATH

    def remove_log(self):
        if os.path.isfile(LOCAL_LOGFILE_PATH):
            os.remove(LOCAL_LOGFILE_PATH)

    def detect_keep_alives(self):
        log.info('Detecting BL keep-alives')
        capture = pyshark.FileCapture(self._pull_log())
        
        for packet in capture:
            if hasattr(packet, 'hci_h4'):
                # direction is SENT
                if packet.hci_h4.direction == '0x00000000':
                    if packet.length not in self._keep_alives:
                        self._keep_alives[packet.length] = set()

                    if hasattr(packet, 'btatt') and hasattr(packet.btatt, 'value'):
                        self._keep_alives[packet.length].add(str(packet.btatt.value))

        capture.close()
        if not capture.eventloop.is_closed():
            capture.eventloop.close()
        self.remove_log()


    def _is_keep_alive(self, packet):
        if hasattr(packet, 'hci_h4'):
            if packet.hci_h4.direction == '0x00000000' and hasattr(packet, 'btatt'):
                if packet.length in self._keep_alives:
                    #if str(packet.btatt.value) in self._keep_alives[packet.length]:
                   return True
        return False


    def get_new_sent_packet_ts(self, start_ts):
        capture = pyshark.FileCapture(self._pull_log())
        timestamp = None
        for packet in capture:
            if hasattr(packet, 'hci_h4'):
                # direction is SENT
                if packet.hci_h4.direction == '0x00000000':
                    if not self._is_keep_alive(packet) and float(packet.sniff_timestamp) > start_ts:
                        log.debug('New BL packet: {}'.format(packet.sniff_timestamp))
                        timestamp = float(packet.sniff_timestamp)
                        break

        capture.close()
        if not capture.eventloop.is_closed():
            capture.eventloop.close()
        self.remove_log()
        if timestamp is None:
            log.debug('No new BL packet')
        return timestamp
