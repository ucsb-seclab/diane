import json
import re
import random
import os
from random_values import RandomValues
from pcapreader.pcapreader import PcapReader
# from keyhunter.key_hunter import KeyHunter

OPEN_PLACEHOLDER = '<<-<<'
CLOSE_PLACEHOLDER = '>>->>'


class FormattedValues:
    def __init__(self, config):
        self.rv = RandomValues()
        self.fw_path = None
        self.fmt_strs = []
        self.android_ip = config['android_ip']
        self.device_ip = config['device_ip']
        self.fmt_data_keys = []
        self.params = {}
        self.current_fmt_str = None
        self.par_to_replace = 0
        self.current_fmt_idx = 0
        self.populate_fmt_data(config)

    def replace_hex_chars(self, s):
        to_conv = list(set(re.findall('\\\\x[0-9A-Fa-f][0-9A-Fa-f]?', s)))
        for elem in to_conv:
            c = chr(int(elem.replace('\\x', ''), 16))
            s = s.replace(elem, c)
        return s

    def populate_fmt_data(self, config):
        if 'pcap_path' not in config:
            return

        pcap_dir = config['pcap_path']
        for pcap_file in os.listdir(pcap_dir):
            if not pcap_file.endswith('.pcap'):
                continue

            pcap_file = pcap_dir + '/' + pcap_file
            reader = PcapReader(pcap_file)
            for p in reader.get_http_packets():
                if p.dst != self.device_ip:
                    # we are only interested in traffic
                    # generate for the device
                    continue

                if p.method == 'GET':
                    # take the URI and extract the parameter values
                    # creating a single format string
                    params = p.get_parameters()
                    tmp_uri = p.uri
                    for k, v in params.items():
                        par_key = OPEN_PLACEHOLDER + str(k) + CLOSE_PLACEHOLDER
                        s = tmp_uri.find(k + '=') + len(k) + 1
                        e = s + len(v)
                        tmp_uri = tmp_uri[:s] + par_key + tmp_uri[e:]
                        if par_key not in self.params:
                            self.params[par_key] = []
                        self.params[par_key].append(v)
                    self.fmt_strs.append(tmp_uri)

                elif p.method == 'POST':
                    # post bodies might have a recursive structure.
                    # Therefore, we have to add a format string for
                    # each parameter (differently from the get method)
                    p.body = self.replace_hex_chars(p.body)
                    for k, v in p.get_parameters().items():
                        # FIXME: handle CDATA[]
                        v = self.replace_hex_chars(v)
                        par_key = OPEN_PLACEHOLDER + str(k) + CLOSE_PLACEHOLDER
                        s = p.body.find(k[0]) + len(k[0])
                        e = p.body.find(k[1])
                        tmp_body = p.body[:s] + par_key + p.body[e:]
                        if par_key not in self.params:
                            self.params[par_key] = []
                        self.params[par_key].append(v)
                        self.fmt_strs.append(tmp_body)

        # get additional data key from firmware, if present
        if 'fmt_data_keys' in config:
            self.fmt_data_keys = config['fmt_data_keys']
        # elif 'fw_dir' in config:
        #     fw_dir = config['fw_dir']
        #     if os.path.exists(fw_dir) and os.listdir(fw_dir) != []:
        #         kh = KeyHunter(fw_dir, pcap_dir)
        #         self.fmt_data_keys = kh.get_potential_keywords()

        self.current_fmt_str = self.fmt_strs[0] if self.fmt_strs else None

    def next_fmt_string(self):
        self.par_to_replace = 0
        self.current_fmt_idx = (self.current_fmt_idx + 1) % len(self.fmt_strs)
        self.current_fmt_str = self.fmt_strs[self.current_fmt_idx]

    def fuzz_java_lang_String(self, obj_creator, *kargs, **kwargs):
        if self.current_fmt_str is None:
            return None

        pars = re.findall(OPEN_PLACEHOLDER + "(?:[ -~]*?)" + CLOSE_PLACEHOLDER, self.current_fmt_str)
        final_str = self.current_fmt_str
        for i, k in enumerate(pars):
            # FIXME: default argument in rv
            val = random.choice(self.params[k]) if i != self.par_to_replace else self.rv.fuzz_java_lang_String(lambda *x, **y: None)
            final_str = final_str.replace(k, val)
        obj_creator('java.lang.String', False, final_str, 1, *kargs, **kwargs)
        self.par_to_replace += 1
        if self.par_to_replace >= len(pars):
            self.next_fmt_string()
        return final_str

    def fuzz_byte_array(self, obj_creator, *kargs, **kwargs):
        s = self.fuzz_java_lang_String(lambda *a, **b: None)
        if s is None:
            return None
        val = [int(elem.encode("hex"), 16) for elem in s]
        if obj_creator is not None:
            obj_creator('byte', True, val, len(val), *kargs, **kwargs)
        return val

if __name__ == '__main__':
    config_path = '../experiments/insteon/config_insteon.json'
    #config_path = '../experiments/weemo/config_weemo.json'
    empty_f = lambda *a, **b: None

    with open(config_path) as fp:
        config = json.load(fp)
    fv = FormattedValues(config)
    for i in range(10):
        res = fv.fuzz_java_lang_String(empty_f)
        print res.replace('\\xa', '\n')
        import ipdb; ipdb.set_trace()
