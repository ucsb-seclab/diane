from utils import *
import os
import angr
import sys
import logging
import subprocess
from os.path import dirname, abspath
sys.path.append(dirname(dirname(abspath(__file__))))

from pcapreader.pcapreader import PcapReader


all_function_parameters_at_all_callsites = []
all_strings_addr_len = []


class LogFilter(object):
    def __init__(self, min_level, max_level):
        self.min_level = min_level
        self.max_level = max_level


    def filter(self, logRecord):
        return logRecord.levelno >= self.min_level and logRecord.levelno <= self.max_level


class KeyHunter:
    def __init__(self, fw_dir, pcap_dir):
        self.fw_dir = fw_dir                                        # Directory to search for firmware binaries in
        self.pcap_dir = pcap_dir                                    # Directory to search for PCAP dumps in
        self.keywords = None
        self.binaries = None
        self.project = None
        self.cfg = None
        self._init_logging()                                        # Initialize logger


    # https://docs.python.org/3/howto/logging.html#logging-flow
    def _init_logging(self):
        # Mute angr logger
        angr.loggers.disable_root_logger()

        # Configure a named logger
        self.logger = logging.getLogger(__name__)           # Create a named logger
        self.logger.propagate = False                       # Disable propagation of log records to root logger
        log_format_string = "[%(levelname)s] | %(module)s | %(message)s"
        formatter = logging.Formatter(log_format_string)
        min_log_level = logging.INFO
        max_log_level = logging.INFO
        self.logger.setLevel(logging.INFO)                  # Change the default logging level (which is WARN)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.addFilter(LogFilter(min_log_level, max_log_level))
        self.logger.addHandler(console_handler)

        file_handler = logging.FileHandler(os.path.join(fw_dir, 'key_hunter.log'), mode='w')
        file_handler.setFormatter(formatter)
        file_handler.addFilter(LogFilter(min_log_level, max_log_level))
        self.logger.addHandler(file_handler)

        self.logger.info('Key Hunter is searching for potential keys in the binary...')


    def _get_keywords_from_pcap(self):
        keywords_from_pcap = set()
        pcap_files = get_files_from_dir(self.pcap_dir, '*.pcap')
        all_packets = None
        for pcap_file in pcap_files:
            pcap_reader = PcapReader(pcap_file)
            for http_pkt in pcap_reader.get_http_packets():
                # HTML arguments
                parameters_from_http_packet = http_pkt.get_parameters()
                keywords_from_http_packet = set(parameters_from_http_packet.keys())
                keywords_from_pcap = keywords_from_pcap.union(keywords_from_http_packet)
            self.logger.info('Extracted keywords from %s pcap' % pcap_file)

            self.logger.info('Potential keywords in pcap %s: %s' % (pcap_file, str(keywords_from_pcap)))
        return keywords_from_pcap


    # https://stackoverflow.com/a/1263782/1895325
    def is_keywords(function_depending_on_keywords):
        def check_if_keywords_extracted_from_pcap(self):
            # Initial list of keywords harvested from the PCAP
            self.keywords = self.keywords if self.keywords else self._get_keywords_from_pcap()
            return function_depending_on_keywords(self)
        return check_if_keywords_extracted_from_pcap


    def _get_candidate_binaries(self):
        all_keywords = '|'.join(self.keywords)
        os_cmd = 'find %(fw_dir)s -exec file {} \; | grep -i ELF | awk \'{ print substr($1, 1, length($1)-1) }\' | xargs -I {} grep -lE \'%(all_keywords)s\' {}' % {'fw_dir': self.fw_dir, 'all_keywords': all_keywords}
        try:
            candidate_binaries = subprocess.check_output(os_cmd, shell=True)
        except Exception as e:
            candidate_binaries = str(e.output)
        candidate_binaries = candidate_binaries.strip().split('\n')
        return candidate_binaries


    def is_binaries(function_depending_on_binaries):
        def check_if_binaries_extracted_from_firmware(self):
            # Firmware binaries to be analyzed for potential key strings
            self.binaries = self.binaries if self.binaries else self._get_candidate_binaries()
            return function_depending_on_binaries(self)
        return check_if_binaries_extracted_from_firmware


    def _find_str_xref_in_call(self, str_addrs, found=lambda *x: True, only_one=False):
        cfg = self.cfg
        p = self.project
        info_collected = {}

        # Get all the string references we are looking for
        direct_refs = [s for s in cfg.memory_data.items() if s[0] in str_addrs]
        print "[DEBUG]: direct_refs", direct_refs
        indirect_refs = get_indirect_str_refs(p, cfg, str_addrs)
        print "[DEBUG]: indirect_refs", indirect_refs
        import ipdb; ipdb.set_trace()

        for a, s in direct_refs + indirect_refs:
            print "[DEBUG]: (a, s)", a, s, type(a), type(s)
            info_collected[s.address] = []

            if is_call(s):
                for (irsb_addr, stmt_idx, insn_addr) in list(s.refs):
                    if are_parameters_in_registers(p):
                        reg_used = get_reg_used(self.project, self.cfg, irsb_addr, stmt_idx, a)
                        print "[DEBUG]: reg_used", reg_used
                        if not reg_used:
                            continue

                        ret = found(self.cfg, cfg.get_any_node(irsb_addr), s.address, reg_used)
                        info_collected[s.address].append(ret)
                    else:
                        self.logger.error("Architecture doesn't use registers to pass function parameters")
                        import ipdb; ipdb.set_trace()

                    if only_one:
                        break

        return info_collected


    def _get_key_value_extractor_method_xref_based(self):
        keyword_addrs = get_addrs_string(self.project, self.keywords)
        print "[DEBUG]: ", [hex(keyword_addr) for keyword_addr in keyword_addrs]
        print "[DEBUG]: ", self._find_str_xref_in_call(keyword_addrs)


    def _get_call_target(self, function, call_instruction_addr):
        for block in function.blocks:
            if block.instruction_addrs[-1] == call_instruction_addr:
                call_targets = list(block.vex.constant_jump_targets)
                # BUGFIX: https://github.com/angr/angr/issues/307
                if len(call_targets) != 1:
                    self.logger.warning('No or more than one call targets at basic block 0x%x' % block.addr)
                    return None
                call_target = call_targets[0]
                return call_target


    def _get_callee_function_parameters(self, function):
        if not function:
            return None

        function_parameters_at_obs_pt = []

        try:
            calls = [block.instruction_addrs[-1] for block in function.blocks if block.vex.jumpkind == 'Ijk_Call']
            observation_points = [(call, angr.analyses.reaching_definitions.OP_BEFORE) for call in calls]
            if len(observation_points) == 0:
                return None
            rd = self.project.analyses.ReachingDefinitions(func=function, observation_points=observation_points, init_func=True)
        except Exception as e:
            self.logger.warning(str(e) + ', func_addr=' + hex(function.addr))
            return None

        # Does this architecure pass parameters through registers?
        if are_parameters_in_registers(self.project):
            # Record parameter values at every observation points; which are basically call sites to other functions
            for observation_point in observation_points:
                # Don't bail out entirely if reach-def analysis complains for a few functions
                try:
                    observed_result = rd.observed_results[observation_point]
                    # Record the values in each of the registers for a call site
                    for reg_off in argument_regs[self.project.arch.name]:
                        # There can be more than one possible values per register per call site
                        for reg_def in observed_result.register_definitions.get_objects_by_offset(reg_off):
                            for parameter in reg_def.data.data:
                                if type(parameter) == angr.analyses.reaching_definitions.undefined.Undefined:
                                    continue
                                if type(parameter) not in (int, long):
                                    self.logger.warning('Data type is unexpected')
                                call_instruction_addr = observation_point[0]
                                call_target = self._get_call_target(function, call_instruction_addr)
                                if call_target:
                                    function_parameter_values = (observation_point, reg_off, parameter, call_target)
                                    function_parameters_at_obs_pt.append(function_parameter_values)
                except Exception as e:
                    import ipdb; ipdb.set_trace()
            return function_parameters_at_obs_pt
        else:
            self.logger.warning('Calling convention is not supported')
            import ipdb; ipdb.set_trace()


    def _get_all_function_parameters_at_all_callsites(self):
        global all_function_parameters_at_all_callsites
        global all_strings_addr_len

        all_strings_addr_len = get_all_strings_addr_len(self.project)

        for function_addr in self.cfg.functions:
            function = self.cfg.functions.function(function_addr)
            callee_function_parameters = self._get_callee_function_parameters(function)
            if callee_function_parameters:
                all_function_parameters_at_all_callsites += callee_function_parameters


    def _get_call_sites_using_known_keywords(self):
        global all_function_parameters_at_all_callsites
        call_sites_using_known_keywords = []

        self._get_all_function_parameters_at_all_callsites()
        keyword_addrs = get_addrs_string(self.project, self.keywords)

        for function_parameters_at_obs_pt in all_function_parameters_at_all_callsites:
            observation_point, reg_off, parameter, function_addr = function_parameters_at_obs_pt
            for keyword_addr in keyword_addrs:
                if parameter == keyword_addr:
                    call_sites_using_known_keywords.append((observation_point, reg_off, keyword_addr, function_addr))
        return call_sites_using_known_keywords


    def _filter_key_extractor_methods(self, call_sites_using_known_keywords):
        func_param_to_keyword_map = {}
        keyword_to_obs_pt_map = {}

        for call_site_using_known_keywords in call_sites_using_known_keywords:
            observation_point, reg_off, keyword_addr, function_addr = call_site_using_known_keywords

            keyword_list = func_param_to_keyword_map.get((function_addr, reg_off))
            if keyword_list:
                keyword_list.append(keyword_addr)
            else:
                keyword_list = []
                keyword_list.append(keyword_addr)
                func_param_to_keyword_map[(function_addr, reg_off)] = keyword_list

            obs_pt_list = keyword_to_obs_pt_map.get(keyword_addr)
            if obs_pt_list:
                obs_pt_list.append(observation_point)
            else:
                obs_pt_list = []
                obs_pt_list.append(observation_point)
                keyword_to_obs_pt_map[keyword_addr] = obs_pt_list

        return func_param_to_keyword_map.keys()


    def _get_key_value_extractor_methods(self):
        call_sites_using_known_keywords = self._get_call_sites_using_known_keywords()
        key_value_extractor_methods = self._filter_key_extractor_methods(call_sites_using_known_keywords)
        return key_value_extractor_methods


    @is_keywords
    @is_binaries
    def get_potential_keywords(self):
        potential_keywords_in_firmware = self.keywords.copy()
        total_binary_count = len(self.binaries)

        for current_binary_count, binary in enumerate(self.binaries):
            self.logger.info('Extracting potential keywords from the %s binary (%d/%d)' % (binary, current_binary_count + 1, total_binary_count))
            self.binary = binary
            self.project = angr.Project(self.binary, auto_load_libs=False)
            self.cfg = self.project.analyses.CFG(collect_data_references=True, extra_cross_references=True, normalize=True)

            key_value_extractor_methods = self._get_key_value_extractor_methods()
            potential_keywords_in_binary = set()

            for function_parameter_at_a_callsite in all_function_parameters_at_all_callsites:
                observation_point, func_param_reg_off, parameter, call_target = function_parameter_at_a_callsite
                for key_value_extractor_method in key_value_extractor_methods:
                    function_addr, key_value_reg_off = key_value_extractor_method
                    if call_target == function_addr and func_param_reg_off == key_value_reg_off:
                        potential_keyword = get_string(self.project, parameter)
                        if potential_keyword:
                            potential_keywords_in_binary.add(potential_keyword)

            potential_keywords_in_firmware = potential_keywords_in_firmware.union(potential_keywords_in_binary)
            self.logger.info('Potential keywords in the %s binary: %s' % (self.binary, str(potential_keywords_in_binary)))

        potential_keywords_in_firmware = list(potential_keywords_in_firmware)
        return potential_keywords_in_firmware


    def read_potential_keywords(self):
        with open('{}/key_strings.txt'.format(os.path.dirname(__file__)), 'r') as fp:
            potential_keywords_in_firmware = fp.read().split('\n')
        return potential_keywords_in_firmware


if __name__ == "__main__":
    if len(sys.argv) == 3:
        fw_dir = sys.argv[1]
        pcap_dir = sys.argv[2]
    else:
        fw_dir = '/data/research/projects/iotfuzzer/insteon_fw'
        pcap_dir='/data/research/projects/iotfuzzer/insteon_fw'
    kh = KeyHunter(fw_dir, pcap_dir)
    potential_keywords_in_firmware = kh.get_potential_keywords()
    kh.logger.info('Potential keywords in firmware: %s' % str(potential_keywords_in_firmware))

