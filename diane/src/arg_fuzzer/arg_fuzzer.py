import json
import time
import logging
import os
import signal
import itertools
from values import Values
from pysoot.lifter import Lifter
import sys
from os.path import dirname, abspath

sys.path.append(dirname(dirname(abspath(__file__))))

from frida_hooker import FridaHooker, ApkExploded, TransportError, FridaRunner, FridaRunnerMeta
from crash_detector.pcap_base_detector import PcapBasedDetector
from ui.core import ADBDriver

logging.basicConfig()
log = logging.getLogger("ArgFuzzer")
log.setLevel(logging.DEBUG)

PRIMITIVE_TYPES = ["byte", "short", "int", "long", "char", "float", "double", "boolean", "[B", "[I"]
KNOWN_OBJ = ["java.lang.String", "java.lang.Integer", "java.lang.Float", "java.lang.Double", "java.nio.ByteBuffer"]
FUZZ_RES_PATH = "{}/{}_IoTFuzz/"
FUZZ_RES_FILE_NAME = "{}_0"

N_FUZZ = 1000
WINDOW_FUZZ = 350


class FuzzTerminate(Exception):
    pass


class ArgFuzzer:
    __metaclass__ = FridaRunnerMeta

    def __init__(self, config, hooker=None, generator=None):
        self.config = config
        self.hooker = hooker if hooker else FridaHooker(config)
        self.lifter = None
        self.vals = Values(config, generator=generator)
        self.an = PcapBasedDetector(config)
        self.reran_proc = None
        self.fuzz_history = {}

        self.fuzz_res_dir = FUZZ_RES_PATH.format(config["results_path"], config["proc_name"])
        os.system('mkdir -p ' + self.fuzz_res_dir)
        self.fp = None

        self.traces = {}
        self.pos_trace = 0
        self.replaying = False

        # debug fields
        self.pos_fun_param_to_fuzz = None
        self.fields = []
        self.fuzz_class_fields = True
        self.fuzz_fun_params = True

    def parse_trace_file(self, fpath):
        with open(fpath) as fp:
            m = None
            arg_vals = []
            pos = None
            conf = None

            def save_vals(_v, _m, _p, _c):
                _v[-1] = _v[-1][:-1]
                self.traces[_m][_c][_p].append(''.join(arg_vals))

            for line in fp:
                if '*** Method:' in line:
                    arg_vals = []
                    m = line.split('*** Method: ')[1].strip()
                    if m not in self.traces:
                        self.traces[m] = {}
                elif 'Fuzzed Args:' in line:
                    assert m
                    if arg_vals:
                        save_vals(arg_vals, m, pos, conf)
                        arg_vals = []

                    conf = line.split('Fuzzed Args: (')[1].split('),')[0]
                    conf = tuple(map(int, [x for x in conf.split(',') if x]))
                    if conf not in self.traces[m]:
                        self.traces[m][conf] = {}
                    pos = line.split('Arg pos: ')[1].split(',')[0]
                    if pos not in self.traces[m][conf]:
                        self.traces[m][conf][pos] = []

                    val = line.split(', val: ')[1]
                    arg_vals.append(val)
                else:
                    arg_vals.append(line)

            if pos:
                assert m and conf
                save_vals(arg_vals, m, pos, conf)

    def save_run(self):
        log.info("Interesting run  detected.")
        if self.fp is not None:
            log.info("Saving it...")
            for key, vals in self.fuzz_history.items():
                for val in vals:
                    self.fp.write("Fuzzed Args: {}, Arg pos: {}, type: {}, val: {}\n".format(
                        key[0], key[1], key[2], str(val))
                    )
        self.fp.flush()

    def kill_reran(self):
        try:
            os.killpg(os.getpgid(self.reran_proc.pid), signal.SIGTERM)
        except:
            pass

    def is_known_type(self, p):
        return any([p.startswith(pt) for pt in PRIMITIVE_TYPES + KNOWN_OBJ])

    def is_primitive_type(self, p):
        return any([p.startswith(pt) for pt in PRIMITIVE_TYPES])

    def hook_new_methods(self, methods):
        time.sleep(5)
        log.debug("Hooking {} methods".format(len(methods)))
        self.hooker.start(methods, force_hook=True)

    def wait_for_repetition(self):
        while not self.hooker.is_repetition_done():
            time.sleep(1)
            # return if reran finished
            if self.reran_proc.poll() is not None:
                log.debug("Stop waiting, reran finished. Might not be the correct send")
                return

    def wait_for_reran(self):
        while True:
            time.sleep(1)
            # return if reran finished
            if self.reran_proc.poll() is not None:
                return

    def equal_types(self, a, b):
        #FIXME: fix this!!! Use the frida_hooker approach instead
        if a is None or b is None:
            return False

        if "[]" in a:
            a = "[" + a[0].upper()
        if "[]" in b:
            b = "[" + b[0].upper()
        return a == b

    def spawn_and_fuzz_class_field(self, method, times, field_name, finfo, fast_fuzz=False, pos_in_trace=0):
        cls = method[0]
        m = method[1]

        obj_type = finfo[1]

        self.hook_new_methods([method])
        self.hooker.prepare_new_fuzzing(cls, m, times, 0, fast_fuzz)

        log.info("Setting up {} different values for the field {}. "
                  "This might take a while".format(str(times), str(field_name)))

        for _ in xrange(times):
            self.hooker.next_fields_list()
            field_val = self.vals.create_value(obj_type, self.hooker.modify_class_field, field_name)
            if field_val is None:
                log.error("fuzz_primitive has does not have a function for type {}".format(obj_type))
                continue

            key_h = (field_name, obj_type)
            if key_h not in self.fuzz_history:
                self.fuzz_history[key_h] = []
            self.fuzz_history[key_h].append(field_val)
        log.info("Done.")
        self.hooker.fuzz_prepare_done(True)

    def get_class_fields(self, cls, extended=True):
        def rename_for_frida(f):
            f_name = f[0]
            f_info = f[1]
            if any([str(m.name) == f_name for m in self.lifter.classes[cls].methods]):
                f_name = '_' + f_name
            return (f_name, f_info)

        if self.fields:
            # for debugging
            return self.fields
        if not self.lifter:
            log.info("Building lifter")
            apk_path = self.config["apk_path"]
            android_sdk = self.config["android_sdk_platforms"]
            self.lifter = Lifter(apk_path, input_format="apk", android_sdk=android_sdk)

        # get all the fields: own and inherited boths
        clx = self.lifter.classes[cls]
        fields = map(rename_for_frida, clx.fields.items())

        if extended:
            worklist = [clx.super_class]
            while worklist:
                cls = worklist[0]
                worklist = worklist[1:]
                if cls == 'java.lang.Object':
                    break
                clx = self.lifter.classes[cls]
                fields += map(rename_for_frida, clx.fields.items())
                worklist.append(clx.super_class)

        return fields

    def spawn_and_fuzz_param(self, method, times, pos_to_fuzz, fast_fuzz=False, single_call_fuzz=False, curr_call=0 ):
        cls = method[0]
        m = method[1]
        params = method[2]

        self.fuzz_history = {}
        self.hook_new_methods([method])
        self.hooker.prepare_new_fuzzing(cls, m, times, len(params), fast_fuzz, single_call_fuzz, curr_call)

        log.info("Setting up {} different values for the {}-th parameters of {}:{}"
                    " This might take a while".format(str(times),
                                                      ', '.join(map(lambda x: str(x + 1), pos_to_fuzz)),
                                                      cls, m))
        for _ in xrange(times):
            # add new param list
            self.hooker.next_param_list()

            for i, p_type in enumerate(params):
                if i in pos_to_fuzz:
                    if not self.is_known_type(p_type):
                        # parameters is a not primitive,
                        # we gotta retrieve the object fields
                        # and fuzz them
                        par_val = "Class Obj"
                        try:
                            class_fields = self.get_class_fields(p_type)
                        except KeyError:
                            log.warning('Cannot find class {}'.format(p_type))
                            continue
                        for fname, finfo in class_fields:
                            obj_type = finfo[1]
                            self.vals.create_value(obj_type, self.hooker.modify_class_field, fname)
                            self.hooker.set_arg_simple_obj()
                    else:
                        par_val = self.vals.create_value(p_type, self.hooker.create_obj)
                        if par_val is None:
                            log.error("fuzz_primitive does not have a function for type {}".format(p_type))
                            self.hooker.set_unfuzzed_obj()
                            continue

                    # log it!
                    key_h = (str(pos_to_fuzz), str(i), p_type)
                    if key_h not in self.fuzz_history:
                        self.fuzz_history[key_h] = []
                    self.fuzz_history[key_h].append(par_val)
                else:
                    self.hooker.set_unfuzzed_obj()

        log.info("Done.")
        self.hooker.fuzz_prepare_done(True)

    def spawn_and_replay_class_field(self, *kargs, **kwargs):
        log.error("Replay class fields is not implemented... yet")

    def spawn_and_replay_param(self, method, times, pos_to_fuzz, fast_fuzz=False):
        cls = method[0]
        m = method[1]
        params = method[2]
        traces = self.traces[str(method)][pos_to_fuzz]
        pos_trace = self.pos_trace
        self.hook_new_methods([method])
        self.hooker.prepare_new_fuzzing(cls, m, times, len(params), fast_fuzz)
        log.info("Setting up {} different values for the {}-th parameters of {}:{}"
                 " This might take a while".format(str(times),
                 ', '.join(map(lambda x: str(x + 1), pos_to_fuzz)),
                                                      cls, m))

        for _ in xrange(times):
            # add new param list
            self.hooker.next_param_list()
            for p, p_type in enumerate(params):
                if p in pos_to_fuzz:
                    s_p = str(p)
                    if s_p not in traces:
                        self.hooker.set_unfuzzed_obj()
                    else:
                        p_type = params[p]
                        if not self.is_known_type(p_type):
                            log.error("Replay non primitive fields not implemented..yet.")
                        else:
                            try:
                                vals = traces[s_p][pos_trace].strip()
                                if '[' in vals:
                                    vals = vals[1:-1].split(', ')
                            except:
                                import ipdb; ipdb.set_trace()
                            base_type = p_type.strip('[]')
                            nelem = 1

                            if '[]' in p_type:
                                nelem = len(vals)
                            else:
                                vals = [vals]

                            if not vals[0]:
                                par_val = []
                            else:
                                try:
                                    par_val = map(getattr(self.vals, 'str_to_' + str(base_type.replace('.', '_'))), vals)
                                except:
                                    import ipdb; ipdb.set_trace()

                                    par_val = map(getattr(self.vals, 'str_to_' + str(base_type.replace('.', '_'))), vals)

                            if nelem == 1:
                                try:
                                    par_val = par_val[0]
                                except:
                                    par_val = []

                            # FIXME: check that javascript functions to create ad-hoc objects work here
                            self.hooker.create_obj(base_type, self.is_primitive_type(p_type), par_val, nelem)
                else:
                    self.hooker.set_unfuzzed_obj()
            pos_trace += 1

        log.info("Done.")
        self.hooker.fuzz_prepare_done(False)

    def terminate(self):
        self.kill_reran()
        raise FuzzTerminate("Stop")

    def do_fuzz(self, method, spawn_and_prepare_ran, ran_fun, remain_reps, *kargs, **kwargs):
        log.info("Fuzzing device with {} values".format(str(remain_reps)))
        tot_reps = 0
        unlimited = False
        first_run = True

        if 'single_call_fuzz' in kwargs and kwargs['single_call_fuzz']:
            # first execute one run to register the number
            # of calls
            kwargs['curr_call'] = 0
            self.hooker.start([method], force_hook=True)
            self.reran_proc = ran_fun()
            self.wait_for_reran()
            util_method_calls = self.hooker.get_n_repeated()
            log.info("Hooked function repeated {} times".format(str(util_method_calls)))

        # set initial number or repetitions
        if remain_reps is None:
            remain_reps = 0
            unlimited = True
            reps = WINDOW_FUZZ
        else:
            reps = min(remain_reps, WINDOW_FUZZ)

        while remain_reps > 0 or unlimited:
            try:
                spawn_and_prepare_ran(method, reps, *kargs, **kwargs)
                #reg_id = self.an.start_reg_run()
                self.reran_proc = ran_fun()
                self.wait_for_reran()
                # check and save run results
                #self.an.stop_reg_run(reg_id)

                #if not self.an.verify_reg_run(reg_id):
                #    log.info("Interesting run registered")
                self.save_run()

                # check how many times function has been executed
                n_repeated = self.hooker.get_n_repeated()
                log.info("Hooked function repeated {} times".format(str(n_repeated)))
                fuzzed_last_ran = min(n_repeated, reps)
                remain_reps -= fuzzed_last_ran

                # adaptive window
                if first_run:
                    reps = n_repeated
                    first_run = False
                if reps < n_repeated:
                    reps = n_repeated
                if not unlimited and reps > remain_reps:
                    reps = remain_reps

                tot_reps += fuzzed_last_ran
                if self.replaying:
                    self.pos_trace += fuzzed_last_ran

                if tot_reps == 0:
                    return False

                if 'curr_call' in kwargs:
                    kwargs['curr_call'] = (kwargs['curr_call'] + 1) % util_method_calls
                    n = self.hooker.get_util_calls(method)
                    if n != 0:
                        util_method_calls = n
                    print "Utils calls: " + str(util_method_calls)

                log.info("Function fuzzed {} times.".format(str(tot_reps)))
            except ApkExploded as ae:
                log.error("App exploded")
                # we replayed the function once and the app exploded
                # let's move on
                if tot_reps <=1 and self.hooker.get_n_repeated() <= 1:
                    log.debug("Param or class field make the app crash. Stop fuzzing this one.")
                    break

        log.info("Fuzzing completed")
        return True

    def get_combination(self, ls):
        cmb = []
        for s in range(0, len(ls) + 1):
            for subset in itertools.combinations(ls, s):
                cmb.append(subset)
        return cmb

    def do_fuzz_params_function(self, method, ran_fun, fast_fuzz=False, single_call_fuzz=False):
        cls = method[0]
        m = method[1]
        params = method[2]
        if not fast_fuzz:
            log.info("Fuzzing params functions: Fuzzing might take a while, fast_fuzz is disabled."
                     "We change values to the sweet spot every time we encounter it")
        else:
            log.info("Fast fuzz is enabled")

        cmb = self.get_combination(range(len(params)))
        cmb = [x for x in cmb if x]

        for pos in cmb:
            if self.pos_fun_param_to_fuzz is not None:
                if (pos not in self.pos_fun_param_to_fuzz) and (pos != self.pos_fun_param_to_fuzz):
                    continue

            fuzzed = self.do_fuzz(method, self.spawn_and_fuzz_param, ran_fun, N_FUZZ, pos,
                                  fast_fuzz=fast_fuzz, single_call_fuzz=single_call_fuzz)
            if not fuzzed:
                log.debug("Reran finished and sweet spot was not encoutered.")
                break
            log.info("Param fuzzed")

    # FIXME: handle single_call_fuzz and curr_call
    def do_fuzz_class_fields(self, method, ran_fun, fast_fuzz=False, single_call_fuzz=False):
        # if methods take no argument, we will fuzz
        # every simple objects in its class
        cls = method[0]
        class_fields = self.get_class_fields(cls)

        if not fast_fuzz:
            log.info("Fuzzing might take a while, fast_fuzz is disabled."
                     "We change values to the sweet spot every time we encounter it")
        else:
            log.info("Fast fuzz is enabled")

        for fname, ftype_info in class_fields:
            type_field = ftype_info[1]
            if not self.is_known_type(type_field):
                log.error("Field {} is not of a primitive type.. skipping this one. Implement me.".format(fname))
                continue

            fuzzed = self.do_fuzz(method, self.spawn_and_fuzz_class_field, ran_fun, fname,
                            ftype_info, N_FUZZ, fast_fuzz=fast_fuzz)
            if not fuzzed:
                log.debug("Reran finished and sweet spot was not encoutered.")
                break
            log.info("Object fuzzed")

    def register_normal_run(self, ran_fun):
        #self.an.start_normal_run()
        #ran_fun()
        #if not self.an.stop_normal_run():
        #    log.error("Can't save pcap files to verify fuzzing results")
        pass

    def get_res_complete_path(self, method):
        s_params = '_'.join(map(str, method[2]))
        m_string = '_'.join([str(method[0]), str(method[1]),s_params, str(method[3])]).replace('u\'', '')
        m_string = m_string.replace('[]', '_array')
        return self.fuzz_res_dir + FUZZ_RES_FILE_NAME.format(m_string)

    def start(self, method, fast_fuzz=False, ran_fun=lambda *args: None, reg_run=True, single_call_fuzz=False, lifter=None):
        self.lifter = lifter

        name = self.get_res_complete_path(method)

        counter = 1
        while os.path.isfile(name):
            name = '_'.join(name.split('_')[:-1]) + '_' + str(counter)
            counter += 1
        self.fp = open(name, "w")

        if reg_run:
            self.register_normal_run(ran_fun)

        # start new fuzzing
        self.fuzz_history = {}
        self.fp.write("\n*** Method: {}\n ***".format(str(method)))

        try:
            params = method[2]
            if params and params[0] and self.fuzz_fun_params:
                log.info("Fuzzing params")
                self.do_fuzz_params_function(method, ran_fun, fast_fuzz=fast_fuzz, single_call_fuzz=single_call_fuzz)

            if self.fuzz_class_fields:
                log.info("Fuzzing class fields")
                self.do_fuzz_class_fields(method, ran_fun, fast_fuzz=fast_fuzz, single_call_fuzz=single_call_fuzz)
        except FuzzTerminate as ft:
            log.info("Fuzz terminate")

        self.fp.close()
        log.info("Terminating Fuzzing")

    def replay_trace(self, trace_file, fast_fuzz=False, ran_fun=lambda *args: None):
        self.replaying = True
        self.parse_trace_file(trace_file)
        # debug data structure

        for s_method, r_info in self.traces.iteritems():
            # extract method info from string
            cls = s_method.split(', ')[0][1:].strip('\'')
            m = s_method.split(', ')[1].strip('\'')
            s_params = s_method.split(', [\'')[1].split('], \'')[0]
            params = map(lambda x: x.strip('\''), s_params.split(', '))
            ret = s_method.split(', ')[-1][:-1].strip('\'')
            method = [cls, m, params, ret]

            for comb, c_info in r_info.iteritems():
                self.pos_trace = 0
                times = len(c_info.values()[0])
                self.do_fuzz(method, self.spawn_and_replay_param, ran_fun, times, comb, fast_fuzz=fast_fuzz)

if __name__ == "__main__":
    from ui.core import ADBDriver
    from optparse import OptionParser
    import ast

    parser = OptionParser()
    usage = "usage: %prog config_path [options] arg1 "
    parser = OptionParser(usage=usage)
    parser.add_option("-l", "--lifter", dest="lifter", action="store_true",
                      help="build lifter", default=False)
    parser.add_option("-s", "--sweet_file", dest="sweets_file",
                      help="file containing sweet-spots", metavar="FILE")
    parser.add_option("-t", "--trace_file", dest="trace_file",
                      help="file containing a pvreiovus run to replay", metavar="FILE")
    (options, args) = parser.parse_args()
    if not args:
        parser.print_help()
        sys.exit(0)
 
    config_path = args[0]
    with open(config_path) as fp:
        config = json.load(fp)

    lifter = None
    trace_file = options.trace_file
    sweets_file = options.sweets_file
    ss = config['send_functions'] + config['sweet_spots']

    if sweets_file:
        with open(sweets_file) as fp:
            ss = []
            for s_method in fp:
                # extract method info from string
                s_method = s_method.strip()
                cls = s_method.split(', ')[0][1:].strip('\'')
                m = s_method.split(', ')[1].strip('\'')
                s_params = s_method.split(', \"[\'')[1].split(']\", \'')[0]
                params = map(lambda x: x.strip('\''), s_params.split(', '))
                if 'PAR' not in s_method:
                    ret = s_method.split(', ')[-1][:-1].strip('\'')
                    pars = []
                else:
                    ret = s_method.split(' PAR ')[0].split(', ')[-1][:-1].strip('\'')
                    pars = ast.literal_eval(s_method.split(' PAR ')[1])

                method = [cls, m, params, ret]
                ss.append((method, pars))

    reran_record_path = config["reran_record_path"]
    adbd = ADBDriver(f_path=reran_record_path, device_id=config['device_id'])

    af = ArgFuzzer(config)
    af.fuzz_class_fields = False

    if options.lifter:
        print "Building lifter"
        apk_path = config["apk_path"]
        android_sdk = config["android_sdk_platforms"]
        lifter = Lifter(apk_path, input_format="apk", android_sdk=android_sdk)

    if trace_file:
        af.replay_trace(trace_file, ran_fun=adbd.replay_ui_async)
    else:
        for s, pars in ss:
            print "Fuzzing " + str(s)
            if pars:
                af.pos_fun_param_to_fuzz = pars
                print "Paramenters " + str(pars)
            else:
                af.pos_fun_param_to_fuzz = None
            af.start(s, ran_fun=adbd.replay_ui_async, single_call_fuzz=True, reg_run=False, lifter=lifter)

    print "DONE."
