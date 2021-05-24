import time
import frida
import os
import ast
import json
import signal
import pickle
import types

from optparse import OptionParser
from optparse import Option, OptionValueError

from os.path import dirname, abspath
from frida import TransportError, InvalidOperationError
import sys
sys.path.append(dirname(dirname(abspath(__file__))))

from node_filter.node_filter import NodeFilter

import logging

logging.basicConfig()
log = logging.getLogger("FridaHooker")
log.setLevel(logging.DEBUG)

GRANULARITY_IGN_HOOK = 1
SUCC_THRESH_HOOK = 1
SCRIPT_NAMES = ["base_script.js", "object_setter.js", "exports.js"]
DUMP_RESULTS_PATH = "/tmp/frida_results.pickle"
TIME_LOG = "/tmp/frida_time.log"
WAIT_FOR_HOOK_SEC = 5
WAIT_FOR_SPAWN_SEC = 50
TYPE_DESCRIPTOR = {'short': 'S',
                     'int': 'I',
                     'double': 'D',
                     'void': 'V',
                     'float': 'F',
                     'long': 'J',
                     'char': 'C',
                     'boolean': 'Z',
                     'byte': 'B'}

R_TYPE_DESCRIPTOR = {v: k for k, v in TYPE_DESCRIPTOR.items()}


class ApkExploded(Exception):
    pass


class ApkKilled(Exception):
    pass


class ApkStuck(Exception):
    pass


def deprecated(func):
    def f(*args, **kwargs):
        log.warning("Call to deprecated function %s." % func.__name__)
        return func(*args, **kwargs)
    f.__name__ = func.__name__
    f.__doc__ = func.__doc__
    f.__dict__.update(func.__dict__)
    return f


def fun_decorator(f):
    def g(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        #except TransportError as te:
        #    log.debug("Caught TransportError exception in " + f.__name__)
        except InvalidOperationError as ioe:
            log.debug("Caught InvalidOperationError exception in " + f.__name__)
            raise ApkExploded('InvalidOperationError')

    g.__name__ = f.__name__
    return g


class MultipleOption(Option):
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            values.ensure_value(dest, []).append(value)
        else:
            Option.take_action(self, action, dest, opt, value, values, parser)


class FridaRunnerMeta(type):
    def __new__(cls, name, bases, attrs):
        for a_name, a_value in attrs.iteritems():
            if a_name == 'spawn_apk_in_device':
                # we do not want to suppress any frida's
                # exceptions until the app is spawn
                continue

            if isinstance(a_value, types.FunctionType):
                attrs[a_name] = fun_decorator(a_value)

        return super(FridaRunnerMeta, cls).__new__(cls, name, bases, attrs)


def FridaRunner(cls):
    for a_name, a_value in cls.__dict__.items():
        if a_name == 'spawn_apk_in_device':
            # we do not want to suppress any frida's
            # exceptions until the app is spawn
            continue
        binded_value = cls.__dict__[a_name]

        if hasattr(a_value, '__call__') and \
                not isinstance(binded_value, staticmethod):
            setattr(cls, a_name, fun_decorator(a_value))
    return cls


class FridaHooker:
    __metaclass__ = FridaRunnerMeta

    def __init__(self, config, node_filter=None):
        global DUMP_RESULTS_PATH
        self.config = config

        self.device = None
        self.device_id = config['device_id']
        self.proc_name = config['proc_name']
        self.dump_result_path = DUMP_RESULTS_PATH + "_" + self.proc_name
        self.time_log_path = TIME_LOG+ "_" + self.proc_name

        self.ignore_methods = config["skip_methods"]
        self.ignore_classes = config["skip_classes"]
        self.fhp = config['frida_hooker_pickle']

        self.hooking_method = None
        self.hook_done = False
        self.stuck = False
        self.force_hook = False
        self.nf = node_filter

        self.script = None
        self.script_cnt = None
        self.frida_separators = {}
        self.last_methods_called = []
        self.last_methods_instances = []
        self.last_methods_errored = []
        self.is_running = False
        self.last_methods_call_time = None
        self.method_repeat_done = False
        self.method_n_repeatitions = 0
        self.method_tot_repeatitions = -1

        self.good_hooks = {}
        self.setup()

    @staticmethod
    def wait_for_spawn():
        log.info("Sleeping for {} sec to give time to the app to spawn"
                 " completely".format(str(WAIT_FOR_SPAWN_SEC)))
        time.sleep(WAIT_FOR_SPAWN_SEC)  # ten seconds to give reran time

    @property
    def methods_called(self):
        return self.last_methods_called

    @property
    def methods_instances(self):
        return self.last_methods_instances

    @property
    def methods_call_time(self):
        return self.last_methods_call_time

    def wait_for_destroy_signal(self):
        debug_warning = 0
        try:
            while True:
                time.sleep(1)

                debug_warning += 1
                if debug_warning > 120:
                    log.debug("Got stuck in waiting for destroy?")
                    self.is_running = False
                    break
        except:
            pass
        if self.is_running:
            import ipdb; ipdb.set_trace()
        #assert not self.is_running, "signal_handler did not set is_running to False"

    def was_called(self, cls, method, args):
        return any([x[0] == cls and x[1] == method and x[2] == args
                    for x in self.last_methods_called])

    def kill_app(self, is_stuck=False):
        self.stuck = is_stuck
        is_running = self.is_running
        try:
            proc = self.device.get_process(self.config['proc_name'])
            self.device.kill(proc.pid)
            log.debug("APK killed")
            if is_running:
                self.wait_for_destroy_signal()
        except:
            pass

    def on_message(self, message, data):
        if message['type'] == 'send':

            if message['payload'].startswith('METHODS'):
                self.last_methods_call_time = time.time()
                cnt = message['payload'][7:]
                methods = cnt.split(self.frida_separators['next_entry'])
                self.last_methods_called = map(self.our_notation, methods)

            elif message['payload'].startswith('INSTANCES'):
                cnt = message['payload'][9:]
                methods = cnt.split(self.frida_separators['next_entry'])
                self.last_methods_instances = map(
                    lambda x: self.our_notation(x, is_instance=True), methods
                )

            elif message['payload'].startswith('HOOKING'):
                cnt = message['payload'][7:]
                self.hooking_method = self.our_notation(cnt)

            elif message['payload'].startswith('ERRORED'):
                cnt = message['payload'][7:]
                self.last_methods_errored.append(self.our_notation(cnt))

            elif message['payload'].startswith('HOOKDONE'):
                self.hook_done = True

            elif message['payload'].startswith('NREP:'):
                n_rep = int(message['payload'][5:])
                if self.method_n_repeatitions < n_rep:
                    self.method_n_repeatitions = n_rep

                if self.method_n_repeatitions >= self.method_tot_repeatitions > 0:
                    log.debug("Repetition done")
                    self.method_repeat_done = True

            elif message['payload'] == 'REPEATDONE':
                log.debug("Repetition done")
                self.method_repeat_done = True

            else:
                log.warning("[*] {0}".format(message['payload']))

        else:
            log.debug("Whoops, error received. ")
            log.error(message)
            if self.last_methods_called and not self.force_hook:
                log.debug("Ignoring last function")
                method = self.last_methods_called[-1]
                self.ignore_methods.append(method)

    def on_destroyed(self):
        if log is not None and os is not None:
            log.debug("on_destroyed called")
            os.kill(os.getpid(), signal.SIGUSR1)

    def terminate(self):
        self.last_methods_called = []
        self.last_methods_instances = []
        self.kill_app()

    def signal_handler(self, sig, frame):
        if sig == signal.SIGUSR1:
            log.debug("SIGUSR1 caught")
            is_running = self.is_running
            self.is_running = False

            # app exploded and wasn't stuck on a hook
            if not self.stuck and is_running:
                raise ApkExploded("Crash")
            # app was stuck on a hook
            if self.stuck:
                raise ApkStuck("Intentionally killed")
            # we killed it
            raise ApkKilled("Killed")

        # unexpected :(
        raise Exception("Caugth signal " + str(sig))

    def setup(self):
        signal.signal(signal.SIGUSR1, self.signal_handler)

        # setup frida
        self.device = frida.get_device(self.device_id)
        self.script_cnt = ''
        for name in SCRIPT_NAMES:
            path_script = os.path.dirname(__file__) + '/' + name
            with open(path_script) as f:
                self.script_cnt += f.read()

            self.script_cnt += '\n'

        # unpickle the results, if any:
        try:
            data = pickle.load(open(self.fhp))
            self.ignore_methods += data['skip_methods']
            self.ignore_classes += data['skip_classes']
            self.good_hooks.update(data['good_hooks'])
        except:
            pass

    def spawn_apk_in_device(self, to_hook=None, get_instances=False):
        try:
            if to_hook is None:
                to_hook = []
            pid = self.device.spawn([self.proc_name])
            self.device.resume(pid)
            time.sleep(1)  # Without it Java.perform silently fails
            session = self.device.attach(pid)
            self.script = session.create_script(self.script_cnt)
            self.script.on('message', self.on_message)
            self.script.on('destroyed', self.on_destroyed)
            self.script.load()
            self.frida_separators = self.script.exports.getseparators()
            self.script.exports.runit(to_hook, get_instances)
        except Exception as e:
            self.is_running = False
            raise e

    def setup_new_run(self):
        self.last_methods_called = []
        self.last_methods_instances = []
        self.is_running = True
        self.hooking_method = None
        self.hook_done = False
        self.stuck = False
        self.last_methods_call_time = None

    def our_notation(self, frida_method, is_instance=False):
        def find_between(s, first, last):
            try:
                start = s.index(first) + len(first)
                end = s.index(last, start)
                return s[start:end]
            except ValueError:
                return ""

        def convert_arg(arg):
            if arg == '':
                return ""

            is_array = ''
            if arg.startswith('['):
                is_array = '[]'
                arg = arg[1:]
            if arg in R_TYPE_DESCRIPTOR:
                return "{}{}".format(R_TYPE_DESCRIPTOR[arg], is_array)
            else:
                arg = arg.strip(';')
                if arg.startswith('L'):
                    arg = arg[1:]
                # assume class
                return "{}{}".format(arg, is_array)
        if type(frida_method) in (str, unicode):
            cls = find_between(frida_method, *self.frida_separators['cls'])
            mname = find_between(frida_method, *self.frida_separators['met'])
            params = find_between(frida_method, *self.frida_separators['par']).split(
                self.frida_separators['new_par']
            )
            ret = find_between(frida_method, *self.frida_separators['ret'])
        elif type(frida_method) == list:
            cls = frida_method[0]
            mname = frida_method[1]
            params = frida_method[2]
            ret = frida_method[3]
        else:
            log.error("Wtf, frida_method type is " + str(type(frida_method)))
            return [None, None, [], None]

        mname = '<init>' if mname == '$init' else mname
        if params == ['']:
            params = []

        if not is_instance:
            # convert types
            params = map(convert_arg, params)
            ret = convert_arg(ret)
        else:
            new_params = []
            for par in params:
                if self.frida_separators['class_field'][0] in str(par):
                    fields = {}
                    fields_info = [x for x in par.split(self.frida_separators['new_class_field']) if x]
                    for info in fields_info:
                        fname = find_between(info, *self.frida_separators['field_name'])
                        fval = find_between(info, *self.frida_separators['field_value'])
                        fields[fname] = fval
                    new_params.append(fields)
                else:
                    new_params.append(par)
            params = list(new_params)
        return [cls, mname, params, ret]

    def frida_it(self, m):
        def convert_arg(arg):
            if arg.endswith('[]'):
                if arg[:-2] in TYPE_DESCRIPTOR:
                    return '[' + TYPE_DESCRIPTOR[arg[:-2]]
                else:
                    return '[L' + arg[:-2] + ';'
            return arg

        # methods
        t = list(m)
        t[1] = '$init' if m[1] == '<init>' else m[1]
        # params
        t[2] = map(convert_arg, m[2])
        # ret
        t[3] = convert_arg(m[3])
        return t

    def hook_methods_sync(self, to_hook, get_instances=False):
        debug_counter = 0
        if to_hook is None:
            to_hook = []

        frida_names = [self.frida_it(l) for l in to_hook]
        log.info("trying to hook {} methods".format(len(frida_names)))
        self.spawn_apk_in_device(frida_names, get_instances=get_instances)

        while not self.hook_done:
            last_hooking_function = self.hooking_method
            time.sleep(WAIT_FOR_HOOK_SEC)

            debug_counter += 1
            if debug_counter > 120:
                log.debug("Hook got stuck?")

            if last_hooking_function == self.hooking_method and \
                    to_hook != []:
                log.debug("Hooking got stuck!")
                self.kill_app(is_stuck=True)
                raise ApkStuck("STUCK")

    def is_repetition_done(self):
        return self.method_repeat_done

    def prepare_new_fuzzing(self, cls, m, n, nargs, fast_fuzz=False, single_call_fuzz=False, curr_call=0):
        self.method_repeat_done = False
        self.method_tot_repeatitions = n
        self.method_n_repeatitions = 0
        self.script.exports.preparenewfuzz(cls, m, n, nargs, fast_fuzz, single_call_fuzz, curr_call)

    def get_n_repeated(self):
        return self.method_n_repeatitions

    def stop_args_fuzz(self):
        self.script.exports.stopargsfuzz()

    def next_param_list(self):
        self.script.exports.nextparamlist()

    def next_fields_list(self):
        self.script.exports.nextfieldslist()

    def fuzz_prepare_done(self, shuffle=False):
        self.script.exports.fuzzpreparedone(shuffle)

    def get_util_calls(self, m):
        return self.script.exports.getutilscalls(m)

    def clear_methods_called_cache(self):
        self.last_methods_called = []
        self.last_methods_instances = []
        self.last_methods_call_time = []
        self.script.exports.resetlastmethods()
        self.script.exports.resetlastinstances()

    def create_obj(self, type_obj, prim, *kargs, **kwargs):
        s = self.script
        fname = 'add' + type_obj.lower().replace('.', '')

        # first check if an ad-hoc contructor is provided
        if fname in s.exports.adhocconstructors():
            f = getattr(s.exports, fname)
        else:
            f = s.exports.addprimitivetype if prim else s.exports.addobj
        f(type_obj, *kargs, **kwargs)

    def modify_class_field(self, type_obj, prim, *kargs, **kwargs):
        s = self.script
        fname = 'addfieldvar' + type_obj.lower().replace('.', '')

        if fname in s.exports.adhocconstructors():
            f = getattr(s.exports, fname)
        else:
            f = s.exports.addfieldvalprim if prim else s.exports.addfieldvalobj
        f(type_obj, *kargs, **kwargs)

    def set_unfuzzed_obj(self):
        self.script.exports.addunfuzzedobj()

    def set_arg_simple_obj(self):
        self.script.exports.addsimpleobj()

    def get_vals_returned(self):
        return None

    def sanitize_hooks(self, hooks):
        return [l for l in hooks if l not in self.ignore_methods and
                l[0] not in self.ignore_classes]

    def should_rehook(self, to_hook):
        new_methods = self.sanitize_hooks(to_hook)
        k = str(new_methods)
        success = 0 if k not in self.good_hooks else self.good_hooks[k]
        return success <= SUCC_THRESH_HOOK

    def register_good_hook(self, to_hook):
        if str(to_hook) not in self.good_hooks:
            self.good_hooks[str(to_hook)] = 0
        self.good_hooks[str(to_hook)] += 1

    def recursive_hook(self, to_hook, fast_hook=False, get_instances=False):
        while True:
            try:
                self.setup_new_run()
                to_hook = self.sanitize_hooks(to_hook)
                self.hook_methods_sync(to_hook, get_instances=get_instances)
                FridaHooker.wait_for_spawn()
                self.register_good_hook(to_hook)
                return True

            except ApkStuck:

                #
                # Handle apk stuck
                #
                log.warning("Apk got stuck. ")
                
                if len(self.last_methods_errored) > 0:
                    self.ignore_methods += self.last_methods_errored
                    self.last_methods_errored = []

                elif not self.force_hook:
                    log.warning("Removing last hook and trying again")
                    self.ignore_methods.append(self.hooking_method)

            except ApkExploded:

                #
                # Handle apk exploded
                #

                log.error("APK exploded")

                if len(self.last_methods_errored) > 0:
                    self.ignore_methods += self.last_methods_errored
                    self.last_methods_errored = []

                elif not self.force_hook:
                        log.info("Handling it")
                        if fast_hook:
                            if self.last_methods_called:
                                log.warning("Removing hook from the last called method")
                                self.ignore_methods.append(self.last_methods_called[-1])

                            else:
                                log.warning("Removing last hook")
                                self.ignore_methods.append(self.hooking_method)

                        else:
                            if len(to_hook) == 0:
                                log.error("Seriously? Can't hook no functions? "
                                        "WTF. Try again!")
                            elif len(to_hook) <= GRANULARITY_IGN_HOOK:
                                self.ignore_methods += to_hook

                                if not self.should_rehook([]):
                                    # we don't want to hook the empty set
                                    # over and over.
                                    return False
                            else:
                                # first half
                                new_to_hook = to_hook[:len(to_hook) / 2]
                                if self.should_rehook(new_to_hook):
                                    self.recursive_hook(new_to_hook, get_instances=get_instances)

                                # second half
                                new_to_hook = to_hook[len(to_hook) / 2:]
                                if self.should_rehook(new_to_hook):
                                    self.recursive_hook(new_to_hook, get_instances=get_instances)

            except frida.TimedOutError:

                #
                # Frida timeout
                #

                log.info("Frida spawning timeout triggered")
            except Exception as e:
                log.error("whoops, something unexpected happened: " + str(e))

    def pickle_results(self):
        log.info("Frida results pickle saved in " + self.dump_result_path)
        to_dump = {'good_hooks': self.good_hooks,
                   'skip_classes': self.ignore_classes,
                   'skip_methods': self.ignore_methods}
        pickle.dump(to_dump, open(self.dump_result_path, 'w'))

    def hook(self, to_hook, pickle_results=False, fast_hook=False, get_instances=False):
        if type(to_hook) != list:
            raise TypeError('hook: argument type should be a list')

        self.recursive_hook(to_hook, fast_hook=fast_hook, get_instances=get_instances)
        log.info("Hooking done")

        if pickle_results:
            self.pickle_results()

    def hook_leaves(self, lifter=None, fast_hook=False, get_instances=False):
        if not self.ignore_methods:
            log.info("Hooking all the leaves with no exceptions "
                     "might take quite some time. Take a break, "
                     "and be patient.")
        if not self.nf:
            self.nf = NodeFilter(self.config, lifter=lifter)

        leaf_names = [l for l in self.nf.nodes]
        self.hook(to_hook=leaf_names, pickle_results=True, fast_hook=fast_hook, get_instances=get_instances)

    def clean_state(self):
        try:
            self.terminate()
        except ApkKilled as ak:
            pass

    def add_known_object(self, obj):
        self.script.exports.addknownobject(obj)

    def start(self, to_hook=None, lifter=None, leaves=False, force_hook=False, fast_hook=False, ignore=None, get_instances=False):

        self.clean_state()
        self.force_hook = force_hook
        if ignore is not None and type(ignore) == list:
            self.ignore_methods += ignore

        if leaves:
            return self.hook_leaves(lifter=lifter, fast_hook=fast_hook, get_instances=get_instances)
        if to_hook is None:
            to_hook = []
        self.hook(to_hook, fast_hook=fast_hook, get_instances=get_instances)


def parse_options():
    parser = OptionParser(option_class=MultipleOption,
                          description="Run an app, and hooks some functions",
                          usage="usage: %prog [options] [binaries] -j config_file",
                          version="%prog 2.0")
    parser.add_option("-m", "--method",
                      action="extend", metavar='CATEGORIES',
                      help="method to hook")
    parser.add_option("-c", "--cls",
                      action="extend", metavar='CATEGORIES',
                      help="class to hook (it hooks all methods in the class)", )
    parser.add_option("-j", "--json",
                      action="extend", metavar='CATEGORIES',
                      help="app config file", )
    parser.add_option("-v", "--values",
                      action="store_true", help="show values" )

    (options, args) = parser.parse_args()

    if not options.json:
        parser.print_help()
        return None, None, None, None
    return options.json[0], options.method, options.cls, options.values


if __name__ == '__main__':
    import sys
    from pysoot.lifter import Lifter

    config_path, methods, clss, show_vals = parse_options()
    if config_path is None:
        sys.exit(0)

    with open(config_path) as fp:
        config = json.load(fp)

    lifter = None
    leaves = True

    if methods:
        leaves = False
        methods = map(lambda x: ast.literal_eval(x.replace('\\', '')), methods)

    elif clss:
        leaves = False
        lifter = Lifter(config['apk_path'], input_format="apk",
                        android_sdk=config['android_sdk_platforms'])
        classes = [c for c in lifter.classes.values()
                   if c.name in clss]
        methods = [[clx.name, m.name, list(m.params), m.ret]
                   for clx in classes for m in clx.methods]

    fh = FridaHooker(config)
    fh.start(leaves=leaves, lifter=lifter, to_hook=methods, fast_hook=True)  # , force_hook=True)
    last = []

    print "Now you can interact with the app and see which hooked methods are called."
    print "Press ctrl+c to exit."
    while True:
        if fh.last_methods_called:
            for m in fh.last_methods_called if not show_vals else fh.last_methods_instances:
                print str(m)
            fh.clear_methods_called_cache()
