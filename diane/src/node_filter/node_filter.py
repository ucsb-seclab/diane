#TODO: add also methods containing functions that share messages/signals. io.reactivex.FlowableEmitter
#FIXME: this class needs refactory and consistence
import os
import pickle
from pysoot.lifter import Lifter
import itertools

import logging

logging.basicConfig()
log = logging.getLogger("NodeFilter")
log.setLevel(logging.DEBUG)


NET_PACKAGES = ['java.net.', 'javax.net.', 'android.net.', 'android.webkit.', 'org.apache.']#, 'java.io.printstream', 'java.io.outputstream']
BLT_PACKAGES = ['android.bluetooth.']
CLASSES_TO_IGNORE = ['proxy']


class NodeFilter:
    def __init__(self, config, lifter=None, lazy_execution=False, reload=False):
        self.methods_black_list = []
        self.should_not_contain_method = config['bad_functions']
        self.apk_path = config['apk_path']
        self.android_sdk = config['android_sdk_platforms']
        self.proc_name = config['proc_name']
        self.lifter = lifter
        self.bnodes = []
        if 'leaf_pickle' not in config:
            self.leaf_pickle = None
        else:
            self.leaf_pickle = config['leaf_pickle']
        self.filter_reasons = {}

        if not lazy_execution:
            self.start(reload=reload)

    def setup_lifter(self):
        # pysoot
        self.lifter = Lifter(self.apk_path, input_format="apk", android_sdk=self.android_sdk)

    def get_filter_reason(self, method):
        key = method if type(method[2]) == tuple else (method[0], method[1], tuple(method[2]))
        try:
            return self.filter_reasons[key]
        except:
            return []

    def get_hierarchy(self, cls):
        hierarchy = []
        try:
            clx = self.lifter.classes[cls]
            current_class = clx
            hierarchy.append(clx)

            while True:
                current_class = self.lifter.classes[current_class.super_class]
                hierarchy.append(current_class)
        except KeyError as ke:
            return hierarchy

    def dispatch_invoke(self, bcls, mname, params):
        h = self.get_hierarchy(bcls)
        for clx in h:
            for m in clx.methods:
                if m.name == mname and m.params == params:
                    return clx, m
        return None, None

    def get_methods(self, caller_class, caller_method, stmt):
        # invoke params
        fld = 'invoke_expr' if hasattr(stmt, 'invoke_expr') else 'right_op'
        callee_clx = getattr(stmt, fld)
        callee_m = getattr(stmt, fld)
        callee_cls = callee_clx.class_name
        callee_mname = callee_m.method_name
        callee_params = getattr(stmt, fld).method_params

        # filter on bad guys (some hooking tools, like Frida, don't handle some
        # functions if hooked
        if any([callee_cls == c and callee_mname == m for c, m in self.should_not_contain_method]):
            self.methods_black_list.append([caller_class.name, caller_method.name])
            return None, None, None

        # filter on package name
        is_net = any([n for n in NET_PACKAGES if callee_cls.lower().startswith(n)])
        is_blt = any([n for n in BLT_PACKAGES if callee_cls.lower().startswith(n)])

        # if is_net or is_blt:
        if is_blt:
            # gotta save strings. Pickle/unpickle won't work with soot :(
            to_save = [callee_cls, callee_mname, callee_params]
            self.filter_reasons[(caller_class.name, caller_method.name, caller_method.params)] = to_save
            return caller_class, caller_method, caller_method.params, caller_method.ret

        # get definition
        clx, method = self.dispatch_invoke(callee_cls, callee_mname, callee_params)
        if method and 'NATIVE' in method.attrs:
            # gotta save strings. Pickle/unpickle won't work with soot :(
            to_save = [clx.name, method.name, method.params]
            self.filter_reasons[(clx.name, method.name, method.params)] = to_save
            return clx, method, method.params, method.ret
        return None, None, None

    def is_invoke(self, stmt):
        if hasattr(stmt, 'invoke_expr'):
            return True
        if hasattr(stmt, 'right_op') and 'invoke' in str(type(stmt.right_op)).lower():
            return True
        return False

    def _get_nodes_core(self):
        nodes = []
        for cls, clx in self.lifter.classes.items():
            if any([c in cls for c in CLASSES_TO_IGNORE or 'INTERFACE' in clx.attrs]):
                continue
            for method in clx.methods:
                st_invoked = [s for b in method.blocks for s in b.statements if self.is_invoke(s)]
                methods = [self.get_methods(clx, method, s) for s in st_invoked]
                nodes += [[m[0].name, m[1].name, list(m[2]), m[3]] for m in methods if None not in m]

        # we gotta do this at the end because methods can be inherited
        self.bnodes = [n for n in nodes if n not in self.methods_black_list]
        # remove duplicates
        self.bnodes.sort()
        self.bnodes = list(k for k, _ in itertools.groupby(self.bnodes))

    def start(self, reload=False):
        log.info("Getting APK border nodes")
        if not reload and self.leaf_pickle and os.path.isfile(self.leaf_pickle):
            internal_struct = pickle.load(open(self.leaf_pickle))
            self.bnodes = internal_struct[0]
            self.filter_reasons = internal_struct[1]
        else:
            if not self.lifter:
                self.setup_lifter()
            self._get_nodes_core()
            pickle_name = '/tmp/leaves_' + self.proc_name
            dump_struct = [self.bnodes, self.filter_reasons]
            pickle.dump(dump_struct, open(pickle_name, "wb"), protocol=pickle.HIGHEST_PROTOCOL)
            log.info("APK leaves pickled in " + pickle_name)

    @property
    def nodes(self):
        return self.bnodes

if __name__ == '__main__':
    import json
    import sys

    try:
        config_path = sys.argv[1]
    except:
        print "Usage: {} [config path]".format(sys.argv[0])
        sys.exit(1)

    with open(config_path) as fp:
        config = json.load(fp)

    nf = NodeFilter(config, reload=True)
    print len(nf.nodes)
    import ipdb; ipdb.set_trace()
    print "Done"