from androguard.misc import AnalyzeAPK

import time
import json
import math
import logging
from os.path import dirname, abspath
import sys
import os

sys.path.append(dirname(dirname(abspath(__file__))))

from pysoot.lifter import Lifter
from androguard.core.bytecodes.dvm_types import TYPE_DESCRIPTOR
import turi
from turi.utils import walk_all_statements
from turi.common import x_ref
from turi.statements import is_invoke
import pysoot
import pickle
from enum import Enum

LIFTER_PICKLE = "/tmp/lifter.pk"
logging.basicConfig()
log = logging.getLogger("SweetSpotFinder")
log.setLevel(logging.DEBUG)

DK_MATH_OPS = ['neg-', 'add-', 'sub-', 'mul-', 'div-']
DK_BIT_OPS = ['and-', 'or-', 'xor-', 'shl-', 'shr-', 'ushr-']
DK_OPS = DK_BIT_OPS
OPS_THRESHOLD = 5 #FIXME: find some meaningful value
BRANCHING_INS = ['if-', 'goto']
BLACKLIST = ['android.support']
BLACKLIST_M = ['event', 'error', 'header', 'dns', 'info', 'ping', 'failure']
WHITELIST = ['socket', 'http']


class Dep(Enum):
    RET = 0
    ARG = 1

def dex_to_name(n):
    if n == "":
        return ""
    is_array = ""
    # FIXME what about n-dimensional arrays?
    if n.startswith("["):
        is_array = "[]"
        n = n[1:]
    if n in TYPE_DESCRIPTOR:
        return "{}{}".format(TYPE_DESCRIPTOR[n], is_array)
    else:
        # assume class
        n = n.replace('/', '.').strip().strip(';')
        if n.startswith('L'):
            n = n[1:]
        return "{}{}".format(n, is_array)

class SweetSpotFinder:
    def __init__(self, apk_path):
        sdk_path = os.path.join(os.path.expanduser("~"), "Android/Sdk/platforms/")
        if not os.path.exists(sdk_path):
            print("cannot run test_apk_loading since there is no Android SDK folder")
            sys.exit(1)

        lifter = Lifter(path_apk, input_format="apk", android_sdk=sdk_path)

        self.p = turi.Project(apk_path, input_format='apk', android_sdk=sdk_path, lifter=lifter)

        self.apk_path = apk_path
        _, _, self.dx = AnalyzeAPK(apk_path)
        self.call_graph = self.dx.get_call_graph()

        self.avg_math_ops = self.get_avg_math_ops()
        self.sweet_spots = []
        self.sweet_objs = []
        self.reran_proc = None
        self.has_dominant = False
        self.entropies = {}

    @property
    def spots(self):
        return self.sweet_spots

    @staticmethod
    def make_method_hashable(m):
        m[2] = tuple(m[2])
        return tuple(m)

    @staticmethod
    def get_invoked_method(stmt):
        if hasattr(stmt, 'invoke_expr'):
            invoke_expr = stmt.invoke_expr
        else:
            invoke_expr = stmt.right_op
        return [invoke_expr.class_name, invoke_expr.method_name, invoke_expr.method_params]

    def get_callers(self, method):
        try:
            callgraph = self.p.callgraph()
            key_method = method[:3]
            if type(key_method[2]) == list:
                key_method[2] = tuple(key_method[2])
            if type(key_method) == list:
                key_method = tuple(key_method)
            if key_method not in self.p.methods:
                log.error("cant find method")
                return []
            m = self.p.methods[key_method]
            return [[p.class_name, p.name, list(p.params), p.ret] for p in callgraph.prev(m)]
        except:
            return []

    def _has_sweet_spots_dominants_core(self, method):
        callers = self.get_callers(method)
        if not self.has_dominant:
            return
        if not callers:
            self.has_dominant = False
        for c in callers:
            if c in self.sweet_spots:
                continue
            self._has_sweet_spots_dominants_core(c)

    def has_sweet_spots_dominant(self, method):
        self.has_dominant = True
        try:
            self._has_sweet_spots_dominants_core(method)
            return self.has_dominant
        except:
            return False

    def get_constructor_method(self, method):
        try:
            clx = self.p.classes[method[0]]
            cons = [m for m in clx.methods if m.name == '<init>'][0]
            return [cons.class_name, cons.name, list(cons.params), cons.ret]
        except:
            log.error("Cant find constructor")
            return []

    def get_function_setter(self, inp, filter_method):
        filter_method = self.get_pysoot_method(filter_method)
        if filter_method is None:
            return []

        bslicer = self.p.backwardslicer()

        try:
            bslicer.slice(inp)
        except Exception as e:
            log.error(str(e))
            return [], [], False

        bbs = [x for x in bslicer.affected_blocks if self.p.blocks_to_methods[x].name == filter_method.name]

        tainted_vars = bslicer.tainted_in_method(filter_method)

        dd_f = []
        dep_caller = False

        # find those tainted variables that are tainted and returned by a function call
        # consider only the blocks within the caller function
        class_method = self.p.classes[filter_method.class_name]
        invokes = [s[2] for s in walk_all_statements({filter_method.class_name: class_method}, [filter_method])
                   if is_invoke(s[2])]
        for c in invokes:
            if hasattr(c, 'left_op') and hasattr(c.left_op, 'name') and c.left_op.name in tainted_vars:
                tmp_m = [c.right_op.class_name, c.right_op.method_name, list(c.right_op.method_params), c.left_op.type]
                if tmp_m not in dd_f and tmp_m[0] in self.p.classes:
                    dd_f.append(tmp_m)

        # consider also the caller if its parameters are tainted.
        # get function parameters
        first_block = filter_method.blocks[0]
        for st in first_block.statements:
            if hasattr(st, 'right_op') and type(st.right_op) == pysoot.sootir.soot_value.SootParamRef:
                if hasattr(st, 'left_op') and hasattr(st.left_op, 'name') and st.left_op.name in tainted_vars:
                    dep_caller = True
                    break
        return bbs, dd_f, dep_caller

    def get_pysoot_method(self, method):
        if type(method) == pysoot.sootir.soot_method.SootMethod:
            return method
        try:
            cls = self.p.classes[method[0]]
            pysoot_method = [x for x in cls.methods if x.name == method[1] and x.params == tuple(method[2])]
            return pysoot_method[0]
        except:
            log.error("Class not found in class hierarchy")
            return None

    def get_method_invokes(self, caller, callee=None):
        caller = self.get_pysoot_method(caller)
        if caller is None:
            return []

        cls = self.p.classes[caller.class_name]
        invokes = [s[2] for s in walk_all_statements({caller.class_name: cls}, [caller]) if is_invoke(s[2])]

        if callee:
            callee = self.get_pysoot_method(callee)
            if callee is None:
                return []

            all_invokes = list(invokes)
            invokes = []
            for s in all_invokes:
                tmp = SweetSpotFinder.get_invoked_method(s)
                if callee.class_name == tmp[0] and callee.name == tmp[1] and callee.params == tmp[2]:
                    invokes.append(s)

        return invokes

    def get_invoke_args(self, stmt):
        if hasattr(stmt, 'invoke_expr'):
            arg_vars = [a for a in stmt.invoke_expr.args if hasattr(a, 'name')]
        elif hasattr(stmt, 'right_op'):
            arg_vars = [a for a in stmt.right_op.args if hasattr(a, 'name')]
        else:
            import ipdb;
            ipdb.set_trace()
            arg_vars = []
        return arg_vars

    def get_data_dependent_functions(self, caller, callee):
        callee_invokes = self.get_method_invokes(caller, callee)

        dep_callers = []
        ddf_s = []

        for i in callee_invokes:
            arg_vars = self.get_invoke_args(i)
            for v in arg_vars:
                v_name = v.name
                inp = {'class_name': caller[0],
                       'method_name': caller[1],
                       'method_params': caller[2],
                       'type': 'method_var',
                       'var_name': v_name}
                tainted_blocks, dd_f, dep_caller = self.get_function_setter(inp, caller)

                ddf_s += dd_f
                if dep_caller:
                    dep_callers = [caller]

                # if the variable is not set withtin the function, let's check whether is a class
                # variable
                #FIXME: move this among the class fields?
                if not dd_f and not dep_caller:
                    current_var = v
                    v_ass = None
                    try:
                        while v_ass is None:
                            current_var = [s.right_op for b in tainted_blocks for s in b.statements if
                                     type(s) == pysoot.sootir.soot_statement.AssignStmt and hasattr(s.left_op, 'name') and
                                     s.left_op.name == current_var.name]
                            current_var = current_var[0]
                            if hasattr(current_var, 'field'):
                                v_ass = current_var
                    except:
                        log.error("Could not find variable assignment")
                        continue

                    refs = x_ref([v_ass.field[1], v_ass.field[0]], 'class_var', self.p)
                    for write_op in [r for r in refs if r.type == 'write']:
                        m = self.p.blocks_to_methods[self.p.stmts_to_blocks[write_op.stmt]]
                        inp = {'class_name': m.class_name,
                               'method_name': m.name,
                               'method_params': list(m.params),
                               'obj_class_name': v_ass.field[1],
                               'obj_field_name': v_ass.field[0],
                               'type': 'object_field'}
                        _, tmp_dd, dep_caller = self.get_function_setter(inp, m)
                        if dep_caller:
                            dep_callers.append([m.class_name, m.name, list(m.params), m.ret])
                        dd_f += tmp_dd

        return ddf_s, dep_callers

    @staticmethod
    def get_shannon_entropy(val):
        val_bytes = [x for x in val.split('0x') if x]
        if len(val_bytes) <= 1:
            # value is not an array of bytes
            return 0

        total = len(val_bytes)
        byte_counts = bytearray.fromhex(''.join(val_bytes))
        entropy = 0

        for count in byte_counts:
            if count == 0:
                continue
            p = 1.0 * count / total
            entropy -= p * math.log(p, 256)

        return abs(entropy)

    def should_consider_caller(self, caller, callee):
        # returns true if the caller itself adds entropy
        m = self.get_method_node(caller)

        if not m or not hasattr(m, 'get_instructions'):
            return False

        try:
            end = [i for i in m.get_instructions() if 'invoke' in i.get_name() and callee[0].replace('.', '/') in
                   str(i.get_operands()) and callee[1] in str(i.get_operands())][0]
        except Exception as e:
            end = None

        ops = self.get_math_operation_stat(m, end)

        # FIXME: check for strings and byte as type params?
        if ((ops - self.avg_math_ops) / float(self.avg_math_ops)) > OPS_THRESHOLD:
            return True

        return False


    def get_math_operation_stat(self, node, end=None):
        if not hasattr(node, 'get_instructions'):
            return 0
        insns = [i for i in node.get_instructions()]
        tot_ops = 0
        tot_ops_in_loops = 0

        # FIXME: ugly AF.
        math_ops_in_loop = 0
        if_found = False

        for ins in insns:
            if end is not None and ins == end:
                break
            name_op = ins.get_name()
            if 'if-' in name_op:
                if_found = True
                math_ops_in_loop = 0

            if 'goto' in name_op and if_found:
                tot_ops_in_loops += math_ops_in_loop
                math_ops_in_loop = 0
                if_found = False

            math_ops = len([op for op in DK_OPS if op in name_op])
            tot_ops += math_ops

            if if_found:
                math_ops_in_loop += math_ops

        return tot_ops * 0.3 + tot_ops_in_loops * 0.7

    def get_method_node(self, method):
        # getting node in androguard call-graph is not so user-friendly
        cls = method[0].replace('.', '/')
        mname = method[1]
        params = method[2]

        candidates = [n for n in self.call_graph.nodes.keys() if cls in n.class_name and mname in n.name]

        if len(candidates) == 1:
            return candidates[0]

        # easy case: no params
        if not params:
            to_ret = [c for c in candidates if hasattr(c, 'get_information') and 'params' not in c.get_information()]
            if to_ret:
                return to_ret[0]

        for c in candidates:
            try:
                info = c.get_information()
            except:
                continue

            if 'params' not in info:
                continue
            m_params = [p[1] for p in info['params']]
            # FIXME: only use the triple!
            if m_params == params or ';'.join(params) in c.get_triple()[2]:
                return c

        return None

    def get_avg_math_ops(self):
        tot_ops = 0
        counter = 0

        for node in self.call_graph.nodes:
            ops = self.get_math_operation_stat(node)
            counter += 1
            if ops:
                tot_ops += ops
        return tot_ops / float(counter) if counter != 0 else 0

    def filter_sweet_spots_ret(self, funs):
        if not funs:
            return []

        to_return = []
        for f in funs:
            m = self.get_method_node(f)
            if not m or not hasattr(m, 'get_instructions'):
                continue

            ops = self.get_math_operation_stat(m)
            # FIXME: check for strings and byte as type params?
            if ((ops - self.avg_math_ops) / float(self.avg_math_ops)) > OPS_THRESHOLD:
                to_return.append(f)

        return to_return

    def update_caller_worklist(self, fun, worklist):
        callers = self.get_callers(fun)
        added = False

        for c in callers:
            c = SweetSpotFinder.make_method_hashable(c)
            if c not in worklist:
                worklist[c] = []
            worklist[c].append(fun)
            added = True
        return added

    def get_obj_class_returned(self, method):
        pysoot_method = self.get_pysoot_method(method)
        if pysoot_method is None:
            return []
        stmts = [s for b in pysoot_method.blocks for s in b.statements]
        this_asn = [s for s in stmts if type(s) == pysoot.sootir.soot_statement.IdentityStmt and
                    s.right_op.type == method[0]]
        if not this_asn:
            return []

        this_var_name = this_asn[0].left_op.name
        var_rets = [s for b in pysoot_method.blocks for s in b.statements
                    if type(s) == pysoot.sootir.soot_statement.ReturnStmt
                    and hasattr(s, 'value') and hasattr(s.value, 'name')]
        fslicer = self.p.forwardslicer()
        fields = []
        for r in var_rets:
            inp = {'class_name': method[0],
                   'method_name': method[1],
                   'method_params': method[2],
                   'type': 'method_var',
                   'var_name': this_var_name}
            fslicer.slice(inp)

            if r.value.name in fslicer.tainted_in_method(pysoot_method):
                affected_stmts = [s for b in fslicer.affected_blocks for s in b.statements]
                # get class objects being referenced
                # FIXME: this is a copy of the one in find_sweet_spots_class_fields
                # create a function instead. I am too tired now to do it :(
                fields += [s.right_op.field for s in affected_stmts if hasattr(s, 'right_op') and hasattr(s.right_op, 'base')
                            and s.right_op.base.name == this_var_name
                            and type(s.right_op) == pysoot.sootir.soot_value.SootInstanceFieldRef]

                # right_op
                fields += [s.left_op.field for s in affected_stmts if hasattr(s, 'left_op') and hasattr(s.left_op, 'base')
                             and s.left_op.base.name == this_var_name
                             and type(s.left_op) == pysoot.sootir.soot_value.SootInstanceFieldRef]
        return fields

    def get_referred_obj_fields(self, sender):
        pysoot_sender = self.get_pysoot_method(sender)
        stmts = [s for b in pysoot_sender.blocks for s in b.statements]
        this_asn = [s for s in stmts if type(s) == pysoot.sootir.soot_statement.IdentityStmt and
                    s.right_op.type == sender[0]]
        if not this_asn:
            return []
        this_var_name = this_asn[0].left_op.name

        # get class objects being referenced
        # left_op
        fields = [s.right_op.field for s in stmts if hasattr(s, 'right_op') and hasattr(s.right_op, 'base')
                  and s.right_op.base.name == this_var_name
                  and type(s.right_op) == pysoot.sootir.soot_value.SootInstanceFieldRef]

        # right_op
        fields += [s.left_op.field for s in stmts if hasattr(s, 'left_op') and hasattr(s.left_op, 'base')
                   and s.left_op.base.name == this_var_name
                   and type(s.left_op) == pysoot.sootir.soot_value.SootInstanceFieldRef]

        # returned from calls
        calls_stms = [s for s in stmts if type(s) == pysoot.sootir.soot_statement.AssignStmt
                      and type(s.right_op) == pysoot.sootir.soot_expr.SootVirtualInvokeExpr
                      and hasattr(s.left_op, 'name') and hasattr(s.right_op, 'base')
                      and s.right_op.base.name == this_var_name]

        new_fields = map(lambda x: self.get_obj_class_returned(SweetSpotFinder.get_invoked_method(x)), calls_stms)
        try:
            fields += [x for y in new_fields for x in y]
        except:
            fields =[]

        return list(set(fields))

    def iterative_sweet_spot_finder(self, method):
        callers = self.get_callers(method)
        worklist = {}
        candidate_sweet_spots = []

        for c in callers:
            c = SweetSpotFinder.make_method_hashable(c)
            worklist[c] = [method]

        while worklist:
            caller = worklist.keys()[0]
            caller_worklist = worklist.pop(caller)

            while caller_worklist:
                callee = caller_worklist[0]
                caller_worklist = caller_worklist[1:]

                # get data dependant functions and filter them according their
                # added entropy to the input data
                dd_funs, dependent_from_callers = self.get_data_dependent_functions(caller, callee)
                new_caller_sweet_spots = self.filter_sweet_spots_ret(dd_funs)

                # if the callee uses data passed to the caller, we consider the caller as
                # a candidate sweet_spot as well
                if dependent_from_callers:
                    for dependent_from_caller in dependent_from_callers:
                        if self.should_consider_caller(dependent_from_caller, callee):
                            self.update_caller_worklist(dependent_from_caller, worklist)
                            candidate_sweet_spots += [dependent_from_caller]

                # if the method is already a candidate sweetspost and it has no other
                # candidate sweet spots dominating it, we add it in the sweet spot list
                if not new_caller_sweet_spots and callee in candidate_sweet_spots:
                    if callee not in self.sweet_spots and len(callee[2]) != 0:
                        self.sweet_spots.append(callee)
                    candidate_sweet_spots.remove(callee)

                # save new sweet spots
                candidate_sweet_spots += new_caller_sweet_spots
                caller_worklist += new_caller_sweet_spots

    def find_sweet_spots_args(self, sender):
        if not sender[2] or sender[2] == ['']:
            sender = self.get_constructor_method(sender)
            self.sweet_spots.append(sender)
        self.iterative_sweet_spot_finder(sender)

    def find_sweet_spots_class_fields(self, sender):
        fields = self.get_referred_obj_fields(sender)
        for field in fields:
            self.sweet_objs.append(field)
            refs = x_ref([field[1], field[0]], 'class_var', self.p)
            for write_op in [r for r in refs if r.type == 'write']:
                m = self.p.blocks_to_methods[self.p.stmts_to_blocks[write_op.stmt]]
                inp = {'class_name': m.class_name,
                       'method_name': m.name,
                       'method_params': list(m.params),
                       'obj_class_name': field[1],
                       'obj_field_name': field[0],
                       'type': 'object_field'}
                _, tmp_dd, dep_caller = self.get_function_setter(inp, m)
                self.sweet_spots += tmp_dd
                if dep_caller:
                    method_our_notation = [m.class_name, m.name, list(m.params), m.ret]
                    for caller in self.get_callers(method_our_notation):
                        self.iterative_sweet_spot_finder(caller)

    def find_sweet_spots(self, sender):
        self.sweet_spots = []
        self.find_sweet_spots_args(sender)
        self.find_sweet_spots_class_fields(sender)
        return self.sweet_spots, self.sweet_objs

    def clean_ss(self):
        # ugly AF, but for this submission gotta go like this
        for i in range(len(self.sweet_spots)):
            if type(self.sweet_spots[i]) == list:
                self.sweet_spots[i] = (self.sweet_spots[i][0], self.sweet_spots[i][1], tuple(self.sweet_spots[i][2]), self.sweet_spots[i][3])
        self.sweet_spots = list(set(self.sweet_spots))
        for i in range(len(self.sweet_spots)):
            self.sweet_spots[i] = [self.sweet_spots[i][0], self.sweet_spots[i][1], list(self.sweet_spots[i][2]), self.sweet_spots[i][3]]

        new_ss = []

        for m in self.sweet_spots:
            callers = self.get_callers(m)
            callers = [c for c in callers if c[2]]
            if any([c for c in callers if c not in self.sweet_spots]) or not callers:
                new_ss.append(m)

        self.sweet_spots = list(new_ss)
        new_ss = []

        for ss in self.sweet_spots:
            if not self.has_sweet_spots_dominant(ss):
                new_ss.append(ss)
        self.sweet_spots = list(new_ss)

    def find_senders(self):
        ret = []
        for cls, clx in self.p.classes.items():
            if any([x for x in BLACKLIST if x in cls]):
                continue

            for m in clx.methods:
                if any([x for x in BLACKLIST_M if x in m.name.lower()]):
                    continue
                if m.name.lower().startswith('is') or m.name.lower().startswith('has'):
                    continue

                if 'send' in m.name.lower():
                    ret.append((cls, m))
        sends = []
        for r in ret:
            if any([x for x in WHITELIST if x in r[1].name.lower() or x in r[0].lower()]):
                sends.append(r)

        return ret if not sends else sends

    def start_core(self, sender):
        self.find_sweet_spots(sender)
        self.clean_ss()
        return self.sweet_spots, self.sweet_objs

    def start(self):
        tot_start_time = time.time()
        methods = self.find_senders()
        res = []
        so = []

        for cls, m in methods:
            fp = open('/tmp/sweet_spots_' + path_apk.split('/')[-1], 'a')
            fp.write("****************************************************************************")
            fp.write(str(m))
            fp.write('\n')
            self.sweet_spots, self.sweet_objs = [], []
            our_notation_m = [m.class_name, m.name, list(m.params), m.ret]
            try:
                last_res, last_so = self.start_core(our_notation_m)
            except Exception as e:
                fp.write("ERRORED")
                continue

            res += last_res
            so += last_so
            fp.write(str(last_res))
            fp.write('\n')
            fp.write(str(last_so))
            fp.write('\n\n')
            fp.close()

        tot_elapsed_time = time.time() - tot_start_time
        print("Time (s): " + str(tot_elapsed_time))
        return res, so


if __name__ == "__main__":
    try:
        path_apk = sys.argv[1]
    except:
        print("Usage: {} [APK path]".format(sys.argv[0]))
        sys.exit(1)

    ssf = SweetSpotFinder(path_apk)
    res, so = ssf.start()

    print(res)
    print(so)
    print("Done")
