import time
import json
import math
import logging
from os.path import dirname, abspath
import sys
sys.path.append(dirname(dirname(abspath(__file__))))

from frida_hooker.frida_hooker import FridaHooker, ApkExploded, ApkKilled, ApkStuck, FridaRunner
from pysoot.lifter import Lifter
from node_filter.node_filter import NodeFilter
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

@FridaRunner
class SweetSpotFinder:
    def __init__(self, config, hooker=None, node_lifter=None):
        apk_path = config['apk_path']
        self.apk_path = apk_path
        self.config = config
        self.hooker = hooker if hooker else FridaHooker(config)

        self.sweet_spots = []
        self.sweet_objs = []
        self.lifter = None
        self.reran_proc = None
        self.p = None
        self.nf = node_lifter
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

    def should_consider_caller(self, caller, callee, ran_fun):
        # returns true if the caller itself adds entropy

        def flat_and_filter_arg(_args):
            _return_list = []
            for _arg_list in _args:
                for _arg in _arg_list:
                    if type(_arg) == dict:
                        _return_list += [x for x in _arg.values()]
                    else:
                        _return_list.append(_arg)

            return _return_list

        if not caller or not callee:
            return []

        to_hook = [caller, callee]
        while True:
            try:
                self.hooker.start(to_hook, force_hook=True, get_instances=True)
                self.set_known_obj_for_funs(to_hook)
                self.reran_proc = ran_fun()
                caller_args = []
                callee_args = []

                while True:
                    # analyzed called methods
                    # while executing the apk
                    if self.reran_proc.poll() is not None:
                        break

                    methods_instances = list(self.hooker.methods_instances)
                    self.hooker.clear_methods_called_cache()

                    for info in methods_instances:
                        cls_i = info[0]
                        m_i = info[1]
                        val_params = info[2]
                        if caller[0] == cls_i and m_i == caller[1] and len(val_params) == len(caller[2]):
                            caller_args.append(val_params)
                        if cls_i == callee[0] and m_i == callee[1] and len(val_params) == len(callee[2]):
                            callee_args.append(val_params)
            except ApkExploded as e:
                log.error(str(e))
                continue
            break

        flat_caller_args = flat_and_filter_arg(caller_args)
        flat_callee_args = flat_and_filter_arg(callee_args)

        # consider strings
        str_caller_args = [x for x in flat_caller_args if x not in ('null', 'UNHANDLED') and not x.isdigit()]
        str_callee_args = [x for x in flat_callee_args if x not in ('null', 'UNHANDLED') and not x.isdigit()]

        if any([clr_a in clee_a for clr_a in str_caller_args for clee_a in str_callee_args]):
            return True

        # get entropy arguments
        max_entropy_caller = 0
        if flat_caller_args:
            max_entropy_caller = max(map(self.get_shannon_entropy, flat_caller_args))
        max_entropy_callee = 0
        if flat_callee_args:
            max_entropy_callee = max(map(self.get_shannon_entropy, flat_callee_args))

        if str(caller) not in self.entropies:
            self.entropies[str(caller)] = []
        self.entropies[str(caller)].append(max_entropy_caller)
        if str(callee) not in self.entropies:
            self.entropies[str(callee)] = []
        self.entropies[str(callee)].append(max_entropy_callee)

        if max_entropy_caller < max_entropy_callee:
            return True

        return False

    def set_known_obj_for_funs(self, methods):
        params = list(set([tuple(x[2]) for x in methods]))
        params = [x for y in params for x in y]
        for par in params:
            if par in self.p.classes:
                clx = self.p.classes[par]
                fields = []
                for f_name, f_info in clx.fields.items():
                    if f_name in [m.name for m in clx.methods]:
                        # frida internal naming
                        f_name = '_' + f_name
                    fields.append([f_info[1], f_name])
                self.hooker.add_known_object({par: fields})

    def get_obj_bigget_entropy_prim(self, obj):
        def find_between(s, first, last):
            try:
                start = s.index(first) + len(first)
                end = s.index(last, start)
                return s[start:end]
            except ValueError:
                return ""

        fields = obj.split(self.hooker.frida_separators['new_class_field'])
        obj_entropy = None
        candidate = None
        for field in fields:
            tmp_val = find_between(field, self.hooker.frida_separators['field_value'][0],
                                   self.hooker.frida_separators['field_value'][1])
            tmp_e = SweetSpotFinder.get_shannon_entropy(tmp_val)
            if obj_entropy is None or tmp_e > obj_entropy:
                candidate = tmp_val
                obj_entropy = tmp_e
        return candidate

    def filter_sweet_spots_ret(self, funs, ran_fun, *args, **kwargs):
        if not funs:
            return []

        while True:
            # apk might explode due to frida shenanigans,
            # this loop assures that if it happens we try again
            to_return = []

            try:
                self.hooker.start(funs, force_hook=True, get_instances=True)
                self.set_known_obj_for_funs(funs)
                self.reran_proc = ran_fun()
                
                while True:
                    # analyzed called methods
                    # while executing the apk
                    if self.reran_proc.poll() is not None:
                        break

                    methods_called = list(self.hooker.methods_called)
                    methods_instances = list(self.hooker.methods_instances)
                    self.hooker.clear_methods_called_cache()

                    for info in methods_instances:
                        cls_i = info[0]
                        m_i = info[1]
                        val_params = info[2]
                        ret = info[3]

                        if ret == 'UNHANDLED':
                            continue

                        if 'CLS' in str(ret):
                            ret = self.get_obj_bigget_entropy_prim(ret)
                            if ret is None:
                                continue

                        # calculate entropy of params and return value
                        ret_entropy = SweetSpotFinder.get_shannon_entropy(ret)

                        # fixme: consider arguments type too
                        method = [x for x in methods_called if x[0] == cls_i and x[1] == m_i]
                        if method:
                            method = method[0]
                        else:
                            log.warning("Found instance, but not the method declaration.. check me.")
                            continue

                        if method in to_return:
                            continue

                        # transform parameters in a list of values
                        # objets too
                        cons_params = []
                        for p in val_params:
                            if p != 'UNHANDLED':
                                if type(p) == dict:
                                    cons_params += p.values()
                                else:
                                    cons_params.append(p)

                        # WHAT's THIS?
                        # if len(cons_params) == 0 and len(val_params) != 0:
                        #     self.sweet_spots.append(method)

                        max_param_entropy = 0
                        if cons_params:
                            max_param_entropy = max(map(SweetSpotFinder.get_shannon_entropy, cons_params))

                        # consider the function if the return entropy
                        # is greater than the maximum input entropy
                        # or the retuend value wraps the input value
                        type_params = method[2]
                        if str(method) not in self.entropies:
                            self.entropies[str(method)] = []
                        self.entropies[str(method)].append([max_param_entropy, ret_entropy])

                        if ret_entropy > 2 * max_param_entropy or \
                                any([p for t, p in zip(type_params, val_params)
                                     if t in ('java.lang.String', 'byte[]') and
                                        p in ret and len(p) <= len(ret)]):
                            to_return.append(method)
            except ApkExploded as e:
                log.error(str(e))
                continue
            break
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

    def iterative_sweet_spot_finder(self, method, ran_fun):
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
                try:
                    new_caller_sweet_spots = self.filter_sweet_spots_ret(dd_funs, ran_fun)
                except ApkExploded as ex:
                    log.error("Apk exploded: " + str(ex))
                    log.error("Skipping this one")
                    continue

                # if the callee uses data passed to the caller, we consider the caller as
                # a candidate sweet_spot as well
                if dependent_from_callers:
                    for dependent_from_caller in dependent_from_callers:
                        if self.should_consider_caller(dependent_from_caller, callee, ran_fun):
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

    def find_sweet_spots_args(self, sender, ran_fun):
        if not sender[2] or sender[2] == ['']:
            sender = self.get_constructor_method(sender)
            self.sweet_spots.append(sender)
        self.iterative_sweet_spot_finder(sender, ran_fun)

    def find_sweet_spots_class_fields(self, sender, ran_fun):
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
                #if tmp_dd:
                #    import ipdb; ipdb.set_trace()
                self.sweet_spots += tmp_dd
                if dep_caller:
                    method_our_notation = [m.class_name, m.name, list(m.params), m.ret]
                    for caller in self.get_callers(method_our_notation):
                        self.iterative_sweet_spot_finder(caller, ran_fun)

    def find_sweet_spots(self, sender, ran_fun):
        self.sweet_spots = []
        self.find_sweet_spots_args(sender, ran_fun)
        self.find_sweet_spots_class_fields(sender, ran_fun)
        return self.sweet_spots, self.sweet_objs

    def clean_ss(self):
        # ugly AF, but for this submission gotta go like this
        for i in xrange(len(self.sweet_spots)):
            if type(self.sweet_spots[i]) == list:
                self.sweet_spots[i] = (self.sweet_spots[i][0], self.sweet_spots[i][1], tuple(self.sweet_spots[i][2]), self.sweet_spots[i][3])
        self.sweet_spots = list(set(self.sweet_spots))
        for i in xrange(len(self.sweet_spots)):
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

    def start(self, sender, ran_fun=lambda *args: None, lifter=None):
        if not self.lifter:
            if lifter is not None:
                self.lifter = lifter
            if self.lifter is None:
                log.debug("Building Lifter")
                self.lifter = Lifter(self.config['apk_path'], input_format="apk",
                                android_sdk=self.config['android_sdk_platforms'])
                log.debug("Lifter pickled in " + LIFTER_PICKLE)
        self.p = turi.Project(self.apk_path, input_format='apk',
                              android_sdk=self.config['android_sdk_platforms'], lifter=self.lifter)
        if not self.nf:
            self.nf = NodeFilter(self.config, lifter=self.lifter)

        self.find_sweet_spots(sender, ran_fun)
        self.clean_ss()
        return self.sweet_spots, self.sweet_objs

if __name__ == "__main__":
    from ui.core import ADBDriver

    try:
        config_path = sys.argv[1]
    except:
        print "Usage: {} [config path]".format(sys.argv[0])
        sys.exit(1)

    with open(config_path) as fp:
        config = json.load(fp)

    tot_start_time = time.time()
    log_path = '/tmp/sweet_spots_log.' + config['proc_name']
    fp = open(log_path, 'w')

    methods = config['send_functions']
    reran_record_path = config["reran_record_path"]

    start_time = time.time()
    adbd = ADBDriver(f_path=reran_record_path, device_id=config['device_id'])
    ssf = SweetSpotFinder(config)
    res = []
    so = []
    FAILED = []
    for m in methods:
        fp = open('/tmp/sweet_spots_' + config['proc_name'], 'a')
        fp.write("****************************************************************************")
        fp.write(str(m))
        fp.write('\n')

        try:
            last_res, last_so = ssf.start(m, ran_fun=adbd.replay_ui_async)
        except Exception as e:
            fp.write("ERRORED");
            continue

        res += last_res
        so += last_so
        fp.write(str(last_res))
        fp.write('\n')
        fp.write(str(last_so))
        fp.write('\n\n')
        fp.close()

    tot_elapsed_time = time.time() - tot_start_time
    print "Time (s): " + str(tot_elapsed_time)
    print res
    print so
    import ipdb; ipdb.set_trace()
    print "Done"
