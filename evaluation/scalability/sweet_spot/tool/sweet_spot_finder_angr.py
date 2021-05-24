from androguard.misc import AnalyzeAPK
import angr
import claripy
from angr.procedures.java import JavaSimProcedure
from angr.engines.soot.values import SimSootValue_ThisRef, SimSootValue_StringRef, SimSootValue_ParamRef, SimSootValue_ArrayRef
from angr.engines.soot.expressions import SimSootExpr_NewArray
from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor, SootAddressTerminator, SootArgument, SootNullConstant
import random

import string
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
import subprocess as sp
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
BLACKLIST_M = ['event', 'error', 'header', 'dns', 'info', 'ping', 'failure', 'handler']
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


def get_main_activity(apk):
    p = sp.Popen('aapt dump badging {} | grep launchable-activity'.format(apk), stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
    o, e = p.communicate()
    return o.decode('utf-8').split("name='")[1].split("'")[0] + '.onCreate'


def get_new_object_arg(obj_ref, is_this_ref=False):
    """
    Wraps an object reference so it can be passed as a method parameter

    :param obj_ref: the reference to the object we want to pass as parameter
    :type SimSootValue_ThisRef
    :param is_this_ref: indicates if the object reference is a 'this' reference or not
    :type bool
    :return SootArgument
    """
    return SootArgument(obj_ref, obj_ref.type, is_this_ref)


def get_new_primitive_arg(value, type_):
    """
    Wraps a primitive value so it so it can be used as a parameter for a method

    :param value: the value of the primitiva value.
    :type BV
    :param value: the type of the primitive value (int, boolean, etc.)
    :type str
    :return SootArgument
    """
    return SootArgument(value, type_)


class SweetSpotFinder:
    def __init__(self, apk_path):
        sdk_path = os.path.join(os.path.expanduser("~"), "Android/Sdk/platforms/")
        if not os.path.exists(sdk_path):
            print("cannot run test_apk_loading since there is no Android SDK folder")
            sys.exit(1)

        main_activity = get_main_activity(path_apk)
        loading_opts = {'android_sdk': sdk_path,
                        'entry_point': main_activity,
                        'entry_point_params': ('android.os.Bundle',)}

        self.angr_p = angr.Project(apk_path, main_opts=loading_opts)
        self.p = turi.Project(apk_path, input_format='apk', android_sdk=sdk_path, lifter=self.angr_p.loader.main_object.lifter)

        self.apk_path = apk_path

        self.sweet_spots = []
        self.sweet_objs = []
        self.reran_proc = None
        self.has_dominant = False
        self.entropies = {}
        self.trace = []
        self.loop_iters = {}
        self.max_loop_iters = 2

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

    def _discard_state(self, state):
        # if state.addr not in self.trace and state.addr.method.is_loaded:
        #     if not any([m in state.addr.method.fullname for m in self.followable_methods]):
        #         return True

        prev_addr = state.scratch.source
        loop_iters = self.loop_iters.get((prev_addr, state.addr), 0)
        if loop_iters >= self.max_loop_iters:
            return True

        return False

    def is_back_jump(self, src_addr, dst_addr):
        return src_addr.method == dst_addr.method and src_addr.block_idx >= dst_addr.block_idx

    def count_loop_iters(self, state):
        prev_addr = state.scratch.source
        if prev_addr is not None and self.is_back_jump(prev_addr, state.addr):
            # this is a back jump
            if (prev_addr, state.addr) not in self.loop_iters:
                self.loop_iters[(prev_addr, state.addr)] = 0
            self.loop_iters[(prev_addr, state.addr)] += 1

        elif state.addr.block_idx == 0:
            # TODO this might not be correct
            for k in self.loop_iters.keys():
                if k[0].method == state.addr.method:
                    self.loop_iters[k] = 0

    def get_soot_method(self, method):
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
            return self.p.methods[key_method]
        except:
            return None

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
        invokes = [s for s in walk_all_statements({filter_method.class_name: class_method}, [filter_method])
                   if is_invoke(s)]
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

    def get_class_inheritance(self, method):
        inh = []
        cls = method[0]
        while True:
            clx = self.p.classes[cls]
            if clx.super_class == 'java.lang.Object':
                break

            cls = clx.super_class
            inh.append(clx.super_class)
        return inh

    # FIXME: handle polymorphism. Use turi's Hierarchy to check if an invoke is a valid target
    def get_method_invokes(self, caller, callee=None):
        caller = self.get_pysoot_method(caller)
        if caller is None:
            return []

        cls = self.p.classes[caller.class_name]
        invokes = [s for s in walk_all_statements({caller.class_name: cls}, [caller]) if is_invoke(s)]

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
                try:
                    tainted_blocks, dd_f, dep_caller = self.get_function_setter(inp, caller)
                except:
                    continue

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

    def random_generator(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for x in range(size))

    def _get_initialized_method_args(self, state, soot_method):
        arg_vals = []
        args_target_method = []
        if 'STATIC' not in soot_method.attrs:
            this = SimSootValue_ThisRef.new_object(state, soot_method.class_name, init_object=False)
            args_target_method.append(get_new_object_arg(this, is_this_ref=True))

        for param in soot_method.params:
            if param in ['byte', 'char']:
                val = random.randint(0, 255)
                arg_vals.append(val)
                arg = get_new_primitive_arg(claripy.BVV(val, 8), param)
            elif param in ['short', 'int', 'boolean']:
                val = random.randint(0, 2**32)
                arg_vals.append(val)
                arg = get_new_primitive_arg(claripy.BVV(val, 32), param)
            elif param == 'long':
                val = random.randint(0, 2**64 - 1)
                arg_vals.append(val)
                arg = get_new_primitive_arg(claripy.BVV(val, 64), param)
            elif param == 'float':
                val = random.randint(0, 2**64 - 1)
                arg_vals.append(val)
                arg = get_new_primitive_arg(claripy.FPV(val, claripy.FSORT_FLOAT), param)
            elif param == 'double':
                val = random.randint(0, 2**64 - 1)
                arg_vals.append(val)
                arg = get_new_primitive_arg(claripy.FPV(val, claripy.FSORT_DOUBLE), param)

            elif param == 'java.lang.String':
                s = "A"*20
                arg_vals.append(s)
                sym_str = claripy.StringV(s, 20)
                str_ref = SimSootValue_StringRef.new_string(state, sym_str)
                arg = get_new_object_arg(str_ref)

            elif param.endswith('[][]'):
                raise NotImplementedError

            elif param.endswith('[]') and 'byte' in param:
                # TODO: symbolic size?
                base_ref = SimSootExpr_NewArray.new_array(state, param[:-2], claripy.BVV(20, 32))
                arg_vals.append([0x41]*20)
                for idx in range(20):
                    elem_ref = SimSootValue_ArrayRef(base_ref, idx)
                    state.memory.store(elem_ref, claripy.BVV(0x41, 8))
                arg = get_new_object_arg(base_ref)
            elif param.endswith('[]'):
                # TODO: symbolic size?
                array_ref = SimSootExpr_NewArray.new_array(state, param[:-2], claripy.BVV(2, 32))
                arg = get_new_object_arg(array_ref)
            else:
                obj_ref = SimSootValue_ThisRef.new_object(state, param, init_object=False)
                if param in self.p.classes:
                    clx = self.p.classes[param]
                    for info in clx.fields.items():
                        # initialize strings and byte[] with some random values
                        name = info[0]
                        t = info[1][1]
                        if 'String' in t:
                            s = "A"*20
                            arg_vals.append(s)
                            sym_str = claripy.StringV(s, 20)
                            str_ref = SimSootValue_StringRef.new_string(state, sym_str)
                            obj_ref.set_field(state, name, t, str_ref)

                        if 'byte[]' in t:
                            print ("Setting byte[]")
                            import ipdb;
                            ipdb.set_trace()
                            arg_vals.append([0x41] * 20)
                            base_ref = SimSootExpr_NewArray.new_array(state, 'byte', claripy.BVV(20, 32))
                            for idx in range(20):
                                elem_ref = SimSootValue_ArrayRef(base_ref, idx)
                                state.memory.store(elem_ref, claripy.BVV(0x41, 8))
                            obj_ref.set_field(state, name, t, base_ref)
                arg = get_new_object_arg(obj_ref)
            args_target_method.append(arg)

        return args_target_method, arg_vals

    def is_call_to_method(self, thing, method):
        inh = self.get_class_inheritance(method)
        inh.insert(0, method[0])

        if type(thing) == angr.sim_state.SimState:
            if thing.addr.method.class_name in inh and thing.addr.method.name == method[1] and \
                    thing.addr.method.params == tuple(method[2]) and thing.addr.block_idx == 0 and \
                    thing.addr.stmt_idx == 0:
                return True
        else:
            print("Implement ME!")
            import ipdb; ipdb.set_trace()

        return False

    def get_var_value(self, p, state):
        vars = []
        if hasattr(p, 'type'):
            # class
            if 'String' in p.type:
                vars = [state.memory.load(p, none_if_missing=True)]
            elif 'Array' in p.type:
                print("Got Array")
                import ipdb;
                ipdb.set_trace()
            elif p.type in self.p.classes:
                clx = self.p.classes[p.type]
                for info in clx.fields.items():
                    name = info[0]
                    t = info[1][1]
                    val = p.get_field(state, name, t)
                    if 'String' in t:
                        val = state.memory.load(val, none_if_missing=True)
                    if 'byte[]' in t:
                        print("Got byte[]")
                        import ipdb;
                        ipdb.set_trace()
                    else:
                        continue
                    vars.append(val)
        else:
            # symbolic var
            vars = [p]

        to_ret = []
        for v in vars:
            try:
                to_ret.append(state.solver.eval(v))
            except:
                pass
        return to_ret

    def get_param_values(self, preamble_state, n_params):
        pars = []
        try:
            for i in range(0, n_params):
                p = preamble_state.javavm_memory.load(SimSootValue_ParamRef(i, None), none_if_missing=True)

                if type(p) == SootNullConstant:
                    pars.append(0)
                    continue
                pars += self.get_var_value(p, preamble_state)

        except Exception as e:
            print("I FUCKED SMT UP")
            import ipdb; ipdb.set_trace()
        return pars

    def get_max_entropy(self, args):
        if not args:
            return 0

        to_hex = lambda x: "0x" + "".join([hex(ord(c))[2:].zfill(2) for c in x])
        max_entropy = 0
        for arg in args:
            if type(arg) == str:
                if not arg.startswith('0x'):
                    arg = to_hex(arg)
                entropy = self.get_shannon_entropy(arg)
                if entropy > max_entropy:
                    max_entropy = entropy
        return max_entropy

    def should_consider_caller_angr(self, caller, callee):
        # returns true if the caller itself adds entropy
        init_state, caller_args = self.setup_caller(caller)
        simgr = self.angr_p.factory.simgr(init_state)

        # symbolically explore
        keep_looping = True
        self.trace = []
        callee_args = []

        while keep_looping:
            if not simgr.complete() and simgr.active:
                to_be_deleted = []

                for state in simgr.active:
                    if self._discard_state(state):
                        to_be_deleted.append(state)
                    else:
                        self.count_loop_iters(state)

                    if self.is_call_to_method(state, callee):
                        callee_args = self.get_param_values(state, len(callee[2]))
                        keep_looping = False
                        break

                for state in to_be_deleted:
                    simgr.active.remove(state)
                try:
                    simgr.step()
                except:
                    break

            else:
                keep_looping = False

        # checks arguments
        if not caller_args or not callee_args:
            return False

        caller_entropy = self.get_max_entropy(caller_args)
        callee_entropy = self.get_max_entropy(callee_args)
        if caller_entropy > callee_entropy:
            return True

        # check strings
        str_caller_args = [c for c in caller_args if type(c) == str]
        str_callee_args = [c for c in callee_args if type(c) == str]
        if any([clr_a in clee_a for clr_a in str_caller_args for clee_a in str_callee_args]):
            return True

        return False

    def setup_caller(self, caller):
        # returns true if the caller itself adds entropy
        params = tuple(caller[2])
        method_name = caller[0] + '.' + caller[1]
        soot_method = self.angr_p.loader.main_object.get_soot_method(method_name, params=params)
        target_method = SootMethodDescriptor.from_soot_method(soot_method)
        base_state = self.angr_p.factory.blank_state()
        base_state.ip = SootAddressTerminator()
        args_target_method, caller_args = self._get_initialized_method_args(base_state, soot_method)

        return self.angr_p.factory.call_state(target_method.addr, *args_target_method, base_state=base_state), caller_args

    def get_returned_vals(self, state):
        stmts = self.angr_p.factory.block(state.addr).soot.statements
        idx = state.addr.stmt_idx - 1
        call = stmts[idx]
        name = call.left_op.name
        ret = state.javavm_memory.stack.load(name, none_if_missing=True)
        if type(ret) == SootNullConstant:
            return [0]
        return self.get_var_value(ret, state)

    def filter_sweet_spots_ret_angr(self, caller, funs):
        if not funs:
            return []

        to_ret = []
        for fun in funs:
            init_state, caller_args = self.setup_caller(caller)
            simgr = self.angr_p.factory.simgr(init_state)

            # symbolically explore
            keep_looping = True
            self.trace = []
            val_args = []
            fun_ret = []
            fun_entered = False

            while keep_looping:
                if not simgr.complete() and simgr.active:
                    to_be_deleted = []

                    for state in simgr.active:
                        if self._discard_state(state):
                            to_be_deleted.append(state)
                        else:
                            self.count_loop_iters(state)

                        if state.addr.method.class_name == caller[0] and state.addr.method.name == caller[1] and \
                                state.addr.method.params == tuple(caller[2]) and fun_entered:
                            fun_ret = self.get_returned_vals(state)
                            keep_looping = False
                            break

                        if self.is_call_to_method(state, fun):
                            fun_entered = True
                            val_args = self.get_param_values(state, len(fun[2]))

                    for state in to_be_deleted:
                        simgr.active.remove(state)
                    try:
                        simgr.step()
                    except:
                        break
                else:
                    keep_looping = False

            # checks here
            ret_entropy = self.get_max_entropy(fun_ret)
            param_entropy = self.get_max_entropy(val_args)
            if ret_entropy > 2 * param_entropy:
                to_ret.append(fun)
                continue

            str_ret_args = [c for c in fun_ret if type(c) == str]
            str_val_args = [c for c in val_args if type(c) == str]
            for p in str_val_args:
                for r in str_ret_args:
                    if p in r and len(p) <= len(r):
                        to_ret.append(fun)

        return to_ret

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
            caller = [x for x in worklist.keys()][0]
            caller_worklist = worklist.pop(caller)

            while caller_worklist:
                callee = caller_worklist[0]
                caller_worklist = caller_worklist[1:]

                # get data dependant functions and filter them according their
                # added entropy to the input data
                dd_funs, dependent_from_callers = self.get_data_dependent_functions(caller, callee)
                new_caller_sweet_spots = self.filter_sweet_spots_ret_angr(caller, dd_funs)

                # if the callee uses data passed to the caller, we consider the caller as
                # a candidate sweet_spot as well
                if dependent_from_callers:
                    for dependent_from_caller in dependent_from_callers:
                        if self.should_consider_caller_angr(dependent_from_caller, callee):
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
        #self.find_sweet_spots_class_fields(sender)
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

                if 'send' in m.name.lower() or 'httprequest' in m.name.lower():
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
