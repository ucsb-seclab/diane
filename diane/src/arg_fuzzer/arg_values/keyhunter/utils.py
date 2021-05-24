import string
import binascii
import archinfo
import struct
import fnmatch
import os


MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-/_'
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + "%,.;+=_)(*&^%$#@!~`|<>{}[]"


def get_string(p, mem_addr, extended=False):
    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)

    # get string representation at mem_addr
    cnt = p.loader.memory.read_bytes(mem_addr, STR_LEN)
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''

    # check whether the mem_addr might contain an address
    try:
        endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
        tmp_addr = struct.unpack(
            endianess, ''.join(p.loader.memory.read_bytes(mem_addr, p.arch.bytes))
        )[0]
        if bin_bounds[0] <= tmp_addr <= bin_bounds[1]:
            cnt = p.loader.memory.read_bytes(tmp_addr, STR_LEN)
            string_2 = get_mem_string(cnt)
    except:
        pass

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    return candidate if len(candidate) >= MIN_STR_LEN else ''


def get_mem_string(mem_bytes, extended=False):
    tmp = ''
    chars = EXTENDED_ALLOWED_CHARS if extended else ALLOWED_CHARS

    for c in mem_bytes:

        if c not in chars:
            break
        tmp += c

    return tmp


# archinfo.ArchARMEL.registers, archinfo.ArchARMEL.register_names,
# archinfo.ArchARMEL.argument_registers, archinfo.ArchARMEL.argument_register_positions are empty
# r = archinfo.ArchARMEL.register_list[0]; r.name; r.vex_offset work
argument_regs = {
    'ARMEL': [8, 12, 16, 20]
}


# FIXME: so far we only consider arguments passed through registers
def get_ord_arguments_call(p, b_addr):
    """
        Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
        so to infer the artity of the function:
        Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

        :param b: basic block address
        :return:
        """

    set_params = []
    b = p.factory.block(b_addr)
    for reg_off in ordered_agument_regs[p.arch.name]:
        put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put' and s.offset == reg_off]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        set_params.append(put_stmt)

    return set_params

def is_call(x):
    if hasattr(x, 'vex'):
        return x.vex.jumpkind == 'Ijk_Call'
    if x.irsb:
        return x.irsb.jumpkind == 'Ijk_Call'
    return False


def get_addrs_string(p, s):
    b = p.loader.main_object.binary
    str_info = get_bin_strings(b)
    offs = [x[1] for x in str_info for y in s if y == x[0]]
    return [p.loader.main_object.min_addr + off for off in offs]


def get_all_strings_addr_len(p):
    b = p.loader.main_object.binary
    str_info = get_bin_strings(b)
    bin_base = p.loader.main_object.min_addr
    return [(bin_base + str_addr_len[1], str_addr_len[2]) for str_addr_len in str_info]


def get_addrs_similar_string(p, s):
    b = p.loader.main_object.binary
    str_info = get_bin_strings(b)
    tmp = [x for x in str_info if s in x[0]]

    # filter the strings to allow only the most similar ones
    info = []
    for t in tmp:
        sub_str = t[0].replace(s, '')
        non_aplha_num = list(set([x for x in sub_str if not x.isalnum()]))
        if len(non_aplha_num) == 0 or (len(non_aplha_num) == 1 and non_aplha_num[0] in ('_', '-')):
            info.append(t)

    return [(s, p.loader.main_object.min_addr + off) for s, off in info]


def get_bin_strings(filename):
    with open(filename, "rb") as f:
        results = []
        last_off = None
        off = 0
        str = ""

        for c in f.read():
            if c in string.printable and c != '\n':
                last_off = off if not last_off else last_off
                str += c
            else:
                if str and len(str) > 1:
                    results.append((str, last_off, len(str)))
                last_off = None
                str = ""
            off += 1

    return results



def get_indirect_str_refs(p, cfg, str_addrs):
    ret = []

    # FIXME: (DEPRECATED?)
    # code reference
    code_refs = [s for s in cfg.memory_data.items() if 'code reference' in str(s)]
    for a, ref in code_refs:
        addr = ref.address
        cnt = p.loader.memory.read_bytes(addr, p.arch.bytes)

        if 'LE' in p.arch.memory_endness:
            cnt = reversed(cnt)

        cnt = binascii.hexlify(bytearray(cnt))
        if int(cnt, 16) in str_addrs:
            print "[DEBUG]: code", hex(cnt)
            ret += [s for s in cfg.memory_data.items() if s[0] == addr]

    # pointers
    refs = [s for s in cfg.memory_data.items() if s[0] in str_addrs]
    print "[DEBUG]: ", refs
    for ref in refs:
        cnt = ref[1]
        if hasattr(cnt, 'pointer_addr'):
            pt = cnt.pointer_addr
            print "[DEBUG]: ", "pointer1", hex(pt)
            ret += [s for s in cfg.memory_data.items() if s[0] == pt]

    refs = [s for s in cfg.memory_data.items() if s[0] in str_addrs]
    for ref in refs:
        cnt = ref[1]
        if hasattr(cnt, 'pointer_addr'):
            pt = cnt.pointer_addr
            print "[DEBUG]: ", "pointer2", hex(pt)
            # we collect both references
            ret += [(s.address, s) for k, s in cfg.insn_addr_to_memory_data.items() if s.address == pt]
            ret += [(ind_addr, s) for k, s in cfg.insn_addr_to_memory_data.items() if s.address == pt for ind_addr in str_addrs]
    import ipdb; ipdb.set_trace()
    print "[DEBUG]: ", ret
    return ret


def are_parameters_in_registers(p):
    return hasattr(p.arch, 'argument_registers')


def get_args_call(p, no):
    """
    Gets the arguments of function call

    :param no: CFG Accurate node of the call site
    :return:
    """

    ins_args = get_ord_arguments_call(p, no.addr)
    if not ins_args:
        ins_args = get_any_arguments_call(p, no.addr)

    vals = {}

    for state in no.final_states:
        vals[state] = []
        for ins_arg in ins_args:
            # get the values of the arguments
            if hasattr(ins_arg.data, 'tmp'):
                val = state.scratch.temps[ins_arg.data.tmp]
                val = val.args[0] if type(val.args[0]) in (int, long) else None
                if val:
                    vals[state].append((ins_arg.offset, val))
            elif type(ins_arg.data) == pyvex.expr.Const:
                assert len(ins_arg.data.constants) == 1, "Too many constants assigned. Fix me"
                vals[state].append((ins_arg.offset, ins_arg.data.constants[0].value))
            else:
                print("Cant' get the value for function call")
                import ipdb
                ipdb.set_trace()
    return vals


def get_reg_used(p, cfg, addr, idx, s_addr):
    """
    Finds whether and which register is used to store a string address.

    :param addr: basic block address
    :param idx: statement idx of the statement referencing a string
    :param s: string referenced in the statement pointed by idx
    :return: the register name the string is assigned to
    """

    if not are_parameters_in_registers(p):
        raise Exception("Parameters are not in registers")

    block = p.factory.block(addr)
    stmt = block.vex.statements[idx]
    no = cfg.get_any_node(addr)

    # sometimes strings are reference indirectly through an address contained in the
    # text section
    endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
    s_addr_2 = None
    try:
        s_addr_2 = struct.unpack(endianess, ''.join(p.loader.memory.read_bytes(s_addr, p.arch.bytes)))[0]
    except:
        pass

    if hasattr(stmt, 'offset'):
        return p.arch.register_names[stmt.offset]

    # damn! The string is not assigned directly to a register, but to a tmp.
    # It means we have to find out what register is used to pass the string
    # to the function call
    # save the function manager, CFGAccurate will change it
    fm = p.kb.functions

    cfga = p.analyses.CFGAccurate(starts=(no.function_address,), keep_state=True, call_depth=0)
    no = cfga.get_any_node(addr)
    if not no:
        cfga = p.analyses.CFGAccurate(starts=(addr,), keep_state=True, call_depth=0)
        no = cfga.get_any_node(addr)
        if not no:
            return None

    args = get_args_call(p, no)

    # restore the old function manager
    p.kb.functions = fm

    for _, vals in args.iteritems():
        for o, v in vals:
            if v in (s_addr, s_addr_2):
                return p.arch.register_names[o]
    return None


def get_files_from_dir(dir, extension):
    files = []
    for root, dirnames, filenames in os.walk(dir):
        for filename in fnmatch.filter(filenames, extension):
            files.append(os.path.join(root, filename))
    return files