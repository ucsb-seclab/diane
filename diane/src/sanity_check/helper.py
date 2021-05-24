import os
import sys
import os
import traceback

# ANSI color codes
class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Define error codes
class Error:
    ENV_VAR_NOT_SET = 1
    FILE_NOT_FOUND = 2

def check_env_var(env_var):
    # Check if environment variable is set
    try:
        env_val = os.environ[env_var]
        return env_val
    except KeyError as ke:
        print(Color.FAIL + "[*] Set and export " + env_var + " environment variable" + Color.ENDC)
        exit(Error.ENV_VAR_NOT_SET)

def show_block(project, state):
    print('-' * 40 + '\n' + str(state.addr) + '\n' + '-' * 40)
    block = project.factory.block(state.addr)
    soot_block = block.soot
    for statement in soot_block.statements:
        print(statement)

def is_constant(stmt):
    # e.g. SootStringConstant, SootNullConstant, SootIntConstant
    if 'Constant' in str(type(stmt)):
        return True
    else:
        return False

def debug():
    # Ref: https://stackoverflow.com/a/1278740
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    print(exc_type, fname, exc_tb.tb_lineno)
    print(traceback.format_exc())
