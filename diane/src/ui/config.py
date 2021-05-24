import sys
from os.path import dirname, abspath
sys.path.append(dirname(dirname(abspath(__file__))))

ADB_PATH = 'adb'
CMD_WAIT_TIME = 240
MONKEY_TIMEOUT = 600

############ RERAN config ############

DIR = dirname(dirname(abspath(__file__)))
REPLAY_PATH = DIR + '/ui/RERAN/replay'
REPLAY_REMOTE_PATH = '/data/replay'

TRANSLATOR_PATH = DIR + '/ui/RERAN/translate.jar'

############ Monkey config ############

THROTTLE = '1000'
PCT_SYSKEYS = '0'
PCT_ANYEVENT = '0'
IGNORE_CRASHES = True
IGNORE_TIMEOUTS = True
IGNORE_SECURITY_EXCEPTIONS = False
NUM_EVENTS = '2000'
SEED = '123456'
