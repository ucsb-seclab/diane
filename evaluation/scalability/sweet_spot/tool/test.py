import os
import angr
from angr.procedures.java import JavaSimProcedure
from angr.engines.soot.values import SimSootValue_ThisRef
from archinfo.arch_soot import SootArgument, SootMethodDescriptor


file_dir = os.path.dirname(os.path.realpath(__file__))


result = None
BLACKLIST = ['android.support']
BLACKLIST_M = ['event', 'error', 'header', 'dns', 'info', 'ping', 'failure']
WHITELIST = ['socket', 'http']

class Dummy_String_valueOf(JavaSimProcedure):
    __provides__ = (
        ("java.lang.String", "valueOf(int)"),
    )

    def run(self, intv): # pylint: disable=W0221
        global result
        result = intv
        return ""

def find_senders(p):
    ret = []
    for cls, clx in p.loader.main_object._classes.items():

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


def test_androidnative1():
    sdk_path = os.path.join(os.path.expanduser("~"), "Android/Sdk/platforms/")
    if not os.path.exists(sdk_path):
        print("cannot run test_apk_loading since there is no Android SDK folder")
        return

    apk_location = '/media/badnack/Documents/Code/zeppolina/evaluation/scalability/apks/abdo.free.remote.samsung.tv.apk'
    loading_opts = {'android_sdk': sdk_path,
                    'entry_point': 'agency.rain.android.alexa.ui.activity.SplashActivity.onCreate',
                    'entry_point_params': ('android.os.Bundle', ),
                    'supported_jni_archs': ['x86']}
    project = angr.Project(apk_location, main_opts=loading_opts)

    sends = find_senders(project)
    import ipdb;ipdb.set_trace()


    project.hook(SootMethodDescriptor(class_name="java.lang.String", name="valueOf", params=('int',)).address(), Dummy_String_valueOf())

    blank_state = project.factory.blank_state()
    a1 = SimSootValue_ThisRef.new_object(blank_state, 'com.angr.androidnative1.MainActivity')
    a2 = SimSootValue_ThisRef.new_object(blank_state, 'android.os.Bundle', symbolic = True)
    args = [SootArgument(arg, arg.type) for arg in [a1, a2]]
    entry = project.factory.entry_state(args = args)
    simgr = project.factory.simgr(entry)

    simgr.run()

    int_result = simgr.deadended[0].solver.eval(result)
    assert int_result == 221


def test():
    test_androidnative1()


if __name__ == "__main__":
    import logging
    logging.getLogger("angr.engines.soot.engine").setLevel("DEBUG")
    test()
