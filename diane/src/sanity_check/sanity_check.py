import os
import logging
import IPython
import argparse
import json
import glob
import turi
import pickle
import pandas
import viewer
import collections
import multiprocessing
import pysoot
from helper import *

# logging.basicConfig()
# log = logging.getLogger('SanityChecker')
# log.setLevel(logging.DEBUG)

SEND_KEYWORDS = ['send', 'sethttp']
BLACKLIST = ['broadcast', 'accessibility', 'error', 'event']
ANDROID_WANTED_CLASS = ['java.net.', 'javax.net.', 'android.net.', 'android.webkit.', 'org.apache.']
Function = collections.namedtuple('Function', ['cls', 'name', 'args', 'ret'])

class SanityChecker:

    def __init__(self, apk, pickled, config, lift=False):
        self.project = None
        self.sanity_checks = {}         # A nested dictionary of [class][method][args][variable] = <count_sanity_checks_on_that_variable>
        self.send_functions = []
        self.condition_variables = {}   # Holds the list of vaiables involving a sanity check corresponding to a method
        self.apk_name = os.path.splitext(os.path.basename(apk))[0]
        self.apk_path = os.path.abspath(apk)
        self.base_dir = os.path.dirname(apk_path)

        ANDROID_SDK = check_env_var('ANDROID_SDK')
        PLATFORM_PATH = os.path.join(ANDROID_SDK, 'platforms')
        
        # Load apk in turi
        self.project = turi.project.Project(self.apk_path, input_format='apk', android_sdk=PLATFORM_PATH, pickled=pickled)

        # Is it a lifting+pickling run?
        if lift:
            return
        
        # Read the send functions from the app's config file
        if config:
            config_path = os.path.abspath(config)
            with open(config_path, 'r') as fp:
                self.send_functions = json.load(fp)['send_functions']
        else:
            self.find_send_message_functions()

    def find_send_message_functions(self):
        # Look for send message functions
        candidates = []
        for method_name, method in self.project.methods.items():
            if self.is_send(method_name):
                self.send_functions.append((method_name[0], method_name[1], method_name[2], method.ret))
                continue

            # Get function invokes
            invokes = [s.invoke_expr for b in method.blocks for s in b.statements if
                                type(s) == pysoot.sootir.soot_statement.InvokeStmt]
            invoke_methods = [(s.class_name, s.method_name, s.method_params) for s in invokes]

            for im in invoke_methods:
                if self.is_send(im) and im in self.project.methods:
                    invoke_soot_method = self.project.methods[im]
                    self.send_functions.append((im[0], im[1], im[2], invoke_soot_method.ret))
                    continue

        self.send_functions = list(set(self.send_functions))

        # Make it lists for later analyses
        self.send_functions = [[s[0], s[1], list(s[2]), s[3]] for s in self.send_functions]

        # Log the send message functions identified
        send_messages_path = os.path.join(self.base_dir, self.apk_name + '.send')
        with open(send_messages_path, 'w') as fp:
            for send_function in self.send_functions:
                fp.write(str(send_function) + '\n')

    def is_send(self, method_name):
        # first filter out blacklist names
        if any([k for k in BLACKLIST if k in method_name[1].lower()]):
            return False

        # filter out no interesting android classses
        if method_name[0].startswith('android') or method_name[0].startswith('java'):
            if not any([w for w in ANDROID_WANTED_CLASS if w in method_name]):
                return False

        # look for wanted keywords
        if any([k for k in SEND_KEYWORDS if k in method_name[1].lower()]):
            return True

        return False

    def create_slicer_input_structure(self, x_ref):
        """
            Prepare the dictionary containing the required
            information for the backward slicer. The dictionary
            contains the block, variable name and the index of the
            statement where the slicing will start from.
        """
        stmt = x_ref.stmt

        # Get the variable where the value is being assigned to
        # Applicable only for assignment and identity statement types
        if hasattr(stmt.left_op, 'name'):
            var_name = stmt.left_op.name
        else:
            var_name = None

        # Find the index of the statement within the block where it is located in
        block = self.project.stmts_to_blocks[stmt]
        for index, stmt_in_block in enumerate(block.statements):
            if stmt == stmt_in_block:
                break

        slicer_input = (block, var_name, index)
        return [slicer_input]

    def get_slicer_input_structure(self, x_ref, arg_idx):
        """
            Given the invocation (x-ref) of the send function
            and the argument (containing the buffer) we care about,
            prepare the dictionary containing the required
            information for the backward slicer. The dictionary
            contains the variable type, class name, method name,
            method arguments and the name of the variable we 
            want to start slicing from.
        """
        statement = x_ref.stmt
        
        # Get the invoke statement, if this is an assignment statement
        if turi.statements.is_assign(statement):
            statement = statement.right_op
        elif turi.statements.is_invoke(statement):
            statement = self.get_invoke_expression(statement)

        # Get the argument we care about
        try:
            argument = statement.args[arg_idx]
        except Exception as e:
            if DEBUG:
                IPython.embed()
            else:
                log.exception(e)
                pass
        if turi.statements.is_local_var(argument):
            input_type = 'method_var'
        elif turi.statements.is_instance_field_ref(argument):
            input_type = 'object_field'
        else:
            return None
        
        class_name = x_ref.cls.name
        method_name = x_ref.method.name
        method_params = x_ref.method.params
        var_name = argument.name

        slicer_input = {'type': input_type, 'class_name': class_name, 'method_name': method_name, 'method_params': method_params, 'var_name': var_name}
        return slicer_input

    def compute_variables_used_in_conditional_statements(self, method):
        """
            Given a method, returns the list of variables used
            in conditional statements. There are the variables
            which have some sort of sanity check(s) on them.
        """
        variables_used_in_conditional_statements = []

        # Populate the information lazily, on-demand
        condition_variables = self.condition_variables.get(method)
        if condition_variables is None:
            self.condition_variables[method] = []
            for block in method.blocks:
                for statement in block.statements:
                    if turi.statements.is_condition(statement):
                        try:
                            is_condition_variable_found = False
                            condition_expression = statement.condition
                            if 'null_type' in (statement.condition.value1.type, statement.condition.value2.type):
                                continue

                            # Check if the first value of the condition expression is a local
                            condition_variable = condition_expression.value1
                            if turi.statements.is_local_var(condition_variable):
                                condition_variable_name = condition_variable.name
                                self.condition_variables[method].append(condition_variable_name)
                                is_condition_variable_found = True

                            # Regardless of the first one is a local or not, let's check the
                            # second one to detect cases where two variables are being
                            # compared against each other
                            condition_variable = condition_expression.value2
                            if turi.statements.is_local_var(condition_variable):
                                condition_variable_name = condition_variable.name
                                self.condition_variables[method].append(condition_variable_name)
                                is_condition_variable_found = True

                            # ERROR: We should have at least one variable involved in any condition check
                            if not is_condition_variable_found:
                                raise NotImplementedError('No condition variable found')
                            
                        except Exception as e:
                            if DEBUG:
                                IPython.embed()
                            else:
                                log.exception(e)
                                pass

    def record_sanity_check_occurrences(self, method, variable):
        """
            Given a method and a variable used in that method, counts
            the number of _unique_ sanity checks on that variable.
        """
        class_name = method.class_name
        method_name = method.name
        method_args = str(method.params)

        if self.sanity_checks.get(class_name) is None:
            self.sanity_checks[class_name] = {}
        if self.sanity_checks[class_name].get(method_name) is None:
            self.sanity_checks[class_name][method_name] = {}
        if self.sanity_checks[class_name][method_name].get(method_args) is None:
            self.sanity_checks[class_name][method_name][method_args] = {}
        if self.sanity_checks[class_name][method_name][method_args].get(variable) is None:
            self.sanity_checks[class_name][method_name][method_args][variable] = 1
            return 1    # This variable is being sanity checked for the first time
        else:
            self.sanity_checks[class_name][method_name][method_args][variable] += 1
            return 0    # This variable has already been sanity checked in some other context

    def count_sanity_checks_on_a_variable(self, method, variables):
        """
            Given a method and a list of variables, counts how many
            of those variables are sanity checked inside the method.
        """
        # Get a list of variables in this method that are sanity checked
        self.compute_variables_used_in_conditional_statements(method)
        condition_variables = self.condition_variables[method]
        num_sanity_checks_on_variables = 0
        
        # Check if any variable has a condition check on it
        for variable in variables:
            if variable in condition_variables:
                num_sanity_checks_on_variables += self.record_sanity_check_occurrences(method, variable)

        return num_sanity_checks_on_variables

    def count_sanity_checks_on_send_function_args(self, send_function, args):
        """
            Given a send function and the argument(s) that matter, counts the
            number of sanity checks imposed directly or indirectly on them.
        """
        num_sanity_checks_on_a_function = 0   # Total number of sanity checks
        send_function_info = [send_function.cls, send_function.name, send_function.args]
        # Get the call-sites of the send function
        x_refs = turi.common.x_ref(send_function_info, 'method', self.project)
        log.info('XRefs found: %d, with %d arguments to be considered for the presence of sanity checks on' % (len(x_refs), len(args)))
        send_function_info = (send_function.cls, send_function.name, tuple(send_function.args))
        # Get the send function Soot object
        send_function_soot = self.project.methods[send_function_info]

        # Iterate over all the call-sites of the send function
        for x_ref in x_refs:
            log.info('XRef: ' + x_ref.cls.name + '.' + x_ref.method.name + ' [' + str(x_ref.stmt) + ']')

            # Take a slice on all the arguments we care about, one by one
            for arg in args:
                # slicer_input = self.create_slicer_input_structure(x_ref)
                slicer_input = self.get_slicer_input_structure(x_ref, arg)
                log.info('Slicer input on argument %d: %s' % (arg, str(slicer_input)))

                # Currently supported variable types: SootLocal, InstanceFieldRef
                if slicer_input:
                    slicer = self.project.backwardslicer()
                    # slicer.slice(None, slicer_input)
                    slicer.slice(slicer_input)

                    # Iterate over all blocks in the backward slice
                    for block in slicer._tainted.keys():
                        # Iterate over all methods reachable from this block
                        for method in slicer._tainted[block].keys():
                            # We are slicing backward from a call-site (x-ref) of
                            # the send function. It will pull in variables/blocks from the
                            # send function as well: backward_slicer:get_call_ret()
                            # Taint propagates inside the send function, too. However,
                            # for our purpose of sanity check, we'd like to avoid the
                            # send function itself. Because, fuzzing the parameters
                            # of the send function doesn't bypass those checks which
                            # are inside the function.
                            if method != send_function_soot:
                                variables = slicer._tainted[block][method]
                                num_sanity_checks_on_a_function += self.count_sanity_checks_on_a_variable(method, variables)

        return num_sanity_checks_on_a_function

    def get_send_function_arg_idx_that_contains_data_buffer(self, send_function):
        """
            Given a send function, try to figure out the argument that
            contains the data buffer to be sent over the network.
            Return the index of the respective argument.
        """
        # DiAne fuzzes all the primitive arguments (String, int, float)
        # of the send functions, as well as the primitive fields of a
        # complex object. For the purpose of this analysis, we just
        # consider the primitive arguments.
        buffer_args = []
        primitive_types = ['java.lang.String', 'int', 'float', 'boolean']

        for i, arg in enumerate(send_function.args):
            if any(arg == primitive_type for primitive_type in primitive_types):
                buffer_args.append(i)
        return buffer_args

    def count_sanity_checks(self):
        """
            Given a list of send functions, counts the total number
            of sanity checks imposed directly or indirectly on the
            argumemts(s) that contains the data buffer to be sent
            over the network.
        """
        log.info('Found %d send functions' % len(self.send_functions))
        num_sanity_checks_on_all_functions = 0
        for send_function in self.send_functions:
            try:
                function = Function(send_function[0], send_function[1], send_function[2], send_function[3])
                arg_idx = self.get_send_function_arg_idx_that_contains_data_buffer(function)
                log.info('Considering function: %s' % str(function))
                log.info('Send function argument indices: ' + str(arg_idx))
                if len(arg_idx) != 0:
                    num_sanity_checks_on_all_functions += self.count_sanity_checks_on_send_function_args(function, arg_idx)
            except Exception as e:
                if DEBUG:
                    IPython.embed()
                else:
                    log.exception(e)
                    pass
        return num_sanity_checks_on_all_functions

    def get_invoke_expression(self, statement):
        if 'invokeexpr' in str(type(statement)).lower():
            return statement
        elif hasattr(statement, 'invoke_expr'):
            return statement.invoke_expr
        elif hasattr(statement, 'right_op'):
            return self.get_invoke_expression(statement.right_op)
        return None

    def find_send_functions(self):
        """
            Find send functions based on heuristics
        """
        send_keywords = ['http', 'tcp', 'network', 'socket']
        methods_with_an_external_call = {}

        # Filter out methods with at least one call to external function
        for method_info in self.project.methods.keys():
            soot_method = self.project.methods[method_info]
            for block in soot_method.blocks:
                for statement in block.statements:
                    invoke_expression = self.get_invoke_expression(statement)
                    # Is an invoke expression?
                    if invoke_expression is not None:
                        method_args = tuple([arg.type for arg in invoke_expression.args])
                        method_info = tuple([invoke_expression.class_name, invoke_expression.method_name, method_args, invoke_expression.type])    # The tuple will be used as the method-key

                        # Is a call to an external method?
                        if self.project.methods.get(method_info) is None:
                            methods_with_an_external_call[method_info] = soot_method

        # Check is any of the send keywords present in
        # either method name, or arguments or return value
        # for method_info in self.project.methods.keys():
        for method_info in methods_with_an_external_call:
            method_class = method_info[0]
            method_name = method_info[1]
            method_args = method_info[2]
            # soot_method = self.project.methods[method_info]
            soot_method = methods_with_an_external_call[method_info]
            method_return = soot_method.ret

            for send_keyword in send_keywords:
                if (send_keyword in method_name.lower()) or any(send_keyword in method_arg.lower() for method_arg in method_args) or (send_keyword in method_return):
                    self.send_functions.append([method_class, method_name, list(method_args), method_return])

def run_analysis(apk, pickled=None, config=None, lift=False):
    """
        An unit of the analysis task that can be parallelized.
        It is fed to multiprocessing pool workers.
    """
    try:
        apk_name = os.path.basename(apk)
        log.info('Analyzing %s' % apk_name)
        sanity_checker = SanityChecker(apk, pickled, config, lift)
        log.info('SanityChecker instantiated: %s' % apk_name)

        # Is it a lifting+pickling run?        
        if lift:
            return

        if len(sanity_checker.send_functions) > 0:
            log.info('There are %d unique sanity checks on the data buffer argument(s) of the send functions in %s' % (sanity_checker.count_sanity_checks(), apk_name))

            # Log the sanity checks identified
            sanity_check_path = os.path.join(sanity_checker.base_dir, sanity_checker.apk_name + '.sanity')
            with open(sanity_check_path, 'w') as fp:
                fp.write(json.dumps(sanity_checker.sanity_checks, indent=4))

        log.info('Analysis finished on %s' % apk_name)
    except Exception as e:
        log.error('Failed to instantiate SanityChecker: %s => %s' % (apk_name, str(e)))
        if DEBUG:
            IPython.embed()
        else:
            log.exception(e)
            pass

def run_verify(pickled):
    """
        Verifies the sanity of a pickle dump.
    """
    try:
        log.info('Verifying %s' % os.path.basename(pickled))
        with open(pickled, 'rb') as fp:
            pickle.load(fp)
        log.info('Pickle dump is well-formed: %s' % pickled)
    except Exception as e:
        log.info('Pickle dump is malformed: %s' % pickled)
        os.remove(pickled)

def run_log_analysis(logdir):
    """
        Analyses the log files to extract the required numbers for the experiment
    """
    log_regex = os.path.join(logdir, '*.log')
    csv_path = os.path.join(logdir, 'sanity_checks.csv')
    results = {'App': [], 'Send Functions': [], 'Sanity Checks': []}

    for log_file in glob.glob(log_regex):
        apk = None
        is_finished = False
        num_send_functions = 0
        num_sanity_checks = 0
        is_instantiated = False

        with open(log_file, 'r') as fp:
            lines = fp.readlines()
            for log_line in lines[::-1]:
                if 'Analysis finished on' in log_line:
                    apk = log_line.split()[-1].strip()
                    is_finished = True
                if 'unique sanity checks' in log_line and is_finished:
                    num_sanity_checks = log_line.split()[6].strip()
                if 'Found' in log_line and 'send functions' in log_line:
                    num_send_functions = log_line.split()[5].strip()
                if 'SanityChecker instantiated' in log_line:
                    is_instantiated = True
                    break

            # Sanity check the log
            if not is_instantiated:
                log.error('Error processing %s => Analysis not instantiated' % apk)
            if not is_finished:
                log.error('Error processing %s => Analysis not finished' % log_file)
            else:
                results['App'].append(apk)
                results['Send Functions'].append(num_send_functions)
                results['Sanity Checks'].append(num_sanity_checks)
                # log.info('%s has %s send function(s) with %s unique sanity checks on its arguments' % (apk, num_send_functions, num_sanity_checks))

    # Display/write the result
    df = pandas.DataFrame(results)
    print(df.to_string(index=False))
    df.to_csv(csv_path, index=False)

def init_logging(filename):
    """
        Initializes the logger
    """
    global log
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    log_format_string = "[%(levelname)s] | %(name)-12s | %(message)s"
    logging.basicConfig(filename=filename, filemode='w', format=log_format_string, level=logging.INFO)
    formatter = logging.Formatter(log_format_string)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)
    log = logging.getLogger('SanityChecker')
    log.info('SanityChecker started')

if __name__ == '__main__':
    # The entry point
    parser = argparse.ArgumentParser(description='Verifies if the arguments of the send functions are sanitized')
    parser.add_argument('--all', dest='all', required=False, default=False, help='Process all artifacts in the directory specified')
    parser.add_argument('--apk', dest='apk', required=False, help='APK to be analyzed')
    parser.add_argument('--config', dest='config', required=False, default=None, help='Configuration file containing the analysis parameters')
    parser.add_argument('--pickled', dest='pickled', required=False, default=None, help='Path of the file to load the pickle from or save to')
    parser.add_argument('--lift', dest='lift', action='store_true', required=False, help='Lift an APK and serialize it for further analysis')
    parser.add_argument('--analyze', dest='analyze', action='store_true', required=False, help='Analyzes an APK')
    parser.add_argument('--verify', dest='verify', action='store_true', required=False, help='Verify a serialized pickle dump')
    parser.add_argument('--celery', dest='celery', action='store_true', default=False, help='Is the file-path given, or just the file-name?')
    parser.add_argument('--debug', dest='debug', action='store_true', required=False, help='Determines a debug run from a batch run')
    parser.add_argument('--log', dest='log', default=None, required=False, help='Parses generated logs to extract the required numbers')
    arguments = parser.parse_args()

    # Drops to an ipython shell in debug mode
    # Swallows the exception while running an analysis in bulk
    DEBUG = arguments.debug
    DATA_DIR = '../../../../'

    if arguments.all:
        all_dir = os.path.abspath(arguments.all)

        # Lift APKs
        if arguments.lift:
            log_path = os.path.join(all_dir, 'lifter.log')
            init_logging(log_path)
            apk_regex = os.path.join(all_dir, '*.apk')
            apk_paths = glob.glob(apk_regex)
            pool_args = []
            for apk_path in apk_paths:
                apk_name = os.path.basename(apk_path)
                pickle_path = os.path.splitext(apk_path)[0] + '.pickle'
                pool_args.append((apk_path, pickle_path, _, True))

            pool = multiprocessing.Pool(multiprocessing.cpu_count())
            pool.starmap(run_analysis, pool_args)
            pool.close()
            pool.join()

        # Verify pickle dump
        if arguments.verify:
            log_path = os.path.join(all_dir, 'verifier.log')
            init_logging(log_path)
            pickle_regex = os.path.join(all_dir, '*.pickle')
            pickle_paths = glob.glob(pickle_regex)
            pool_args = []
            for pickle_path in pickle_paths:
                pool_args.append((pickle_path,))

            pool = multiprocessing.Pool(multiprocessing.cpu_count())
            pool.starmap(run_verify, pool_args)
            pool.close()
            pool.join()

    elif arguments.log:
        # Process the log files generated by the analysis stage
        result_file_path = os.path.join(arguments.log, 'sanity_checks.txt')
        init_logging(result_file_path)
        run_log_analysis(arguments.log)

    elif arguments.analyze:
        # Analyze an APK to count the number of sanity checks on send function arguments
        if arguments.celery:
            apk_path = os.path.join(DATA_DIR, arguments.apk)
        else:
            apk_path = arguments.apk
        app_path_without_extension = os.path.splitext(apk_path)[0]
        pickle_path = app_path_without_extension + '.pickle'
        log_path = app_path_without_extension + '.log'
        init_logging(log_path)
        run_analysis(apk_path, pickle_path)

    elif arguments.lift:
        # Lift an APK and pickle it for further analysis
        if arguments.celery:
            apk_path = os.path.join(DATA_DIR, arguments.apk)
        else:
            apk_path = arguments.apk
        app_path_without_extension = os.path.splitext(apk_path)[0]
        pickle_path = app_path_without_extension + '.pickle'
        base_dir = os.path.dirname(apk_path)
        log_path = os.path.join(base_dir, 'lifter.log')
        init_logging(log_path)
        run_analysis(apk_path, pickle_path, lift=True)
