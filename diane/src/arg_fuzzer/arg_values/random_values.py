import random
import string
import numpy


MIN_INT_32 = -2147483648
MAX_INT_32 = 2147483647


class RandomValues:
    def __init__(self, *args, **kwargs):
        self.proposed_vals = {
            'int': {
                'fun': [self.low_pos, self.low_neg, self.null, self.big_pos, self.big_neg],
                'dist': [0.23, 0.23, 0.08, 0.23, 0.23]
            },
            'long': {
                'fun': [self.low_pos, self.low_neg, self.null, self.big_pos, self.big_neg],
                'dist': [0.23, 0.23, 0.08, 0.23, 0.23]
            },
            'java.lang.Integer': {
                'fun': [self.low_pos, self.low_neg, self.null, self.big_pos, self.big_neg],
                'dist': [0.23, 0.23, 0.08, 0.23, 0.23]
            },
            'java.lang.Float':{
                'fun': [self.low_pos_float, self.low_neg_float, self.null, self.big_pos_float, self.big_neg_float],
                'dist': [0.23, 0.23, 0.08, 0.23, 0.23]
            },
            'float': {
                'fun': [self.low_pos_float, self.low_neg_float, self.null, self.big_pos_float, self.big_neg_float],
                'dist': [0.23, 0.23, 0.08, 0.23, 0.23]
            },
            'java.lang.Double': {
                'fun': [self.low_pos, self.low_neg, self.null, self.big_pos, self.big_neg],
                'dist': [0.23, 0.23, 0.08, 0.23, 0.23]
            },
            'boolean': {
                'fun': [self.true, self.false],
                'dist': [0.5, 0.5]
            },
            'java.lang.String': {
                'fun': [self.printable_chars],
                'dist': [1]
            },
            'byte': {
                'fun': [self.low_pos],
                'dist': [1]
            },
            'java.nio.ByteBuffer': {
                'fun': [self.low_pos],
                'dist': [1]
            },
            'array': {
                'fun': [self.low_pos_array, self.big_pos_moderate_array],
                'dist': [0.5, 0.5]
                # FIME: fix and use null array
            }
        }

    def low_pos_array(self):
        return random.randint(1, 255)

    def low_pos(self):
        return random.randint(0, 255)

    def low_neg(self):
        return random.randint(-255, 0)

    def big_pos_moderate_array(self):
        return random.randint(500, 16384)

    def big_pos_moderate(self):
        return random.randint(500, 16384)

    def big_pos(self):
        return random.randint(MAX_INT_32 / 2, MAX_INT_32)

    def big_neg(self):
        return random.randint(MIN_INT_32, MIN_INT_32 / 2)

    def low_pos_float(self):
        return random.uniform(0.0, 255.0)

    def low_neg_float(self):
        return random.uniform(-255.0, 0.0)

    def big_pos_float(self):
        return random.uniform(MAX_INT_32 / 2.0, float(MAX_INT_32))

    def big_neg_float(self):
        return random.uniform(float(MIN_INT_32), MIN_INT_32 / 2.0)

    def null(self):
        return 0

    def true(self):
        return True

    def false(self):
        return False

    def printable_chars(self):
        len = numpy.random.choice(self.proposed_vals['array']['fun'], p=self.proposed_vals['array']['dist'])()
        # FIXME: find a way to use empty strings
        len += 1
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(len))

    def fuzz_type(self, type_obj, obj_creator, array, primitive, *kargs, **kwargs):
        if array:
            n = numpy.random.choice(self.proposed_vals['array']['fun'], p=self.proposed_vals['array']['dist'])()
            val = [numpy.random.choice(self.proposed_vals[type_obj]['fun'], p=self.proposed_vals[type_obj]['dist'])() for i in range(0, n)]
        else:
            n = 1
            val = numpy.random.choice(self.proposed_vals[type_obj]['fun'], p=self.proposed_vals[type_obj]['dist'])()

        if obj_creator is not None:
            obj_creator(type_obj, primitive, val, n, *kargs, **kwargs)
        return val

    def fuzz_int(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('int', obj_creator, False, True, *kargs, **kwargs)

    def fuzz_long(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('long', obj_creator, False, True, *kargs, **kwargs)

    def fuzz_float(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('float', obj_creator, False, True, *kargs, **kwargs)

    def fuzz_double(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('float', obj_creator, False, True, *kargs, **kwargs)

    def fuzz_boolean(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('boolean', obj_creator, False, True, *kargs, **kwargs)

    def fuzz_byte(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('byte', obj_creator, False, True, *kargs, **kwargs)

    def fuzz_byte_array(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('byte', obj_creator, True, True, *kargs, **kwargs)

    def fuzz_int_array(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('int', obj_creator, True, True, *kargs, **kwargs)

    def fuzz_java_lang_String(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('java.lang.String', obj_creator, False, False, *kargs, **kwargs)

    def fuzz_java_lang_Integer(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('java.lang.Integer', obj_creator, False, False, *kargs, **kwargs)

    def fuzz_java_lang_Float(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('java.lang.Float', obj_creator, False, False, *kargs, **kwargs)

    def fuzz_java_lang_Doable(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('java.lang.Doable', obj_creator, False, False, *kargs, **kwargs)

    def fuzz_java_nio_ByteBuffer(self, obj_creator, *kargs, **kwargs):
        return self.fuzz_type('java.nio.ByteBuffer', obj_creator, True, True, *kargs, **kwargs)

if __name__ == "__main__":
    types = ['int', 'byte', 'java.lang.Integer', 'java.lang.String', 'boolean', 'java.lang.Double', 'java.lang.Float']
    arrays = [True, False]
    v = Values()
    empty_method = lambda *kargs, **kwargs: None

    for t in types:
        method = 'fuzz_' + t.replace('.', '_')
        if hasattr(v, method):
            print t
            print getattr(v, method)(empty_method)

        method = 'fuzz_' + t.replace('.', '_') + '_array'
        if hasattr(v, method):
            print t + ' array'
            print getattr(v, method)(empty_method)
