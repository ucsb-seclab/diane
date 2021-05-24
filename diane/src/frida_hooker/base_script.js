var last_methods = [];
var last_instances = [];
var MAX_SIZE = 10;
var partial_instance = [];
var known_objects = {};
var separators = {'cls': ['<CLS>', '</CLS>'],
                  'met': ['<MET>', '</MET>'],
                  'par': ['<PARS>', '</PARS>'],
                  'new_par': '<NEWPAR>',
                  'ret': ['<RETTYPE>', '</RETTYPE>'],
                  'next_entry': '<NEXT_ENTRY>',
                  'new_class_field': '<NEW_CLS_FIELD>',
                  'class_field': ['<CLS_FIELD>', '</CLS_FIELD>'],
                  'field_name': ['<NAME>', '</NAME>'],
                  'field_value': ['<VAL>', '</VAL>'],
                };

var knownTypes = ['java.lang.String', 'java.nio.ByteBuffer', '[B', 'byte[]', 'boolean', 'int', 'void'];

function resetLastMethods(){
    last_methods = [];
}

function resetLastInstaces() {
    last_instances = [];
}

function getSeparators() {
    return separators;
}

function methodToString(cls, method, params, ret) {
    return  separators['cls'][0] + cls + separators['cls'][1] +
            separators['met'][0] + method + separators['met'][1] +
            separators['par'][0] + params.join(separators['new_par']) + separators['par'][1] +
            separators['ret'][0] + ret + separators['ret'][1];
}

function recordMethod(cls, method, params, ret) {
    // update window
    var current_method =  methodToString(cls, method, params, ret);
    if (last_methods.length ===  MAX_SIZE) {
        last_methods.shift();
    }
    last_methods.push(current_method);
    send('METHODS' + last_methods.join(separators['next_entry']));
}

function toHexString(uint8arr) {
  if (!uint8arr) {
    return '';
  }

  var hexStr = '';
  for (var i = 0; i < uint8arr.length; i++) {
    var hex = (uint8arr[i] & 0xff).toString(16);
    hex = (hex.length === 1) ? '0' + hex : hex;
    hexStr += hex;
  }

  return hexStr.toUpperCase();
}

function print_fields(nyc) {
    for(var propName in nyc) {
        console.log(propName);
    }
}

function addKnownObject(obj) {
    known_objects = Object.assign({}, known_objects, obj);
}

function getPrimitiveVal(t, v) {
    var _v = "UNHANDLED";
    if (t === 'java.lang.String') {
        if (v === null) {
            return 'null';
        }
        _v = v.toString();
        /* for(var i = 0; i < v.toString().length; i++)
            _v += ("0x" + (str.charCodeAt(i) & 0xff).toString(16)); */
    } else if(t === '[B') {
        Java.perform(function () {
            var a = Java.array('byte', v);
            var b = new Uint8Array(a);
            _v = "";

            for(var i = 0; i < b.length; i++) {
                _v += "0x";
                if (b[i] <= 0xf) {
                    _v += "0";
                }
                _v += b[i].toString(16);
            }
        });
    }
    else if (t === 'boolean') {
        _v = v;
    }
    else if (t === 'int'){
        _v = v.toString();
    }
    else if (t === 'void') {
        _v = 'void';
    }
    else if (t === 'java.nio.ByteBuffer') {
        if (Java.available) {
            Java.perform(function() {
                var z = [];
                for (var i = 0; i < v.remaining(); i++) z[i] = 0;
                var bb = Java.array('byte', z);
                v.get(bb);
                var b = new Uint8Array(bb);
                _v = "";

                for(var i = 0; i < b.length; i++) {
                    _v += "0x";
                    if (b[i] <= 0xf) {
                        _v += "0";
                    }
                    _v += b[i].toString(16);
                }
            });
        }
    }
    return _v;
}

function getVal(t, v){
    var _v = "UNHANDLED";
    if (knownTypes.indexOf(t) >= 0){
        return getPrimitiveVal(t, v);
    }
    else {
        Java.perform(function x() {
            try {
                var jClass = Java.use(t);
            } catch (error) {
                return
            }

            _v = "";
            var fields = jClass.class.getFields().map(function (f) {
              return f.toString()
            });

            for (var i = 0; i < fields.length; i++){
                var typeInfo = fields[i].split(" ");
                for (var j = 0; j < typeInfo.length; j ++) {
                   if (knownTypes.indexOf(typeInfo[j]) >= 0) {
                       // FIXME: fix this hack
                       if (typeInfo[j] === "byte[]") {
                           typeInfo[j] = "[B";
                       }
                       var nameVar = typeInfo[j+1].split(".");
                       nameVar = nameVar[nameVar.length - 1];
                        if (nameVar !== undefined && v[nameVar] !== undefined) {
                           var val = getPrimitiveVal(typeInfo[j], v[nameVar]['value']);
                           // FIXME: specify also name and type
                           if (val === ''){
                               val = 'null';
                           }
                           _v += "<CLS_FIELD><NAME>" + nameVar.toString() + "</NAME><VAL>"  + val + "</VAL></CLS_FIELD>";
                           _v += "<NEW_CLS_FIELD>";
                        }
                   }
               }
           }
        });
    }
    return _v;
}

function recordInstanceParams(cls, method, params, args) {
    var _args = [];
    for (var i = 0; i < args.length; i++) {
        var _v = getVal(params[i], args[i]);
        _args.push(_v);
    }
    var tmp = [cls, method, _args];
    partial_instance.push(tmp);
}

function recordInstanceRet(ret, val_ret) {
    if (last_instances.length ===  MAX_SIZE) {
        last_instances.shift();
    }

    var _val_ret = getVal(ret, val_ret);
    var tmp = partial_instance.pop();
    var cls = tmp[0];
    var met = tmp[1];
    var args = tmp[2];
    var current_instance = methodToString(cls, met, args, _val_ret);
    last_instances.push(current_instance);
    send('INSTANCES' + last_instances.join(separators['next_entry']));
}

function getValueReturn() {
    return last_returned.toString();
}

function runIt(apkHooks, getInstances) {
    if (getInstances === undefined)
         getInstances = false;
    if (!getInstances) {
        console.log("NOT recording instances!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    } else {
        console.log("recording instances!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    }
    setImmediate(function() {
        Java.perform(function x() {
            // Hook Apk functions
            apkHooks.forEach(function(element) {
                var cls = element[0];
                var method = element[1];
                var params = element[2];
                var ret = element[3];
                try
                {
                    var hooking = methodToString(cls, method, params, ret);
                    send('HOOKING' + hooking);
                    var clx = Java.use(cls);

                    clx[method].overload.apply(this, params).implementation = function f()
                    {
                        var args = Array.prototype.slice.call(arguments, f.length);
                        recordMethod(cls, method, params, ret);
                        // we gotta separate params from return value as they might be alised
                        // and we want to capture those two different values
                        if (getInstances)
                            recordInstanceParams(cls, method, params, args);
                        var to_ret = execFunction(this, cls, method, params, args)
                        if (getInstances)
                            recordInstanceRet(ret, to_ret);
                        return to_ret;
                    }
                } catch(error) {
                    var errored = methodToString(cls, method, params, ret);
                    send("ERRORED" + errored);
                    console.log("OOPS: " + error.toString() + ' ' + errored);
                }
            });
            send("HOOKDONE");
        });
    });
}

