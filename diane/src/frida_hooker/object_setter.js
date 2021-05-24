var fuzz = {'cls': 'none', 'm': 'none', 'n': 0, 'nargs': 0, 'args': [], 'fields': {}, 'i': -1, 'ready': false, 'fast_fuzz': false, 'ord': 0, 'tot': 0, 'single_call_fuzz': false, 'curr_call': 0};
var functions_called = {};

function getUtilsCalls(methodPath) {
    var sign = methodPath[0] + methodPath[1] + methodPath[2];
    console.log("method: " + methodPath);
    console.log("SIgn: " + sign);
    if (functions_called[sign] === undefined){
        return 0;
    }
    return functions_called[sign];
}

function execFunction(ctx, cls, method, args_types, args) {
    var new_args = args;
    var i;
    var sign = cls + method + args_types;
    var sent_reps = false;

    if (functions_called[sign] === undefined){
        functions_called[sign] = 0
    }

    // Should we fuzz the function
    // FIXME: check also paramenters!!
    if (cls === fuzz['cls'] && method === fuzz['m']) {
        // console.log(functions_called[sign]);
        // console.log(fuzz['curr_call']);

        var exec = true;
        if (fuzz['single_call_fuzz'] && functions_called[sign] !== fuzz['curr_call'])
            exec = false;

        if (fuzz['ready'] && exec) {
            send("Replaying hooked function");
            if (fuzz['fast_fuzz']) {
                // fast fuzzing is enabled:
                //  execute the same function multiple times
                for (i = 0; i < fuzz['n']; i++) {
                    var fuzzed_args = prepareFuzzedCall(ctx, args, i);
                    ctx[method].apply(ctx, fuzzed_args);
                    send("NREP:" + (i + 1).toString());
                    sent_reps = true;
                }
            }
            else {
                // just change the current function argument values
                fuzz['tot'] = fuzz['tot'] + 1;
                send("NREP:" + (fuzz['tot']).toString());
                new_args = prepareFuzzedCall(ctx, args, fuzz['ord']);
                fuzz['ord'] = (fuzz['ord'] + 1) % fuzz['n'];
                sent_reps = true;
            }
        }
    }

    if (sent_reps === false) {
        send("NREP:" + functions_called[sign].toString());
    }

    functions_called[sign] += 1;
    return ctx[method].apply(ctx, new_args);
}


function shuffle(array) {
  var currentIndex = array.length, temporaryValue, randomIndex;
  while (0 !== currentIndex) {
    randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex -= 1;

    temporaryValue = array[currentIndex];
    array[currentIndex] = array[randomIndex];
    array[randomIndex] = temporaryValue;
  }

  return array;
}

function prepareNewFuzz(cls, m, n, nargs, fast_fuzz, single_call_fuzz, curr_call) {
    fuzz = {'cls': cls, 'm': m, 'n': n, 'nargs': nargs, 'args': [], 'fields':{}, 'i': -1, 'ready': false, 'fast_fuzz': fast_fuzz, 'ord': 0, 'tot': 0, 'single_call_fuzz': single_call_fuzz, 'curr_call': curr_call};
    fuzz['args'][0] = [];
}

function stopArgsFuzz() {
    fuzz['ready'] = false;
}

function fuzzPrepareDone(doShuffle) {
    fuzz['ready'] = true;
    if (doShuffle === true) {
        // shuffle array to introduce even more
        if (fuzz['nargs'] > 0) {
            fuzz['args'] = shuffle(fuzz['args'])
        }
        if (fuzz['fields'].length > 0) {
            fuzz['fields'] = shuffle(fuzz['fields'])
        }
    }
    functions_called = {};
}

function nextFieldsList() {
    fuzz['i'] += 1;
}

function nextParamsList() {
    fuzz['i'] += 1;
    fuzz['args'][fuzz['i']] = [];
}

function getNewArgs(args, ord, ctx) {
    var new_args = [];
    var current_fuzz_args = fuzz['args'][ord];

    for (i = 0; i < args.length; i++){
        if (typeof(current_fuzz_args[i]) === 'string' && current_fuzz_args[i] === 'UNFUZZ') {
            new_args.push(args[i]);
        }
        else if (typeof(current_fuzz_args[i]) === 'string' && current_fuzz_args[i] === 'SIMPLEOBJ') {
            for (var field in fuzz['fields']){
                //FIXME: with java objects might not work like this (?)
                args[i][field]['value'] = fuzz['fields'][field][ord];
            }
            new_args.push(args[i]);
        }
        else {
            new_args.push(current_fuzz_args[i]);
        }
    }

    return new_args;
}

function prepareFuzzedCall(ctx, args, ord) {
    var new_args = args;
    if (fuzz['nargs'] > 0) {
        new_args = getNewArgs(args, ord, ctx);
    }

    else if (Object.keys(fuzz['fields']).length > 0){
        Object.keys(fuzz['fields']).forEach(function(field) {
        //FIXME: with java objects might not work like this (?)
            ctx[field]['value'] = fuzz['fields'][field][ord];
        });
    }
    return new_args;
}

function addPrimitiveType(prim_type, val, len) {
    if (Java.available) {
        Java.perform(function() {
            if (fuzz['n'] > fuzz['i'] && fuzz['nargs'] > fuzz['args'][fuzz['i']].length) {
                var i;
                if (len == 1) {
                    i = val;
                } else {
                    i = Java.array(prim_type, val);
                }
                fuzz['args'][fuzz['i']].push(i);
            }
        }
    )}
}

function addObj(cls, fields, len) {
    if (Java.available) {
        Java.perform(function() {
            if (fuzz['n'] > fuzz['i'] && fuzz['nargs'] > fuzz['args'][fuzz['i']].length) {
                if (len == 1) {
                    const obj = Java.use(cls);
                    var o = obj.$new(fields);
                    fuzz['args'][fuzz['i']].push(o);
                } else {
                    //FIXME: implement array
                    console.log("FIXME: array of objects in param");
                }
            }
        }
    )}
}

function addUnfuzzedObj() {
    fuzz['args'][fuzz['i']].push("UNFUZZ");
}

function addSimpleObj() {
    fuzz['args'][fuzz['i']].push("SIMPLEOBJ");
}

function addFieldValPrim(prim_type, val, len, field_name) {
    if (Java.available) {
        Java.perform(function() {
            if (fuzz['n'] > fuzz['i']) {
                if (len == 1) {
                    i = val;
                } else {
                    i = Java.array(prim_type, val);
                }

                if (fuzz['fields'][field_name] === undefined){
                    fuzz['fields'][field_name] = []
                }
                fuzz['fields'][field_name].push(i);
            }
        }
    )}
}

function addFieldValObj(cls, vals, len, field_name) {
    if (Java.available) {
        Java.perform(function() {
            if (fuzz['n'] > fuzz['i']) {
                if (len == 1) {
                    const obj = Java.use(cls);
                    var o = obj.$new(vals);
                    if (fuzz['fields'][field_name] === undefined){
                        fuzz['fields'][field_name] = []
                    }
                    fuzz['fields'][field_name].push(o);
                } else {
                    //FIXME
                    console.log("FIXME: array of objects in fields");
                }

            }
        }
    )}
}


function addByteBuffer(cls, bytes, len){
    //console.log(cls);
    if (Java.available) {
            Java.perform(function() {
                if (fuzz['n'] > fuzz['i'] && fuzz['nargs'] > fuzz['args'][fuzz['i']].length) {
                    const obj = Java.use("java.nio.ByteBuffer");
                    var barray = Java.array("byte", bytes);
                    var o = obj.wrap(barray);
                    fuzz['args'][fuzz['i']].push(o);
                }
            }
    )}
}

function addFieldValByteBuffer(cls, fields, len){
    // IMPLEMENTME
    console.log("IMPLEMENT ME!!!");
}
