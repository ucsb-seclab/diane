rpc.exports = {
    runit: runIt,
    preparenewfuzz: prepareNewFuzz,
    resetlastmethods: resetLastMethods,
    resetlastinstances: resetLastInstaces,
    fuzzpreparedone: fuzzPrepareDone,
    nextparamlist: nextParamsList,
    nextfieldslist: nextFieldsList,
    addprimitivetype: addPrimitiveType,
    addunfuzzedobj: addUnfuzzedObj,
    addobj: addObj,
    addfieldvalprim: addFieldValPrim,
    addfieldvalobj: addFieldValObj,
    addsimpleobj: addSimpleObj,
    getvaluereturn: getValueReturn,
    getseparators: getSeparators,
    stopargsfuzz: stopArgsFuzz,
    addknownobject: addKnownObject,
    addjavaniobytebuffer: addByteBuffer,
    addfieldvarjavaniobytebuffer: addFieldValByteBuffer,
    adhocconstructors: adHocConstructors,
    getutilscalls: getUtilsCalls,
};

function adHocConstructors(){
    return ['addjavaniobytebuffer', 'addfieldvarjavaniobytebuffer'];
}
