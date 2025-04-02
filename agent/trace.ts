// std::runtime_error *__cdecl std::runtime_error::runtime_error(std::runtime_error *__hidden this, const char *)
const runtime_errorFunc = Module.findExportByName('bshield', '__ZNSt13runtime_errorC1EPKc') ?? new NativePointer(0x00);

Interceptor.attach(runtime_errorFunc, {
    onEnter(args) {
        console.log('runtime_errorFunc:');
        console.log(args[1].readCString());
    },
    onLeave(retval) {
        console.log('runtime_errorFunc return:' + retval.readCString());
    }
});