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

// kern_return_t __cdecl mach_port_allocate(ipc_space_t task, mach_port_right_t right, mach_port_name_t *name)
const mach_port_allocateFunc = Module.findExportByName('bshield', '_mach_port_allocate') ?? new NativePointer(0x00);

Interceptor.attach(mach_port_allocateFunc, {
    onEnter(args) {
        console.log('mach_port_allocateFunc:' + args[0].readUtf8String());
    },
    onLeave(retval) {
        console.log('mach_port_allocateFunc return:' + retval.readCString());
    }
});

Interceptor.attach(Module.findExportByName('bshield', "open"), {
    onEnter: function (args) {
        var filename = args[0].readUtf8String();
        console.log("_open:" + filename);
        args[0] = ptr('0xffffffffffffffff');
    },
    onLeave: function (retval) {
        if (retval.equals(ptr('0xffffffffffffffff'))) {
            /////console.log("\x1b[32m[*] open returned: \x1b[0m" + retval);
        }
    }
});