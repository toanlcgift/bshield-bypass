// frida_hook_terminate.js
// Intercept/replace C++ std::terminate and related functions on iOS
// Usage: frida -U -f <bundle_id> -l frida_hook_terminate.js --no-pause

function tryReplace(addr: NativePointer, sig: string) {
    if (!addr || addr.isNull() && addr.equals(ptr("0x0"))) {
        return false;
    }
    try {
        console.log("[*] Replacing at", addr, " signature:", sig);
        if (sig === 'void_v') {
            Interceptor.replace(addr, new NativeCallback(function () {
                console.log("[+] std::terminate noop called - returning instead of terminating");
                // do nothing — return to caller
            }, 'void', []));
        } else if (sig === 'void_ptr_ptr_ptr') {
            Interceptor.replace(addr, new NativeCallback(function (p1, p2, p3) {
                console.log("[+] __cxa_throw noop called - swallowing exception");
                // optionally examine p1/p2/p3 here, then return to avoid unwind/terminate
            }, 'void', ['pointer', 'pointer', 'pointer']));
        } else if (sig === 'void_int') {
            Interceptor.replace(addr, new NativeCallback(function (code) {
                console.log("[+] _exit noop called with code", code);
            }, 'void', ['int']));
        } else if (sig === 'void_ptr') {
            Interceptor.replace(addr, new NativeCallback(function (p) {
                console.log("[+] abort noop called");
            }, 'void', ['pointer']));
        } else {
            // generic void*
            Interceptor.replace(addr, new NativeCallback(function () {
                console.log("[+] replaced unknown signature (no-op)");
            }, 'void', []));
        }
        return true;
    } catch (e) {
        console.error("[!] replace failed:", e);
        return false;
    }
}

function findAndReplaceSymbol(moduleName: string | null, nameVariants: string[], signature: string) {
    // try Module.findExportByName first (works for exported symbols)
    for (var i = 0; i < nameVariants.length; i++) {
        var sym = nameVariants[i];
        try {
            var addr = null;
            if (moduleName) {
                addr = Module.findExportByName(moduleName, sym);
            } else {
                addr = Module.findExportByName(null, sym);
            }
            if (addr) {
                if (tryReplace(addr, signature)) {
                    console.log("[*] replaced", sym, "from exports");
                    return true;
                }
            }
        } catch (e) {
            // ignore
        }
    }

    // try DebugSymbol.fromName (works when Frida can resolve debug symbols)
    for (var i = 0; i < nameVariants.length; i++) {
        try {
            var dbg = DebugSymbol.fromName(nameVariants[i]);
            if (dbg && dbg.address) {
                if (tryReplace(dbg.address, signature)) {
                    console.log("[*] replaced", nameVariants[i], "from DebugSymbol");
                    return true;
                }
            }
        } catch (e) {
            // ignore
        }
    }

    // try scanning module's exports (case: symbol with leading underscore or variant)
    if (moduleName) {
        try {
            var exps = Process.getModuleByName(moduleName).enumerateExports();
            for (var j = 0; j < exps.length; j++) {
                var exp = exps[j];
                for (var k = 0; k < nameVariants.length; k++) {
                    if (exp.name.indexOf(nameVariants[k]) !== -1) {
                        if (tryReplace(exp.address, signature)) {
                            console.log("[*] replaced", exp.name, "from enumerateExports");
                            return true;
                        }
                    }
                }
            }
        } catch (e) {
            // ignore
        }
    }

    return false;
}

rpc.exports = {
    enablehooks: function (moduleName) {
        // Try common variants for std::terminate (mangled forms differ by platform)
        // C++ Itanium ABI mangled name: ZSt9terminatev -> with leading "_" on Mach-O: _ZSt9terminatev
        var terminateVariants = [
            "__ZSt9terminatev", // sometimes double underscore
            "_ZSt9terminatev",  // common on Mach-O
            "ZSt9terminatev",
            "__ZSt9terminatev@plt",
            "std::terminate",
            "terminate"
        ];
        var replaced = findAndReplaceSymbol(moduleName, terminateVariants, 'void_v');
        console.log("[*] std::terminate replaced:", replaced);

        // Also try to intercept __cxa_throw (often used to throw C++ exceptions)
        var cxaVariants = [
            "__cxa_throw",
            "_ZTISt9exception", // not a function but sometimes useful to inspect
            "_ZSt9terminatev" // redundant, harmless
        ];
        var replacedCxA = findAndReplaceSymbol(moduleName, ["__cxa_throw", "_ZSt9terminatev"], 'void_ptr_ptr_ptr');
        console.log("[*] __cxa_throw replaced:", replacedCxA);

        // Intercept abort/exit/_exit as extra safety
        var abortVariants = ["abort", "_abort"];
        var replacedAbort = findAndReplaceSymbol(null, abortVariants, 'void_ptr'); // abort signature is often void(void) but we allow pointer
        console.log("[*] abort replaced:", replacedAbort);

        var exitVariants = ["_exit", "exit"];
        var replacedExit = findAndReplaceSymbol(null, exitVariants, 'void_int');
        console.log("[*] exit/_exit replaced:", replacedExit);

        return {
            std_terminate: replaced,
            cxa_throw: replacedCxA,
            abort: replacedAbort,
            exit: replacedExit
        };
    }
};

// Auto-run for convenience if script injected interactively:
setImmediate(function () {
    try {
        var mainModule = "bshield"; // usually the main binary, but you can pass module name to rpc
        console.log("[*] Attempting to hook termination functions in main module:", mainModule);
        var res = rpc.exports.enablehooks(mainModule);
        console.log("[*] Hook result:", JSON.stringify(res));
    } catch (e) {
        console.error("[!] Auto-hook failed:", e);
    }
});
