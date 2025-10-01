// Frida script: hook atexit and __cxa_atexit using Process.getModuleByName(...).getExportByName(...)
const moduleName = "bshield"; // change if needed, or set to null to skip module-scoped lookup
const BLOCK_REGISTRATION = false; // flip to true to drop registrations

var atexit_registry = [];
var cxa_atexit_registry = [];

function findExportUsingPreferred(sym) {
    // Try Process.getModuleByName(...).getExportByName(sym) when moduleName provided and module present
    if (moduleName) {
        try {
            var mod = Process.getModuleByName(moduleName);
            if (mod) {
                try {
                    var exp = mod.getExportByName(sym);
                    if (exp) return { name: sym + " (module)", addr: exp };
                } catch (e) {
                    // not found in this module - fall through
                }
            }
        } catch (e) {
            // module not loaded / not found - fall through to global
        }
    }

    // Fallback: global lookup
    var addr = Module.findExportByName(null, sym);
    if (addr) return { name: sym + " (global)", addr: addr };

    return null;
}

// Helper: attempt multiple candidate names and return first match
function findAny(candidates) {
    for (var i = 0; i < candidates.length; i++) {
        var found = findExportUsingPreferred(candidates[i]);
        if (found) return found;
    }
    return null;
}


// --- Hook atexit (C) ---
(function hook_atexit() {
    var candidates = ["atexit", "_atexit"];
    var found = findAny(candidates);
    if (!found) {
        console.log("[-] atexit: symbol not found (" + candidates.join(", ") + ")");
        return;
    }

    console.log("[+] atexit symbol found: " + found.name + " @ " + found.addr);

    var orig_atexit = new NativeFunction(found.addr, 'int', ['pointer']);

    Interceptor.replace(found.addr, new NativeCallback(function (funcPtr) {
        console.log("[*] atexit called. handler=" + funcPtr);

        atexit_registry.push({
            handler: funcPtr,
            timestamp: (new Date()).toISOString()
        });

        if (BLOCK_REGISTRATION) {
            console.log("[!] BLOCK_REGISTRATION enabled — dropping this atexit registration");
            // Many libraries expect 0 on success; return 0 to pretend success without registering.
            return 0;
        }

        try {
            var r = orig_atexit(funcPtr);
            console.log("[*] atexit original returned: " + r);
            return r;
        } catch (e) {
            console.log("ERROR calling original atexit: " + e);
            return -1;
        }
    }, 'int', ['pointer']));
})();


// --- Hook __cxa_atexit (C++) ---
(function hook_cxa_atexit() {
    // __cxa_atexit signature: int __cxa_atexit(void (*f)(void *), void *arg, void *dso_handle)
    var candidates = ["__cxa_atexit", "_Z11__cxa_atexitPvS_Pv"];
    var found = findAny(candidates);
    if (!found) {
        console.log("[-] __cxa_atexit: symbol not found (" + candidates.join(", ") + ")");
        return;
    }

    console.log("[+] __cxa_atexit symbol found: " + found.name + " @ " + found.addr);

    var orig_cxa = new NativeFunction(found.addr, 'int', ['pointer', 'pointer', 'pointer']);

    Interceptor.replace(found.addr, new NativeCallback(function (funcPtr, argPtr, dsoHandle) {
        console.log("[*] __cxa_atexit called. func=" + funcPtr + " arg=" + argPtr + " dso=" + dsoHandle);

        cxa_atexit_registry.push({
            handler: funcPtr,
            arg: argPtr,
            dso: dsoHandle,
            timestamp: (new Date()).toISOString()
        });

        if (BLOCK_REGISTRATION) {
            console.log("[!] BLOCK_REGISTRATION enabled — dropping this __cxa_atexit registration");
            return 0; // pretend success
        }

        try {
            var r = orig_cxa(funcPtr, argPtr, dsoHandle);
            console.log("[*] __cxa_atexit original returned: " + r);
            return r;
        } catch (e) {
            console.log("ERROR calling original __cxa_atexit: " + e);
            return -1;
        }
    }, 'int', ['pointer', 'pointer', 'pointer']));
})();


// --- RPC helpers for inspection / invoke ---
rpc.exports = {
    listAtexit: function () {
        return atexit_registry.map(function (e, i) { return { index: i, handler: e.handler.toString(), timestamp: e.timestamp }; });
    },
    listCxa: function () {
        return cxa_atexit_registry.map(function (e, i) { return { index: i, handler: e.handler.toString(), arg: e.arg.toString(), dso: e.dso.toString(), timestamp: e.timestamp }; });
    },
    callAtexitHandler: function (index) {
        if (index < 0 || index >= atexit_registry.length) return "index out of range";
        var ptr = atexit_registry[index].handler;
        var cb = new NativeFunction(ptr, 'void', []);
        cb();
        return "called handler " + ptr;
    },
    callCxaHandler: function (index) {
        if (index < 0 || index >= cxa_atexit_registry.length) return "index out of range";
        var entry = cxa_atexit_registry[index];
        var cb = new NativeFunction(entry.handler, 'void', ['pointer']);
        cb(entry.arg);
        return "called cxa handler " + entry.handler + " with arg " + entry.arg;
    },
    getRegistries: function () {
        return { atexit: atexit_registry.length, cxa: cxa_atexit_registry.length };
    }
};

console.log("[+] Hook setup complete. Use rpc.exports.* from frida REPL or your orchestration script.");


