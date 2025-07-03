if (ObjC.available) {
    try {
        var className = "ShieldLoader";

        // ---- Replace +[ShieldLoader initShield] ----
        var initShield = ObjC.classes[className]["+ initShield"];
        if (initShield) {
            Interceptor.replace(initShield.implementation, new NativeCallback(function () {
                console.log("[*] Replaced +initShield");
                // Custom behavior here
                // Do nothing or log
                // return 'nil' if return type is object
                return ptr("0x0");
            }, 'pointer', [])); // Return type: id (pointer), no args
        } else {
            console.log("[-] Method not found: +initShield");
        }

        // ---- Replace +[ShieldLoader loadShield:] ----
        var loadShield = ObjC.classes[className]["+ loadShield:"];
        if (loadShield) {
            Interceptor.replace(loadShield.implementation, new NativeCallback(function (self, sel, arg1) {
                var obj = new ObjC.Object(arg1);
                console.log("[*] Replaced +loadShield:");
                console.log("Argument: " + obj.toString());

                // custom behavior here
                // Returning void
            }, 'void', ['pointer', 'pointer', 'pointer']));
        } else {
            console.log("[-] Method not found: +loadShield:");
        }

    } catch (err) {
        console.log("[-] Exception: " + err.message);
    }
} else {
    console.log("[-] Objective-C Runtime is not available.");
}