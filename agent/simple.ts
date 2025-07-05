if (ObjC.available) {
    const className = "ShieldLoader";
    const methodName = "+initShield";

    try {
        const targetMethod = ObjC.classes[className][methodName];

        Interceptor.replace(targetMethod.implementation, new NativeCallback(function (self, _cmd) {
            console.log("[*] Replaced +[ShieldLoader initShield]");


            return; // void return
        }, 'void', ['pointer', 'pointer'])); // 'id' and 'SEL' are both pointers

    } catch (err) {
        console.error("[-] Failed to replace method: " + err);
    }
} else {
    console.log("Objective-C runtime is not available.");
}