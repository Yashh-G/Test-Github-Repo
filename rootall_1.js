console.log("[*] Native Root Detection Bypass Loaded");

try {
    // Hook fopen to prevent access to root-related files
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args);
            var rootFiles = ["su", "magisk", "busybox", "/system/bin/su", "/system/xbin/su"];
            
            for(var i = 0; i < rootFiles.length; i++) {
                if(path.indexOf(rootFiles[i]) !== -1) {
                    console.log("[+] Blocking fopen for: " + path);
                    Memory.writeUtf8String(args, "/dev/null");
                    break;
                }
            }
        }
    });
} catch(e) { console.log("[!] fopen hook error: " + e); }

try {
    // Hook access to prevent checking file access
    Interceptor.attach(Module.findExportByName("libc.so", "access"), {
        onEnter: function(args) {
            var path = Memory.readCString(args);
            if(path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1) {
                console.log("[+] Blocking access check for: " + path);
                args = Memory.allocUtf8String("/dev/null");
            }
        },
        onLeave: function(retval) {
            if(retval.toInt32() === 0) {
                retval.replace(-1); // Return "not found"
            }
        }
    });
} catch(e) { console.log("[!] access hook error: " + e); }

try {
    // Hook system calls
    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args);
            if(cmd.indexOf("su") !== -1 || cmd.indexOf("getprop") !== -1) {
                console.log("[+] Blocking system call: " + cmd);
                Memory.writeUtf8String(args, "echo");
            }
        }
    });
} catch(e) { console.log("[!] system hook error: " + e); }

try {
    // Hook execve to block root processes
    Interceptor.attach(Module.findExportByName("libc.so", "execve"), {
        onEnter: function(args) {
            var filename = Memory.readCString(args);
            if(filename.indexOf("su") !== -1 || filename.indexOf("magisk") !== -1) {
                console.log("[+] Blocking execve: " + filename);
                args = Memory.allocUtf8String("/bin/false");
            }
        }
    });
} catch(e) { console.log("[!] execve hook error: " + e); }

console.log("[*] Native root detection bypass complete");
