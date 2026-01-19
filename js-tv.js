setTimeout(function() {
    Java.perform(function() {
        console.log("[*] Starting Enhanced SSL & Root/Emulator Bypass Suite for JioTV");
        const bypassStatus = {
            ssl: false,
            root: false,
            emulator: false
        };
        const ROOT_FILES = [
           "/data/local/bin/su",
           "/data/local/su",
           "/data/local/xbin/su",
           "/dev/com.koushikdutta.superuser.daemon/",
           "/sbin/su",
           "/system/app/Superuser.apk",
           "/system/bin/failsafe/su",
           "/system/bin/su",
           "/su/bin/su",
           "/system/etc/init.d/99SuperSUDaemon",
           "/system/sd/xbin/su",
           "/system/xbin/busybox",
           "/system/xbin/daemonsu",
           "/system/xbin/su",
           "/system/sbin/su",
           "/vendor/bin/su",
           "/cache/su",
           "/data/su",
           "/dev/su",
           "/system/bin/.ext/su",
           "/system/usr/we-need-root/su",
           "/system/app/Kinguser.apk",
           "/data/adb/magisk",
           "/sbin/.magisk",
           "/cache/.disable_magisk",
           "/dev/.magisk.unblock",
           "/cache/magisk.log",
           "/data/adb/magisk.img",
           "/data/adb/magisk.db",
           "/data/adb/magisk_simple",
           "/init.magisk.rc",
           "/system/xbin/ku.sud",
           "/data/adb/ksu",
           "/data/adb/ksud",
           "/data/adb/ksu.apk",
           "/data/adb/ksud.apk",
           "/data/adb/magisk.apk",
           "/data/adb/magisk_simple.apk",
           "/data/adb/magisk.img",
           "/data/adb/magisk.db",
        ];
        const ROOT_PACKAGES = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "eu.chainfire.supersu.pro",
            "com.kingouser.com"
        ];
        const ROOT_BINARIES = new Set([
            "su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk",
            "SuperSu.apk", "magisk", "magisk64", "magiskhide", "magiskboot"
        ]);
        const ROOT_PROPERTIES = new Map([
            ["ro.build.selinux", "1"],
            ["ro.debuggable", "0"],
            ["service.adb.root", "0"],
            ["ro.secure", "1"],
            ["ro.build.tags", "release-keys"],
            ["ro.build.type", "user"]
        ]);
        const SENSITIVE_PROPS = new Set([
            "ro.secure",
            "ro.debuggable",
            "ro.build.fingerprint",
            "service.adb.root"
        ]);

        const LOG_LEVEL = {
            DEBUG: 0,
            INFO: 1,
            WARN: 2,
            ERROR: 3
        };
        const CURRENT_LOG_LEVEL = LOG_LEVEL.INFO;

        function log(level, message, error) {
            if (level >= CURRENT_LOG_LEVEL) {
                switch(level) {
                    case LOG_LEVEL.DEBUG:
                        console.log("[D] " + message);
                        break;
                    case LOG_LEVEL.INFO:
                        console.log("[*] " + message);
                        break;
                    case LOG_LEVEL.WARN:
                        console.log("[!] " + message);
                        break;
                    case LOG_LEVEL.ERROR:
                        console.error("[E] " + message);
                        if (error) console.error(error.stack || error);
                        break;
                }
            }
        }

        // Enhanced delayed hook with overload support
        function delayedHook(className, methodName, implementation, overloads) {
            function tryHook() {
                try {
                    const clazz = Java.use(className);
                    if (overloads) {
                        overloads.forEach(ol => {
                            try {
                                clazz[methodName].overload(...ol).implementation = implementation;
                                log(LOG_LEVEL.INFO, `[+] Hooked ${className}.${methodName} overload: ${ol.join(', ')}`);
                            } catch (e) {
                                log(LOG_LEVEL.WARN, `[-] Specific overload failed: ${ol.join(', ')}`);
                            }
                        });
                    } else {
                        clazz[methodName].implementation = implementation;
                        log(LOG_LEVEL.INFO, `[+] Hooked ${className}.${methodName}`);
                    }
                    return true;
                } catch (e) {
                    if (e.toString().includes("ClassNotFoundException") || e.toString().includes("has no method named")) {
                        setTimeout(tryHook, 1000); // Increased retry to 1s to avoid overload
                        return false;
                    } else {
                        log(LOG_LEVEL.WARN, `[-] Hook failed for ${className}.${methodName}: ${e}`);
                        return false;
                    }
                }
            }
            tryHook();
        }

        // SSL Bypasses (kept as is, since it worked)
        function setupSSLBypass() {
            console.log("[+] Setting up SSL bypass...");
            try {
                // HttpsURLConnection
                delayedHook("javax.net.ssl.HttpsURLConnection", "setDefaultHostnameVerifier", function(hostnameVerifier) {
                    const NullHostnameVerifier = Java.registerClass({
                        name: 'org.webkit.android.NullHostnameVerifier',
                        implements: [Java.use('javax.net.ssl.HostnameVerifier')],
                        methods: {
                            verify: function (hostname, session) {
                                return true;
                            }
                        }
                    });
                    return this.setDefaultHostnameVerifier(NullHostnameVerifier.$new());
                });

                delayedHook("javax.net.ssl.HttpsURLConnection", "setSSLSocketFactory", function(sslSocketFactory) {
                    return;
                });

                // SSLContext - with overload
                const sslOverloads = [["[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"]];
                delayedHook("javax.net.ssl.SSLContext", "init", function(keyManager, trustManager, secureRandom) {
                    const TrustAllCerts = Java.registerClass({
                        name: 'org.webkit.android.TrustAllCerts',
                        implements: [Java.use('javax.net.ssl.X509TrustManager')],
                        methods: {
                            checkClientTrusted: function(chain, authType) {},
                            checkServerTrusted: function(chain, authType) {},
                            getAcceptedIssuers: function() { return []; }
                        }
                    });
                    return this.init(keyManager, [TrustAllCerts.$new()], secureRandom);
                }, sslOverloads);

                // TrustManagerImpl
                delayedHook("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    return untrustedChain;
                });

                delayedHook("com.android.org.conscrypt.TrustManagerImpl", "checkTrustedRecursive", function(a1, a2, a3, a4, a5, a6) {
                    return Java.use("java.util.ArrayList").$new();
                });

                // OkHttp3 - fixed overload
                const okOverloads = [["java.lang.String", "java.util.List"]];
                delayedHook("okhttp3.CertificatePinner", "check", function(hostname, pins) {
                    console.log(`[+] Bypassing OkHttp check for: ${hostname}`);
                    return;
                }, okOverloads);

                // WebViewClient
                const webOverloads = [["android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"]];
                delayedHook("android.webkit.WebViewClient", "onReceivedSslError", function(view, handler, error) {
                    handler.proceed();
                }, webOverloads);

                delayedHook("android.webkit.WebViewClient", "onReceivedError", function(view, request, error) {
                    // Do nothing
                });

                bypassStatus.ssl = true;
                log(LOG_LEVEL.INFO, "[+] SSL Bypass setup completed");
                return true;
            } catch(e) {
                log(LOG_LEVEL.ERROR, "[-] SSL Bypass setup failed:", e);
                return false;
            }
        }

        // Enhanced Root/Emulator Bypasses
        function setupRootBypass() {
            console.log("[+] Initializing Enhanced Root/Emulator Detection Bypass...");
            try {
                // Comprehensive Build Properties Spoofing for Emulator + Root
                Java.perform(function() {
                    try {
                        const Build = Java.use("android.os.Build");
                        // Anti-emulator spoofs
                        Build.FINGERPRINT.value = "samsung/beyond1qltexx/beyond1q:10/QP1A.190711.020/G973FXXU8FUE5:user/release-keys";
                        Build.MODEL.value = "SM-G973F";  // Non-emulator, non-FireTV
                        Build.MANUFACTURER.value = "samsung";
                        Build.BRAND.value = "samsung";
                        Build.DEVICE.value = "beyond1q";
                        Build.HARDWARE.value = "exynos9820";
                        Build.PRODUCT.value = "beyond1qltexx";
                        Build.BOARD.value = "beyond1q";
                        Build.HOST.value = "HW1A";
                        Build.ID.value = "QP1A.190711.020";
                        // Anti-root spoofs
                        Build.TAGS.value = "release-keys";
                        Build.TYPE.value = "user";
                        log(LOG_LEVEL.INFO, "[+] Build properties spoofed (anti-emulator/root)");
                    } catch (e) {
                        log(LOG_LEVEL.WARN, "[-] Build spoof failed:", e);
                    }
                });

                // SystemProperties
                delayedHook("android.os.SystemProperties", "get", function(key) {
                    if (ROOT_PROPERTIES.has(key)) {
                        return ROOT_PROPERTIES.get(key);
                    }
                    if (key.includes("qemu") || key.includes("goldfish") || key.includes("sdk") || key.includes("generic") || key.includes("emulator")) {
                        return "0";  // Or empty string
                    }
                    return this.get(key);
                });

                // File Operations
                delayedHook("java.io.File", "exists", function() {
                    const path = this.getAbsolutePath();
                    if (ROOT_FILES.some(rf => path.includes(rf))) {
                        return false;
                    }
                    return this.exists();
                });

                delayedHook("java.io.File", "canExecute", function() {
                    const path = this.getAbsolutePath();
                    if (ROOT_FILES.some(rf => path.includes(rf))) {
                        return false;
                    }
                    return this.canExecute();
                });

                // Runtime.exec
                const execOverloads = [
                    "[Ljava.lang.String;",
                    "java.lang.String"
                ];
                delayedHook("java.lang.Runtime", "exec", function(...args) {
                    let cmd = Array.isArray(args[0]) ? args[0][0] : args[0];
                    cmd = cmd.toString().toLowerCase();
                    if (ROOT_BINARIES.has(cmd.split(' ')[0]) || cmd.includes("su") || cmd.includes("root") || cmd.includes("magisk")) {
                        return this.exec("echo 'non-root'");
                    }
                    return this.exec.apply(this, args);
                }, execOverloads);

                // ProcessBuilder
                delayedHook("java.lang.ProcessBuilder", "start", function() {
                    const cmd = this.command().toString();
                    if (ROOT_BINARIES.has(cmd.split(' ')[0]) || cmd.includes("su")) {
                        this.command(["echo", "non-root"]);
                    }
                    return this.start();
                });

                // Targeted JioTV Hooks
                delayedHook("com.jio.jioplay.tv.utils.CommonUtils", "isRooted", function() {
                    console.log("[+] Bypassing JioTV CommonUtils.isRooted()");
                    return false;
                });

                // New: Bypass isRunningOnEmulator
                delayedHook("com.jio.media.tv.ui.permission_onboarding.PermissionActivity", "isRunningOnEmulator", function() {
                    console.log("[+] Bypassing JioTV isRunningOnEmulator()");
                    return false;
                });

                // New: Bypass isSupportedDevice (for emulator/FireTV)
                delayedHook("com.jio.media.tv.ui.permission_onboarding.PermissionActivity", "isSupportedDevice", function() {
                    console.log("[+] Bypassing JioTV isSupportedDevice()");
                    return true;  // Force supported
                });

                // Softened Native hooks (only if stable)
                setTimeout(function() {
                    try {
                        const fopen = Module.findExportByName("libc.so", "fopen");
                        if (fopen && fopen.isValid()) {
                            Interceptor.attach(fopen, {
                                onEnter: function(args) {
                                    try {
                                        this.filePath = args[0].readUtf8String();
                                    } catch (e) {
                                        this.filePath = "";
                                    }
                                },
                                onLeave: function(retval) {
                                    if (retval.toInt32() !== 0 && this.filePath && ROOT_FILES.some(path => this.filePath.includes(path))) {
                                        retval.replace(ptr(0));
                                    }
                                }
                            });
                            log(LOG_LEVEL.INFO, "[+] Native fopen hooked (soft)");
                        }
                    } catch (e) {
                        // Ignore to prevent crash
                    }

                    try {
                        const access = Module.findExportByName("libc.so", "access");
                        if (access && access.isValid()) {
                            Interceptor.attach(access, {
                                onEnter: function(args) {
                                    try {
                                        this.filePath = args[0].readUtf8String();
                                    } catch (e) {
                                        this.filePath = "";
                                    }
                                },
                                onLeave: function(retval) {
                                    if (retval.toInt32() === 0 && this.filePath && ROOT_FILES.some(path => this.filePath.includes(path))) {
                                        retval.replace(ptr(-1));
                                    }
                                }
                            });
                            log(LOG_LEVEL.INFO, "[+] Native access hooked (soft)");
                        }
                    } catch (e) {
                        // Ignore
                    }
                }, 2000);  // Delay native hooks to avoid early crash

                // PackageManager
                delayedHook("android.content.pm.PackageManager", "getInstalledPackages", function(flags) {
                    const pkgs = this.getInstalledPackages(flags);
                    const filtered = Java.cast(pkgs.toArray(), Java.array('android.content.pm.PackageInfo')).filter(pkg => !ROOT_PACKAGES.includes(pkg.packageName));
                    return Java.array('android.content.pm.PackageInfo', filtered);
                }, [["int"]]);  // Overload for int flags

                delayedHook("android.content.pm.PackageManager", "getPackageInfo", function(pkg, flags) {
                    if (ROOT_PACKAGES.includes(pkg)) {
                        throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                    }
                    return this.getPackageInfo(pkg, flags);
                }, [["java.lang.String", "int"]]);  // Fixed overload

                bypassStatus.root = true;
                bypassStatus.emulator = true;
                log(LOG_LEVEL.INFO, "[+] Root/Emulator Bypass setup completed");
                return true;
            } catch(e) {
                log(LOG_LEVEL.ERROR, "[-] Root/Emulator Bypass setup failed:", e);
                return false;
            }
        }

        // Setup
        function setupBypass() {
            const results = {
                ssl: setupSSLBypass(),
                root: setupRootBypass()
            };
            log(LOG_LEVEL.INFO, "\n[*] Bypass Status: " + JSON.stringify(results));
            return results;
        }

        setupBypass();

        // Debugger bypass (last, to avoid interference)
        delayedHook("android.os.Debug", "isDebuggerConnected", function() {
            return false;
        });

    });
}, 0);