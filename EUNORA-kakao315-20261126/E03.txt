package com.example.wheelprobe

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.location.Location
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface
import io.github.libxposed.api.annotations.AfterInvocation
import io.github.libxposed.api.annotations.BeforeInvocation
import io.github.libxposed.api.annotations.XposedHooker
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.util.LinkedHashSet

// Exact probes verified against TMAP driver 3.8.2.190002 (versionCode 176).
private object TmapSecurityHooks {
    // Ten paths in qh.n.a, plus the pre-existing exact Magisk path.
    val rootPaths = setOf(
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su", "/data/adb/magisk"
    )
    private val installed = HashSet<Method>()
    private val diagnosticRoots = java.util.concurrent.ConcurrentHashMap.newKeySet<Method>()
    private val applicationRoots = java.util.concurrent.ConcurrentHashMap<Method, java.lang.reflect.Field>()
    private val whichCommand = Regex("""^(\s*)(which|/system/bin/which|/system/xbin/which)(\s+)su(\s*)$""")
    private val whichExecutables = setOf("which", "/system/bin/which", "/system/xbin/which")
    private const val absentProbe = "/dev/null/eunora_su_probe"

    fun log(message: String) {
        try { ModuleMain.module?.log("TMAP: security $message") } catch (_: Throwable) { }
    }

    @Synchronized fun install(module: ModuleMain, method: Method,
                              hooker: Class<out XposedInterface.Hooker>, target: String) {
        if (installed.contains(method)) {
            log("already installed $target")
            return
        }
        method.isAccessible = true
        module.hook(method, hooker)
        installed.add(method)
        log("installed $target")
    }

    fun rootBoolean(owner: Class<*>, name: String, vararg parameters: Class<*>): Method {
        val method = owner.getDeclaredMethod(name, *parameters)
        require(method.returnType == java.lang.Boolean.TYPE &&
            !Modifier.isAbstract(method.modifiers) && !Modifier.isNative(method.modifiers)) {
            "Expected a concrete primitive Boolean method"
        }
        return method
    }

    @Synchronized fun installDiagnosticRoot(module: ModuleMain, owner: Class<*>) {
        val method = rootBoolean(owner, "i")
        require(Modifier.isStatic(method.modifiers)) { "Expected static Crashlytics root diagnostic" }
        if (installed.contains(method)) {
            log("already installed lb.g.i()Z root diagnostic")
            return
        }
        method.isAccessible = true
        diagnosticRoots.add(method)
        try {
            module.hook(method, TmapRootBooleanHooker::class.java)
            installed.add(method)
        } catch (error: Throwable) {
            diagnosticRoots.remove(method)
            throw error
        }
        log("installed lb.g.i()Z root diagnostic; target version checked at invocation")
    }

    @Synchronized fun installApplicationRoot(module: ModuleMain, owner: Class<*>) {
        require(Modifier.isFinal(owner.modifiers) && !Modifier.isAbstract(owner.modifiers) &&
            owner.interfaces.any { it.name == "wi.a" }) { "Unexpected application root owner" }
        owner.getDeclaredConstructor(java.lang.Integer.TYPE)
        val method = owner.getDeclaredMethod("invoke")
        require(method.returnType == Any::class.java && !Modifier.isStatic(method.modifiers) &&
            !Modifier.isAbstract(method.modifiers) && !Modifier.isNative(method.modifiers)) {
            "Expected concrete invoke():Object"
        }
        val branch = owner.getDeclaredField("a")
        require(owner.declaredFields.size == 1 && branch.type == java.lang.Integer.TYPE &&
            Modifier.isFinal(branch.modifiers) && !Modifier.isStatic(branch.modifiers)) {
            "Unexpected application root branch field"
        }
        if (installed.contains(method)) {
            log("already installed of.a.invoke() application root branch")
            return
        }
        method.isAccessible = true
        branch.isAccessible = true
        // Publish before hook activation. Registration and rollback share this monitor.
        applicationRoots[method] = branch
        try {
            module.hook(method, TmapApplicationRootHooker::class.java)
            installed.add(method)
        } catch (error: Throwable) {
            applicationRoots.remove(method)
            throw error
        }
        log("installed of.a.invoke() root branch a=3; other branches preserved")
    }

    private fun supportedTarget(): Boolean {
        // onPackageLoaded can precede Application creation. Check here, never at installation,
        // and do not cache an early null context or a temporary package lookup failure.
        return try {
            val context = ModuleMain.getApplicationContext() ?: return false
            context.packageName == ModuleMain.TMAP_PACKAGE &&
                context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode == 176L
        } catch (_: Throwable) {
            false
        }
    }

    fun diagnosticRootResult(callback: XposedInterface.AfterHookCallback) {
        try {
            if (callback.throwable != null || callback.result !is Boolean || callback.result != true ||
                callback.args.isNotEmpty() || callback.member !in diagnosticRoots) return
            if (!supportedTarget()) {
                log("root diagnostic result preserved: target package/version unavailable or unsupported")
                return
            }
            callback.result = false
            log("changed lb.g.i() root diagnostic true->false")
        } catch (error: Throwable) {
            log("root diagnostic result unavailable type=${error.javaClass.name}")
        }
    }

    fun applicationRootResult(callback: XposedInterface.AfterHookCallback) {
        try {
            if (callback.throwable != null || callback.result !is Boolean || callback.result != true ||
                callback.args.isNotEmpty()) return
            val method = callback.member as? Method ?: return
            val branch = applicationRoots[method] ?: return
            val receiver = callback.thisObject ?: return
            if (receiver.javaClass !== method.declaringClass || branch.getInt(receiver) != 3) return
            if (!supportedTarget()) {
                log("application root result preserved: target package/version unavailable or unsupported")
                return
            }
            callback.result = false
            log("changed application root branch of.a.invoke() a=3 true->false")
        } catch (error: Throwable) {
            log("application root result unavailable type=${error.javaClass.name}")
        }
    }

    fun rewrittenCommand(command: Any?): Any? = when (command) {
        is String -> whichCommand.matchEntire(command)?.let { match ->
            match.groupValues[1] + match.groupValues[2] + match.groupValues[3] +
                absentProbe + match.groupValues[4]
        }
        is Array<*> -> if (command.size == 2 && command[0] in whichExecutables && command[1] == "su")
            arrayOf(command[0] as String, absentProbe) else null
        else -> null
    }
}

@XposedHooker
class TmapWhichSuHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            val args = callback.args
            if (args.isEmpty()) return
            val replacement = TmapSecurityHooks.rewrittenCommand(args[0]) ?: return
            args[0] = replacement
            TmapSecurityHooks.log("changed Runtime.exec(which su) argument; other exec arguments preserved")
        }
    }
}

@XposedHooker
class TmapRootBooleanHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            TmapSecurityHooks.diagnosticRootResult(callback)
        }
    }
}

@XposedHooker
class TmapApplicationRootHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            TmapSecurityHooks.applicationRootResult(callback)
        }
    }
}

@XposedHooker
class TmapRootPathHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable != null || callback.result !is Boolean || callback.result != true) return
            val path = (callback.thisObject as? java.io.File)?.path ?: return
            if (path !in TmapSecurityHooks.rootPaths) return
            callback.result = false
            TmapSecurityHooks.log("changed File.exists($path) true->false")
        }
    }
}

@XposedHooker
class TmapVsmLocationDataCtorHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            val pair = GpsSpoofState.activeLatLng() ?: return
            val args = callback.args
            // VSMLocationData(longitude, latitude, bearing, accuracy)
            if (args.size >= 2 && args[0] is Double && args[1] is Double) {
                args[0] = pair.second
                args[1] = pair.first
            }
        }
    }
}

@XposedHooker
class TmapLocationSetLatitudeHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            val pair = GpsSpoofState.activeLatLng() ?: return
            if (callback.args.isNotEmpty()) callback.args[0] = pair.first
        }
    }
}

@XposedHooker
class TmapLocationSetLongitudeHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            val pair = GpsSpoofState.activeLatLng() ?: return
            if (callback.args.isNotEmpty()) callback.args[0] = pair.second
        }
    }
}

@XposedHooker
class TmapSimpleLocationProviderHooker : XposedInterface.Hooker {
    companion object {
        @Volatile var vsmCtor: java.lang.reflect.Constructor<*>? = null

        fun configure(ctor: java.lang.reflect.Constructor<*>) {
            vsmCtor = ctor
        }

        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            val pair = GpsSpoofState.activeLatLng() ?: return
            val ctor = vsmCtor ?: return
            try {
                val old = callback.result
                var bearing = 0f
                var accuracy = 5f
                if (old != null) {
                    try {
                        val c = old.javaClass
                        val b = c.getMethod("getBearing").invoke(old) as? Float
                        val a = c.getMethod("getAccuracy").invoke(old) as? Float
                        if (b != null) bearing = b
                        if (a != null) accuracy = a
                    } catch (_: Throwable) {
                    }
                }
                callback.result = ctor.newInstance(pair.second, pair.first, bearing, accuracy)
            } catch (_: Throwable) {
            }
        }
    }
}


@XposedHooker
class TmapRepoConstructorHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.thisObject != null) {
                TmapAcceptController.repoInstance = callback.thisObject
                ModuleMain.module?.log("TMAP: repo instance captured class=${callback.thisObject!!.javaClass.name}")
            }
        }
    }
}

@XposedHooker
class TmapCallListHooker : XposedInterface.Hooker {
    companion object {
        @Volatile private var mapperClass: Class<*>? = null; @Volatile private var dtoClass: Class<*>? = null
        fun configure(mapper: Class<*>, dto: Class<*>) { mapperClass = mapper; dtoClass = dto }
        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                val wrapper = callback.result ?: return
                val tickets = ModuleMain.readField(wrapper, "callList") as? List<*> ?: return
                for (ticket in tickets) {
                    if (ticket == null) continue
                    // APK: me.w 필드명은 R8 후 f13621id (원본 id). getter e() 도 존재
                    val callId = (
                            ModuleMain.readField(ticket, "id")
                                ?: ModuleMain.readField(ticket, "f13625id")
                                ?: ModuleMain.readField(ticket, "f13621id")
                                ?: runCatching {
                                    ticket.javaClass.getMethod("e").invoke(ticket)
                                }.getOrNull()
                            )?.toString() ?: continue
                    val callInfo = ModuleMain.readField(ticket, "callInfo") ?: continue
                    val departure = ModuleMain.readField(callInfo, "departure")?.let { readPlaceInfoTmap(it) } ?: ""
                    val destination = ModuleMain.readField(callInfo, "destination")?.let { readPlaceInfoTmap(it) } ?: ""
                    val fare = (ModuleMain.readField(callInfo, "fare") as? Number)?.toInt() ?: 0
                    // distanceToDepartureMeter / kmToDeparture / distanceToDeparture 중 사용
                    val distMeter = (ModuleMain.readField(callInfo, "distanceToDepartureMeter") as? Number)?.toDouble()
                        ?: ((ModuleMain.readField(callInfo, "kmToDeparture") as? Number)?.toDouble()?.times(1000.0))
                        ?: ((ModuleMain.readField(callInfo, "distanceToDeparture") as? Number)?.toDouble()?.times(1000.0))
                        ?: 0.0
                    val pickupKm = distMeter / 1000.0
                    val callData = CallData("TMAP:$callId", departure, destination, fare, pickupKm)
                    if (ModuleMain.matchAndAccept(callData)) {
                        TmapAcceptController.accept(ticket)
                        break
                    }
                }
            } catch (t: Throwable) {
                ModuleMain.module?.log("TMAP: call list processing error", t)
            }
        }

        /**
         * APK me.a1(LocationInfo) = coordinate + addressInfo(me.e)
         * me.e 에 fullAddress / displayName / poiName / middle / lower / detail 존재
         * (name, address, roadAddress 필드는 없음 → 예전 코드는 dest가 항상 빈 문자열)
         */
        private fun readPlaceInfoTmap(obj: Any): String {
            val addressInfo = ModuleMain.readField(obj, "addressInfo") ?: obj
            val parts = listOf(
                "fullAddress", "displayName", "poiName",
                "forepart", "middle", "lower", "detail", "upper"
            ).mapNotNull { key ->
                ModuleMain.readField(addressInfo, key)?.toString()?.trim()?.takeIf { it.isNotEmpty() }
            }
            return parts.distinct().joinToString(" ")
        }
    }
}


internal object TmapAcceptController {
    @Volatile var repoInstance: Any? = null
    @Volatile var acceptMethod: Method? = null
    @Volatile var driverId: Long = 0

    fun init(classLoader: ClassLoader) {
        try {
            val app = runCatching {
                Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication")
                    .invoke(null) as? Context
            }.getOrNull()

            if (app != null) {
                val prefs = app.getSharedPreferences("app_pref", 0)
                driverId = resolveDriverId()
            } else {
                ModuleMain.module?.log("TMAP: AcceptController Application not ready yet; driverId deferred")
            }

            // 현재 APK: l0.a(long, me.w, Continuation). 구버전 k0 도 시도
            val repoNames = listOf(
                "com.tmapmobility.drive.driver.data.repository.l0",
                "com.tmapmobility.drive.driver.data.repository.k0"
            )
            var repoClass: Class<*>? = null
            for (name in repoNames) {
                try {
                    repoClass = Class.forName(name, false, classLoader)
                    break
                } catch (_: Throwable) {
                }
            }
            if (repoClass == null) {
                ModuleMain.module?.log("TMAP: AcceptController repo class not found")
                return
            }

            for (constructor in repoClass.declaredConstructors) {
                constructor.isAccessible = true
                ModuleMain.module?.hook(constructor, TmapRepoConstructorHooker::class.java)
            }

            // a(long driverId, me.w ticket, Continuation)
            val candidates = repoClass.declaredMethods.filter { m ->
                m.parameterCount == 3 &&
                        (m.parameterTypes[0] == java.lang.Long.TYPE || m.parameterTypes[0] == java.lang.Long::class.java) &&
                        (m.parameterTypes[1].name == "me.w" || m.parameterTypes[1].name.endsWith(".w"))
            }
            for (m in candidates) {
                val p = m.parameterTypes
                ModuleMain.module?.log(
                    "TMAP: accept candidate name=${m.name} " +
                            "p0=${p[0].name} p1=${p[1].name} p2=${p[2].name} " +
                            "p2Interface=${p[2].isInterface}"
                )
            }
            acceptMethod = candidates.firstOrNull { it.parameterTypes[2].isInterface }
                ?: candidates.firstOrNull { it.parameterTypes[2].name.contains("Continuation") }
                        ?: candidates.firstOrNull { it.name == "a" }
                        ?: candidates.firstOrNull()
                        ?: repoClass.declaredMethods.firstOrNull {
                    it.name == "a" && it.parameterCount == 3
                }
            acceptMethod?.isAccessible = true

            ModuleMain.module?.log(
                "TMAP: AcceptController initialized repo=${repoClass.name} " +
                        "driverId=$driverId acceptMethod=${acceptMethod != null} " +
                        "chosen=${acceptMethod?.name} " +
                        "cont=${acceptMethod?.parameterTypes?.lastOrNull()?.name}"
            )
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: AcceptController init FAILED", t)
        }
    }


    fun readDriverIdFromPrefs(prefs: android.content.SharedPreferences): Long {
        try {
            val raw = prefs.all["driverId"]
            ModuleMain.module?.log("TMAP: prefs driverId rawType=${raw?.javaClass?.name} raw=$raw")
            when (raw) {
                is Long -> return raw
                is Int -> return raw.toLong()
                is String -> {
                    val s = raw.trim()
                    if (s.isNotEmpty()) return s.toLongOrNull() ?: 0L
                }
                is Number -> return raw.toLong()
            }
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: prefs.all driverId failed: ${t.message}")
        }
        try {
            val s = prefs.getString("driverId", null)
            ModuleMain.module?.log("TMAP: prefs.getString driverId=$s")
            if (!s.isNullOrBlank()) return s.trim().toLongOrNull() ?: 0L
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: prefs.getString failed: ${t.message}")
        }
        try {
            val l = prefs.getLong("driverId", 0L)
            ModuleMain.module?.log("TMAP: prefs.getLong driverId=$l")
            return l
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: prefs.getLong failed: ${t.message}")
        }
        return 0L
    }

    fun resolveDriverId(): Long {
        try {
            val app = Class.forName("android.app.ActivityThread")
                .getMethod("currentApplication")
                .invoke(null) as? android.content.Context
            if (app == null) {
                ModuleMain.module?.log("TMAP: resolveDriverId Application null")
                return 0L
            }
            // 기본 app_pref
            var id = readDriverIdFromPrefs(app.getSharedPreferences("app_pref", 0))
            if (id != 0L) return id
            // 다른 모드로도 시도
            id = readDriverIdFromPrefs(app.getSharedPreferences("app_pref", android.content.Context.MODE_PRIVATE))
            if (id != 0L) return id
            // 키 후보 스캔
            try {
                val prefs = app.getSharedPreferences("app_pref", 0)
                val keys = prefs.all.keys.joinToString(",")
                ModuleMain.module?.log("TMAP: app_pref keys=$keys")
                for ((k, v) in prefs.all) {
                    if (k.contains("driver", ignoreCase = true) || k.contains("user", ignoreCase = true)) {
                        ModuleMain.module?.log("TMAP: candidate key=$k type=${v?.javaClass?.name} value=$v")
                        val n = when (v) {
                            is Long -> v
                            is Int -> v.toLong()
                            is String -> v.trim().toLongOrNull()
                            is Number -> v.toLong()
                            else -> null
                        }
                        if (n != null && n != 0L) return n
                    }
                }
            } catch (t: Throwable) {
                ModuleMain.module?.log("TMAP: key scan failed: ${t.message}")
            }
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: resolveDriverId failed: ${t.message}")
        }
        return 0L
    }

    fun ensureDriverId() {
        if (driverId != 0L) return
        driverId = resolveDriverId()
        ModuleMain.module?.log("TMAP: ensureDriverId result=$driverId")
    }

    fun accept(ticket: Any) {
        ensureDriverId()
        if (driverId == 0L) {
            ModuleMain.module?.log("TMAP: Accept aborted driverId=0")
            return
        }
        try {
            val callId = extractCallId(ticket)
            if (callId == null || callId == 0L) {
                ModuleMain.module?.log("TMAP: Accept aborted callId missing ticket=${ticket.javaClass.name}")
                return
            }

            val app = Class.forName("android.app.ActivityThread")
                .getMethod("currentApplication")
                .invoke(null) as? android.content.Context
            if (app == null) {
                ModuleMain.module?.log("TMAP: Accept aborted Application null")
                return
            }
            val prefs = app.getSharedPreferences("app_pref", 0)
            val token = (
                    prefs.all["accessToken"]?.toString()
                        ?: prefs.getString("accessToken", null)
                        ?: ""
                    ).trim()
            if (token.isEmpty()) {
                ModuleMain.module?.log("TMAP: Accept aborted accessToken empty")
                return
            }

            val callInfo = readFieldAny(ticket, "callInfo") ?: ticket
            val fare = (readFieldAny(callInfo, "fare") as? Number)?.toInt()
            val paymentInfo = readFieldAny(callInfo, "paymentInfo")
            val paymentType = (
                    readFieldAny(paymentInfo, "paymentType")?.toString()
                        ?: readFieldAny(callInfo, "paymentType")?.toString()
                        ?: "APP"
                    ).let { raw ->
                    val u = raw.uppercase()
                    when {
                        u.contains("CASH") -> "CASH"
                        else -> "APP"
                    }
                }
            val acceptFrom = (
                    readFieldAny(ticket, "acceptFrom")?.toString()
                        ?: "CALLLIST"
                    ).let { raw ->
                    val name = raw.substringAfterLast('.').uppercase()
                    when {
                        name.contains("HONEY") -> "CARD_BOOSTER_HONEY"
                        name.contains("PREFER") -> "CARD_BOOSTER_PREFER"
                        name.contains("CARD") -> "CARD"
                        else -> "CALLLIST"
                    }
                }
            val bonusId = readFieldAny(callInfo, "bonusCallExternalId")?.toString()
            val buyer = readFieldAny(callInfo, "buyer")?.toString()?.uppercase() ?: ""
            val callType = if (buyer.contains("INSOURCING") || buyer.contains("CORPORATE")) {
                "INSOURCING"
            } else {
                "TMAP"
            }

            // 좌표: 가능하면 티켓/콜정보, 없으면 0
            var lat = 0.0
            var lng = 0.0
            try {
                val loc = readFieldAny(callInfo, "currentCoordinate")
                    ?: readFieldAny(ticket, "currentCoordinate")
                if (loc != null) {
                    lat = (readFieldAny(loc, "latitude") as? Number)?.toDouble() ?: 0.0
                    lng = (readFieldAny(loc, "longitude") as? Number)?.toDouble() ?: 0.0
                }
            } catch (_: Throwable) {
            }

            val fareJson = if (fare != null) fare.toString() else "null"
            val bonusJson = if (bonusId.isNullOrBlank()) "null" else "\"${bonusId.replace("\"", "")}\""
            val body =
                """{"callType":"$callType","currentCoordinate":{"latitude":$lat,"longitude":$lng},"tester":false,"paymentType":"$paymentType","paymentFare":$fareJson,"acceptFrom":"$acceptFrom","bonusCallExternalId":$bonusJson}"""

            // 수동 수락 트래픽 확정 경로
            val urlCandidates = listOf(
                "https://drive-pub.tmobiapi.com/call-api/v1/drive/drivers/$driverId/calls/$callId/accept"
            )
            ModuleMain.module?.log("TMAP: Accept API try body=$body")

            val tokenFinal = token
            val bodyFinal = body
            val callIdFinal = callId
            val driverIdFinal = driverId
            Thread {
                try {
                    var success = false
                    for (url in urlCandidates) {
                        try {
                            ModuleMain.module?.log("TMAP: Accept API POST $url")
                            val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                            conn.requestMethod = "POST"
                            conn.connectTimeout = 8000
                            conn.readTimeout = 8000
                            conn.doOutput = true
                            conn.setRequestProperty("Content-Type", "application/json")
                            conn.setRequestProperty("Accept", "application/json")
                            conn.setRequestProperty("Authorization", "Bearer $tokenFinal")
                            conn.setRequestProperty("X-User-Id", driverIdFinal.toString())
                            conn.outputStream.use { os ->
                                os.write(bodyFinal.toByteArray(Charsets.UTF_8))
                            }
                            val code = conn.responseCode
                            val resp = try {
                                val stream = if (code in 200..299) conn.inputStream else conn.errorStream
                                stream?.bufferedReader()?.readText() ?: ""
                            } catch (_: Throwable) {
                                ""
                            }
                            ModuleMain.module?.log("TMAP: Accept API response code=$code body=${resp.take(400)}")
                            if (code in 200..299) {
                                ModuleMain.module?.log("TMAP: Accepted ticket callId=$callIdFinal driverId=$driverIdFinal url=$url")
                                try {
                                    ConditionClient.stopDetecting("tmap_accept_api:$callIdFinal")
                                } catch (t: Throwable) {
                                    ModuleMain.module?.log("TMAP: stopDetecting failed: ${t.message}")
                                }
                                success = true
                                break
                            }
                            // 404면 다음 후보, 그 외(401/400 등)는 경로 맞을 수 있으니 중단하고 로그
                            if (code != 404) break
                        } catch (t: Throwable) {
                            ModuleMain.module?.log("TMAP: Accept API attempt failed: ${t.message}")
                        }
                    }
                    if (!success) {
                        ModuleMain.module?.log("TMAP: Accept API all candidates failed callId=$callIdFinal")
                    }
                } catch (t: Throwable) {
                    ModuleMain.module?.log("TMAP: Accept failed", t)
                }
            }.start()
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: Accept failed", t)
        }
    }

    fun extractCallId(ticket: Any): Long? {
        val candidates = listOf("id", "callId", "rootCallId")
        for (name in candidates) {
            val v = readFieldAny(ticket, name)
            when (v) {
                is Long -> if (v != 0L) return v
                is Int -> if (v != 0) return v.toLong()
                is Number -> if (v.toLong() != 0L) return v.toLong()
                is String -> v.toLongOrNull()?.let { if (it != 0L) return it }
            }
        }
        return null
    }

    fun readFieldAny(obj: Any?, name: String): Any? {
        if (obj == null) return null
        var cls: Class<*>? = obj.javaClass
        while (cls != null && cls != Any::class.java) {
            try {
                val f = cls.getDeclaredField(name)
                f.isAccessible = true
                return f.get(obj)
            } catch (_: Throwable) {
            }
            cls = cls.superclass
        }
        // getter
        try {
            val m = obj.javaClass.methods.firstOrNull {
                it.name.equals("get${name.replaceFirstChar { c -> c.uppercase() }}", true) && it.parameterCount == 0
            }
            if (m != null) return m.invoke(obj)
        } catch (_: Throwable) {
        }
        return null
    }

    fun buildContinuationArg(continuationType: Class<*>, classLoader: ClassLoader): Any? {
        ModuleMain.module?.log(
            "TMAP: cont meta name=${continuationType.name} " +
                    "mod=${continuationType.modifiers} interface=${continuationType.isInterface} " +
                    "abstract=${Modifier.isAbstract(continuationType.modifiers)} " +
                    "super=${continuationType.superclass?.name} " +
                    "ifaces=${continuationType.interfaces.joinToString { it.name }}"
        )
        for (c in continuationType.declaredConstructors) {
            ModuleMain.module?.log("TMAP: cont ctor params=${c.parameterTypes.joinToString { it.name }}")
        }

        val emptyCtx = runCatching {
            Class.forName("kotlin.coroutines.EmptyCoroutineContext", false, classLoader)
                .getDeclaredField("INSTANCE").apply { isAccessible = true }.get(null)
        }.getOrNull()
            ?: runCatching {
                Class.forName("kotlin.coroutines.EmptyCoroutineContext", false, continuationType.classLoader)
                    .getDeclaredField("INSTANCE").apply { isAccessible = true }.get(null)
            }.getOrNull()

        fun tryNewInstance(ctor: java.lang.reflect.Constructor<*>, args: Array<Any?>): Any? {
            return try {
                ctor.isAccessible = true
                val inst = ctor.newInstance(*args)
                ModuleMain.module?.log("TMAP: cont created via ctor params=${ctor.parameterTypes.joinToString { it.name }}")
                inst
            } catch (t: Throwable) {
                ModuleMain.module?.log("TMAP: cont ctor failed: ${t.javaClass.simpleName}: ${t.message}")
                null
            }
        }

        fun valueForType(paramType: Class<*>): Any? {
            if (emptyCtx != null && paramType.isInstance(emptyCtx)) return emptyCtx
            if (paramType.name == "kotlin.coroutines.CoroutineContext" ||
                paramType.name.endsWith(".CoroutineContext") ||
                paramType.name == "ni.c"
            ) {
                if (emptyCtx != null) {
                    if (paramType.isInstance(emptyCtx)) return emptyCtx
                    // ni.c 가 CoroutineContext 구현/별칭일 수 있음 — 할당 시도
                    try {
                        if (paramType.isAssignableFrom(emptyCtx.javaClass)) return emptyCtx
                    } catch (_: Throwable) {
                    }
                }
            }
            // Unsafe allocate for concrete/abstract param class
            val allocated = allocateWithUnsafe(paramType)
            if (allocated != null) return allocated
            // default null for last optional-ish
            return null
        }

        // 생성자로 인스턴스 생성 시도
        val ctors = continuationType.declaredConstructors.sortedBy { it.parameterCount }
        for (ctor in ctors) {
            val pts = ctor.parameterTypes
            val args = arrayOfNulls<Any>(pts.size)
            var ok = true
            for (i in pts.indices) {
                val v = valueForType(pts[i])
                if (v == null && pts[i].isPrimitive) {
                    ok = false
                    break
                }
                // abstract param without value
                if (v == null && Modifier.isAbstract(pts[i].modifiers) && !pts[i].isInterface) {
                    // still try null
                }
                args[i] = v
            }
            if (!ok) continue
            val inst = tryNewInstance(ctor, args)
            if (inst != null) return inst
        }

        // Unsafe 로 pi.c 자체 할당
        val unsafeInst = allocateWithUnsafe(continuationType)
        if (unsafeInst != null) {
            if (emptyCtx != null) {
                try {
                    var cls: Class<*>? = continuationType
                    while (cls != null && cls != Any::class.java) {
                        for (f in cls.declaredFields) {
                            if (f.type.name.contains("CoroutineContext") ||
                                f.name.contains("context", ignoreCase = true) ||
                                f.type.name == "ni.c"
                            ) {
                                f.isAccessible = true
                                f.set(unsafeInst, emptyCtx)
                                ModuleMain.module?.log("TMAP: cont field set ${f.name}")
                            }
                        }
                        cls = cls.superclass
                    }
                } catch (t: Throwable) {
                    ModuleMain.module?.log("TMAP: cont field fill failed: ${t.message}")
                }
            }
            return unsafeInst
        }

        ModuleMain.module?.log("TMAP: Accept aborted - cannot create continuation for ${continuationType.name}")
        return null
    }

    fun allocateWithUnsafe(type: Class<*>): Any? {
        try {
            val unsafeClass = Class.forName("sun.misc.Unsafe")
            var unsafe: Any? = null
            for (f in unsafeClass.declaredFields) {
                if (f.type == unsafeClass) {
                    f.isAccessible = true
                    unsafe = f.get(null)
                    break
                }
            }
            if (unsafe == null) {
                val c = unsafeClass.getDeclaredConstructor()
                c.isAccessible = true
                unsafe = c.newInstance()
            }
            val allocate = unsafeClass.getMethod("allocateInstance", Class::class.java)
            val instance = allocate.invoke(unsafe, type)
            ModuleMain.module?.log("TMAP: Unsafe allocate ok type=${type.name}")
            return instance
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: Unsafe allocate failed type=${type.name}: ${t.javaClass.simpleName}: ${t.message}")
            return null
        }
    }
}

internal fun ModuleMain.installTmapGpsSpoof(classLoader: ClassLoader) {
    ModuleMain.module?.log("TMAP: GPS spoof install start")
    try {
        val locationClass = Class.forName("android.location.Location", false, classLoader)
        ModuleMain.module?.hook(locationClass.getMethod("getLatitude"), GpsLatitudeHooker::class.java)
        ModuleMain.module?.hook(locationClass.getMethod("getLongitude"), GpsLongitudeHooker::class.java)
        try {
            ModuleMain.module?.hook(locationClass.getMethod("setLatitude", Double::class.javaPrimitiveType), TmapLocationSetLatitudeHooker::class.java)
            ModuleMain.module?.hook(locationClass.getMethod("setLongitude", Double::class.javaPrimitiveType), TmapLocationSetLongitudeHooker::class.java)
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: Location setter hook skip: ${t.message}")
        }
        try {
            ModuleMain.module?.hook(locationClass.getDeclaredMethod("isFromMockProvider"), GpsMockFalseHooker::class.java)
        } catch (_: Throwable) {
        }
        try {
            ModuleMain.module?.hook(locationClass.getDeclaredMethod("isMock"), GpsMockFalseHooker::class.java)
        } catch (_: NoSuchMethodException) {
        }

        var vsmDoubleCtor: java.lang.reflect.Constructor<*>? = null
        try {
            val vsmClass = Class.forName(
                "com.skt.tmap.vsm.location.VSMLocationData",
                false,
                classLoader
            )
            try {
                ModuleMain.module?.hook(vsmClass.getMethod("getLatitude"), GpsLatitudeHooker::class.java)
                ModuleMain.module?.hook(vsmClass.getMethod("getLongitude"), GpsLongitudeHooker::class.java)
            } catch (t: Throwable) {
                ModuleMain.module?.log("TMAP: VSMLocationData getter hook skip: ${t.message}")
            }
            for (ctor in vsmClass.declaredConstructors) {
                ctor.isAccessible = true
                if (ctor.parameterTypes.size == 4 &&
                    ctor.parameterTypes[0] == java.lang.Double.TYPE &&
                    ctor.parameterTypes[1] == java.lang.Double.TYPE
                ) {
                    vsmDoubleCtor = ctor
                    ModuleMain.module?.hook(ctor, TmapVsmLocationDataCtorHooker::class.java)
                }
            }
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: VSMLocationData hook skip: ${t.message}")
        }

        try {
            val providerClass = Class.forName(
                "com.skt.tmap.navirenderer.location.SimpleLocationProvider",
                false,
                classLoader
            )
            val getLoc = providerClass.getDeclaredMethod("getLocation")
            getLoc.isAccessible = true
            if (vsmDoubleCtor != null) {
                TmapSimpleLocationProviderHooker.configure(vsmDoubleCtor)
            }
            ModuleMain.module?.hook(getLoc, TmapSimpleLocationProviderHooker::class.java)
        } catch (t: Throwable) {
            ModuleMain.module?.log("TMAP: SimpleLocationProvider hook skip: ${t.message}")
        }

        ModuleMain.module?.log("TMAP: GPS spoof hooks installed (Location set/get + VSM + SimpleLocationProvider)")
    } catch (t: Throwable) {
        ModuleMain.module?.log("TMAP: GPS spoof hook FAILED", t)
    }
}

internal fun ModuleMain.installTmapRootChecks(classLoader: ClassLoader) {
    val module = ModuleMain.module ?: return
    try {
        val exists = TmapSecurityHooks.rootBoolean(java.io.File::class.java, "exists")
        TmapSecurityHooks.install(module, exists, TmapRootPathHooker::class.java, "File.exists exact root paths")
    } catch (error: Throwable) {
        TmapSecurityHooks.log("File.exists installation failed type=${error.javaClass.name}")
    }
    // APK 3.8.2.190002: h() is emulator diagnostics, and qh.n.a(String,String)
    // is a string helper. Neither is a root endpoint.
    try {
        val owner = Class.forName("lb.g", false, classLoader)
        TmapSecurityHooks.installDiagnosticRoot(module, owner)
    } catch (error: Throwable) {
        TmapSecurityHooks.log("unsupported lb.g.i()Z root diagnostic type=${error.javaClass.name}")
    }
    try {
        val owner = Class.forName("of.a", false, classLoader)
        TmapSecurityHooks.installApplicationRoot(module, owner)
    } catch (error: Throwable) {
        TmapSecurityHooks.log("unsupported of.a.invoke() application root branch type=${error.javaClass.name}")
    }
    try {
        val tags = android.os.Build::class.java.getDeclaredField("TAGS")
        tags.isAccessible = true
        val current = tags.get(null) as? String
        val updated = current?.replace(Regex("""(?<![\w-])test-keys(?![\w-])"""), "release-keys")
        if (current != null && updated != current) {
            tags.set(null, updated)
            if (tags.get(null) == updated) TmapSecurityHooks.log("changed Build.TAGS test-keys->release-keys; readback verified")
            else TmapSecurityHooks.log("Build.TAGS write not confirmed by readback")
        } else TmapSecurityHooks.log("Build.TAGS unchanged")
    } catch (error: Throwable) {
        TmapSecurityHooks.log("Build.TAGS write failed type=${error.javaClass.name}")
    }
    val stringArray = Array<String>::class.java
    val signatures = listOf(
        arrayOf<Class<*>>(String::class.java),
        arrayOf<Class<*>>(String::class.java, stringArray),
        arrayOf<Class<*>>(String::class.java, stringArray, java.io.File::class.java),
        arrayOf<Class<*>>(stringArray),
        arrayOf<Class<*>>(stringArray, stringArray),
        arrayOf<Class<*>>(stringArray, stringArray, java.io.File::class.java)
    )
    for (parameters in signatures) {
        val target = "Runtime.exec(" + parameters.joinToString(",") { it.simpleName } + ")"
        try {
            val method = Runtime::class.java.getDeclaredMethod("exec", *parameters)
            require(method.returnType == Process::class.java &&
                !Modifier.isAbstract(method.modifiers) && !Modifier.isNative(method.modifiers))
            TmapSecurityHooks.install(module, method, TmapWhichSuHooker::class.java, target)
        } catch (error: Throwable) {
            TmapSecurityHooks.log("unsupported $target type=${error.javaClass.name}")
        }
    }
}

internal fun ModuleMain.installTmapCallListHook(classLoader: ClassLoader) {
    try {
        // 현재 APK: me.x.b(te.l0) → me.m(CallListInfo)
        // 호출 경로: repository.m.c(...) 마지막 return me.x.b((te.l0) objB)
        val mapperClass = Class.forName("me.x", false, classLoader)
        val mapMethod = mapperClass.declaredMethods.firstOrNull { m ->
            m.name == "b" &&
                    m.parameterCount == 1 &&
                    m.parameterTypes[0].name == "te.l0" &&
                    java.lang.reflect.Modifier.isStatic(m.modifiers)
        }?.apply { isAccessible = true }
            ?: mapperClass.declaredMethods.firstOrNull { m ->
                m.name == "b" && m.parameterCount == 1 && m.parameterTypes[0].name.startsWith("te.")
            }?.apply { isAccessible = true }
            ?: throw NoSuchMethodException(
                "me.x.b methods=" +
                        mapperClass.declaredMethods.joinToString { "${it.name}/${it.parameterCount}/${it.parameterTypes.joinToString { p -> p.name }}" }
            )

        TmapCallListHooker.configure(mapperClass, mapMethod.parameterTypes[0])
        ModuleMain.module?.hook(mapMethod, TmapCallListHooker::class.java)
        ModuleMain.module?.log(
            "TMAP: call list hook installed me.x.b(${mapMethod.parameterTypes[0].name}) static=${Modifier.isStatic(mapMethod.modifiers)}"
        )
    } catch (t: Throwable) {
        ModuleMain.module?.log("TMAP: call list hook FAILED: ${t.javaClass.simpleName}: ${t.message}", t)
    }
}

// ========================================================================
// 아이드라이브 훅 설치 (최종 수정)
