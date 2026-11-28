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

// Exact Java root targets verified against TMAP driver version codes 176 and 177.
private object TmapSecurityHooks {
    // Ten paths in qh.n.a, plus the pre-existing exact Magisk path.
    val rootPaths = setOf(
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su", "/data/adb/magisk"
    )
    private val installed = HashSet<Method>()
    private val diagnosticRoots = java.util.concurrent.ConcurrentHashMap.newKeySet<Method>()
    private data class ApplicationRootContract(
        val versionCode: Long, val ownerName: String, val interfaceName: String, val selector: Int
    )
    private data class ApplicationRootLayout(
        val contract: ApplicationRootContract, val branch: java.lang.reflect.Field
    )
    private val applicationRootContracts = listOf(
        ApplicationRootContract(176L, "of.a", "wi.a", 3),
        ApplicationRootContract(177L, "sg.b", "gj.a", 7)
    )
    private val applicationRoots = java.util.concurrent.ConcurrentHashMap<Method, ApplicationRootLayout>()
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

    fun installApplicationRoots(module: ModuleMain, classLoader: ClassLoader) {
        for (contract in applicationRootContracts) {
            try {
                val owner = Class.forName(contract.ownerName, false, classLoader)
                installApplicationRoot(module, owner)
            } catch (error: Throwable) {
                log("unsupported ${contract.ownerName}.invoke() application root branch type=${error.javaClass.name}")
            }
        }
    }

    @Synchronized fun installApplicationRoot(module: ModuleMain, owner: Class<*>) {
        val contract = applicationRootContracts.singleOrNull { it.ownerName == owner.name }
            ?: throw IllegalArgumentException("Unverified application root owner")
        require(Modifier.isFinal(owner.modifiers) && !Modifier.isAbstract(owner.modifiers) &&
            owner.superclass == Any::class.java && owner.interfaces.size == 1 &&
            owner.interfaces.single().name == contract.interfaceName) { "Unexpected application root owner" }
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
            log("already installed ${contract.ownerName}.invoke() application root branch")
            return
        }
        method.isAccessible = true
        branch.isAccessible = true
        // Publish before hook activation. Registration and rollback share this monitor.
        applicationRoots[method] = ApplicationRootLayout(contract, branch)
        try {
            module.hook(method, TmapApplicationRootHooker::class.java)
            installed.add(method)
        } catch (error: Throwable) {
            applicationRoots.remove(method)
            throw error
        }
        log("installed ${contract.ownerName}.invoke() root branch a=${contract.selector}; other branches preserved")
    }

    private fun targetVersion(): Long? {
        // onPackageLoaded can precede Application creation. Check here, never at installation,
        // and do not cache an early null context or a temporary package lookup failure.
        return try {
            val context = ModuleMain.getApplicationContext() ?: return null
            if (context.packageName != ModuleMain.TMAP_PACKAGE) return null
            context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode
        } catch (_: Throwable) {
            null
        }
    }

    fun diagnosticRootResult(callback: XposedInterface.AfterHookCallback) {
        try {
            if (callback.throwable != null || callback.result !is Boolean || callback.result != true ||
                callback.args.isNotEmpty() || callback.member !in diagnosticRoots) return
            if (targetVersion() !in setOf(176L, 177L)) {
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
            val layout = applicationRoots[method] ?: return
            val receiver = callback.thisObject ?: return
            if (receiver.javaClass !== method.declaringClass ||
                layout.branch.getInt(receiver) != layout.contract.selector) return
            if (targetVersion() != layout.contract.versionCode) {
                log("application root result preserved: target package/version unavailable or unsupported")
                return
            }
            callback.result = false
            log("changed application root branch ${layout.contract.ownerName}.invoke() a=${layout.contract.selector} true->false")
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
        private data class Contract(val method: Method, val wrapper: Class<*>, val ticket: Class<*>)
        @Volatile private var contract: Contract? = null

        fun configure(method: Method, wrapper: Class<*>, ticket: Class<*>) {
            contract = Contract(method, wrapper, ticket)
        }

        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                if (callback.throwable != null) return
                val expected = contract ?: return
                if (callback.member != expected.method) return
                val wrapper = callback.result ?: return
                if (wrapper.javaClass !== expected.wrapper) return
                val tickets = ModuleMain.readField(wrapper, "callList") as? List<*> ?: return
                for (ticket in tickets) {
                    if (ticket == null || ticket.javaClass !== expected.ticket) continue
                    // Both verified APKs declare literal id:J; f...id names are JADX aliases.
                    val callId = (ModuleMain.readField(ticket, "id") as? Long)
                        ?: runCatching {
                            val getter = ticket.javaClass.getDeclaredMethod("e")
                            if (getter.returnType != java.lang.Long.TYPE || Modifier.isStatic(getter.modifiers)) null
                            else getter.invoke(ticket) as? Long
                        }.getOrNull()
                        ?: continue
                    if (callId <= 0L) continue
                    val callInfo = ModuleMain.readField(ticket, "callInfo") ?: continue
                    val departure = ModuleMain.readField(callInfo, "departure")?.let { readPlaceInfoTmap(it) } ?: ""
                    val destination = ModuleMain.readField(callInfo, "destination")?.let { readPlaceInfoTmap(it) } ?: ""
                    if (destination.isBlank()) continue
                    val fare = ModuleMain.readField(callInfo, "fare") as? Int ?: continue
                    if (fare < 0) continue
                    // The verified mapper copies raw metres here; never infer units from another field.
                    val distMeter = ModuleMain.readField(callInfo, "distanceToDepartureMeter") as? Double ?: continue
                    if (!distMeter.isFinite() || distMeter < 0.0) continue
                    val callData = CallData("TMAP:$callId", departure, destination, fare, distMeter / 1000.0)
                    if (ModuleMain.matchAndAccept(callData) && TmapAcceptController.accept(ticket)) break
                }
            } catch (t: Throwable) {
                ModuleMain.module?.log("TMAP: call list processing error", t)
            }
        }

        private fun readPlaceInfoTmap(obj: Any): String {
            val addressInfo = ModuleMain.readField(obj, "addressInfo") ?: return ""
            return listOf(
                "fullAddress", "displayName", "poiName",
                "forepart", "middle", "lower", "detail", "upper"
            ).mapNotNull { key ->
                (ModuleMain.readField(addressInfo, key) as? String)?.trim()?.takeIf { it.isNotEmpty() }
            }.distinct().joinToString(" ")
        }
    }
}

internal enum class TmapAcceptPhase { LOCATION, DISPATCHED, UNKNOWN }
internal enum class TmapAcceptResult { NOT_SENT, SUCCESS, REJECTED, UNKNOWN }
internal enum class TmapAcceptFinish { IGNORED, RELEASED, SUCCESS, STALE_SUCCESS, UNKNOWN }
internal data class TmapAcceptAttempt(val token: Long, val callId: Long, val generation: Long,
                                    var phase: TmapAcceptPhase = TmapAcceptPhase.LOCATION)

internal class TmapAcceptLedger {
    private var generation = 0L
    private var enabled = false
    private var fingerprint = ""
    private var sequence = 0L
    private var pending: TmapAcceptAttempt? = null
    private val succeeded = HashSet<Long>()
    private val rejected = HashSet<Long>()

    @Synchronized fun observeSession(detecting: Boolean, conditions: String) {
        if (detecting != enabled || (detecting && conditions != fingerprint)) {
            generation++
            enabled = detecting
            fingerprint = conditions
            rejected.clear()
            // A request which may have reached the service remains reserved.
            if (pending?.phase == TmapAcceptPhase.LOCATION) pending = null
        }
    }

    @Synchronized fun blocked(): Boolean = pending != null

    @Synchronized fun begin(callId: Long): TmapAcceptAttempt? {
        if (!enabled || callId <= 0 || pending != null || callId in succeeded || callId in rejected) return null
        return TmapAcceptAttempt(++sequence, callId, generation).also { pending = it }
    }

    @Synchronized fun current(token: Long): Boolean {
        val attempt = pending ?: return false
        return attempt.token == token && enabled && attempt.generation == generation &&
                attempt.phase != TmapAcceptPhase.UNKNOWN
    }

    @Synchronized fun dispatch(token: Long): Boolean {
        val attempt = pending ?: return false
        if (!current(token) || attempt.phase != TmapAcceptPhase.LOCATION) return false
        attempt.phase = TmapAcceptPhase.DISPATCHED
        return true
    }

    @Synchronized fun cancelBeforeSend(token: Long) {
        // Caller has not opened a connection or requested its output stream.
        if (pending?.token == token && pending?.phase != TmapAcceptPhase.UNKNOWN) pending = null
    }

    @Synchronized fun finish(token: Long, result: TmapAcceptResult): TmapAcceptFinish {
        val attempt = pending ?: return TmapAcceptFinish.IGNORED
        if (attempt.token != token) return TmapAcceptFinish.IGNORED
        if (result == TmapAcceptResult.UNKNOWN) {
            if (attempt.phase == TmapAcceptPhase.LOCATION) return TmapAcceptFinish.IGNORED
            attempt.phase = TmapAcceptPhase.UNKNOWN
            return TmapAcceptFinish.UNKNOWN
        }
        if (result == TmapAcceptResult.NOT_SENT) {
            // Never clear a dispatched or unknown attempt with an unsent timeout.
            if (attempt.phase != TmapAcceptPhase.LOCATION) return TmapAcceptFinish.IGNORED
            pending = null
            return TmapAcceptFinish.RELEASED
        }
        if (attempt.phase == TmapAcceptPhase.LOCATION) return TmapAcceptFinish.IGNORED
        pending = null
        if (result == TmapAcceptResult.REJECTED) {
            if (attempt.generation == generation) rejected.add(attempt.callId)
            return TmapAcceptFinish.RELEASED
        }
        succeeded.add(attempt.callId)
        return if (enabled && attempt.generation == generation) TmapAcceptFinish.SUCCESS
               else TmapAcceptFinish.STALE_SUCCESS
    }
}

// Uses the exact interface accepted by TMAP's own last-location helper. It does
// not allocate an abstract continuation or modify a coroutine state machine.
internal class TmapLastLocationBridge private constructor(
    val versionCode: Int,
    private val repoClass: Class<*>, private val repoLocation: java.lang.reflect.Field,
    private val locationClass: Class<*>, private val singleton: java.lang.reflect.Field,
    private val delegate: java.lang.reflect.Field, private val getValue: Method,
    private val continuation: Class<*>, private val emptyContext: Any,
    private val marker: Any, private val failureClass: Class<*>,
    private val failureError: java.lang.reflect.Field, private val lastLocation: Method
) {
    fun request(repo: Any?, receive: (Any?, Throwable?) -> Unit) {
        val delivered = java.util.concurrent.atomic.AtomicBoolean(false)
        fun complete(value: Any?, error: Throwable? = null) {
            if (!delivered.compareAndSet(false, true)) return
            if (error != null) receive(null, error)
            else if (failureClass.isInstance(value)) receive(null, failureError.get(value) as Throwable)
            else if (value === marker) receive(null, IllegalStateException("InvalidLocationCompletion"))
            else receive(value, null)
        }
        try {
            val source = if (repoClass.isInstance(repo)) repoLocation.get(repo) else singleton.get(null)
            require(locationClass.isInstance(source)) { "NativeLocationRepositoryUnavailable" }
            val lazyClient = delegate.get(source) ?: error("NativeLocationClientUnavailable")
            val client = getValue.invoke(lazyClient) ?: error("NativeLocationClientUnavailable")
            val terminal = Proxy.newProxyInstance(continuation.classLoader, arrayOf(continuation)) { proxy, method, args ->
                when (method.name) {
                    "getContext" -> emptyContext
                    "resumeWith" -> { complete(args?.getOrNull(0)); null }
                    "toString" -> "TmapLastLocationCompletion"
                    "hashCode" -> System.identityHashCode(proxy)
                    "equals" -> proxy === args?.getOrNull(0)
                    else -> throw UnsupportedOperationException(method.name)
                }
            }
            val immediate = lastLocation.invoke(null, client, terminal)
            if (immediate !== marker) complete(immediate)
        } catch (error: Throwable) {
            complete(null, (error as? java.lang.reflect.InvocationTargetException)?.cause ?: error)
        }
    }

    companion object {
        fun load(loader: ClassLoader): TmapLastLocationBridge {
            fun type(name: String) = Class.forName(name, false, loader)
            // Explicit APK 177 and 176 profiles; no suffix or guessed-method search.
            val modern = runCatching { type("re.w") }.isSuccess
            val cont = type(if (modern) "xi.c" else "ni.c")
            val context = type(if (modern) "xi.h" else "ni.h")
            require(cont.isInterface && cont.declaredMethods.size == 2)
            require(cont.getMethod("getContext").returnType == context)
            require(cont.getMethod("resumeWith", Any::class.java).returnType == java.lang.Void.TYPE)
            val emptyType = type(if (modern) "xi.i" else "ni.i")
            val empty = emptyType.getDeclaredField("a").apply {
                require(Modifier.isStatic(modifiers) && type == emptyType); isAccessible = true
            }.get(null) ?: error("EmptyCoroutineContextUnavailable")
            require(context.isInstance(empty))
            val markerType = type(if (modern) "yi.a" else "oi.a")
            val suspended = markerType.getDeclaredField("a").apply {
                require(Modifier.isStatic(modifiers) && type == markerType); isAccessible = true
            }.get(null) ?: error("SuspensionMarkerUnavailable")
            val failure = type(if (modern) "ti.m" else "ji.m")
            val failureError = failure.getDeclaredField("a").apply {
                require(type == Throwable::class.java && !Modifier.isStatic(modifiers)); isAccessible = true
            }
            val repo = type("com.tmapmobility.drive.driver.data.repository.l0")
            val location = type("com.tmapmobility.drive.driver.data.repository.y0")
            val locationInterface = type("com.tmapmobility.drive.driver.data.repository.w0")
            val repoLocation = repo.getDeclaredField("locationRepository").apply {
                require(type == locationInterface && !Modifier.isStatic(modifiers)); isAccessible = true
            }
            val singleton = location.getDeclaredField("INSTANCE").apply {
                require(type == locationInterface && Modifier.isStatic(modifiers)); isAccessible = true
            }
            val lazyType = type(if (modern) "ti.h" else "ji.h")
            val delegate = location.getDeclaredField("fusedLocationClient\$delegate").apply {
                require(type == lazyType && !Modifier.isStatic(modifiers)); isAccessible = true
            }
            val getValue = lazyType.getMethod("getValue").apply { require(returnType == Any::class.java); isAccessible = true }
            val helper = type(if (modern) "c5.a" else "com.google.android.gms.internal.measurement.a4")
            val last = helper.getDeclaredMethod(if (modern) "f" else "h", type("n9.b"), cont).apply {
                require(Modifier.isStatic(modifiers) && returnType == Any::class.java); isAccessible = true
            }
            return TmapLastLocationBridge(if (modern) 177 else 176, repo, repoLocation, location, singleton, delegate, getValue,
                cont, empty, suspended, failure, failureError, last)
        }
    }
}

internal object TmapAcceptController {
    @Volatile var repoInstance: Any? = null
    private val ledger = TmapAcceptLedger()
    private val handler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }
    @Volatile private var bridge: TmapLastLocationBridge? = null
    private var conditionReceiver: android.content.BroadcastReceiver? = null
    private var initialized = false

    @Synchronized fun init(classLoader: ClassLoader) {
        if (initialized) return
        try {
            val native = TmapLastLocationBridge.load(classLoader)
            val repo = Class.forName("com.tmapmobility.drive.driver.data.repository.l0", false, classLoader)
            for (constructor in repo.declaredConstructors) {
                constructor.isAccessible = true
                ModuleMain.module?.hook(constructor, TmapRepoConstructorHooker::class.java)
            }
            bridge = native
            initialized = true
            ensureConditionObserver()
            ModuleMain.module?.log("TMAP: exact 176/177 native last-location source configured; acceptance uses one POST")
        } catch (error: Throwable) {
            bridge = null
            ModuleMain.module?.log("TMAP: native last-location bindings unavailable; acceptance disabled type=${error.javaClass.simpleName}")
        }
    }

    private fun fingerprint() = ConditionClient.current().toString() +
        ":${CallKindFilter.allowDaeri}:${CallKindFilter.allowTaksong}" +
        ":${TaksongDateFilter.allowToday}:${TaksongDateFilter.allowTomorrow}"

    private fun refreshSession() = ledger.observeSession(ConditionClient.isDetecting(), fingerprint())

    @android.annotation.SuppressLint("UnspecifiedRegisterReceiverFlag")
    @Synchronized private fun ensureConditionObserver(): Boolean {
        if (conditionReceiver != null) return true
        val context = ModuleMain.getApplicationContext() ?: return false
        val observer = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != ConditionBridgeReceiver.ACTION_DELIVER_CONDITIONS) return
                if (!intent.getBooleanExtra(ConditionProvider.KEY_DETECTING, false)) ledger.observeSession(false, "")
                // ConditionClient applies the payload in its existing receiver.
                handler.post { refreshSession() }
            }
        }
        return try {
            val filter = android.content.IntentFilter(ConditionBridgeReceiver.ACTION_DELIVER_CONDITIONS)
            if (android.os.Build.VERSION.SDK_INT >= 33) context.registerReceiver(observer, filter, Context.RECEIVER_EXPORTED)
            else context.registerReceiver(observer, filter)
            conditionReceiver = observer
            true
        } catch (error: Throwable) {
            ModuleMain.module?.log("TMAP: condition observer unavailable type=${error.javaClass.simpleName}")
            false
        }
    }

    // true stops this list scan for a reserved/in-flight/unknown request.
    // Local preflight failures keep detection ON and permit another candidate.
    fun accept(ticket: Any): Boolean {
        val native = bridge ?: return false
        if (!ensureConditionObserver()) return false
        refreshSession()
        if (ledger.blocked()) return true
        val callId = extractCallId(ticket) ?: return skipped("CALL_ID_UNAVAILABLE")
        val context = ModuleMain.getApplicationContext() ?: return skipped("APPLICATION_UNAVAILABLE")
        if (!supportedHost(context, native.versionCode)) return skipped("UNSUPPORTED_PACKAGE_OR_VERSION")
        val prefs = context.getSharedPreferences("app_pref", Context.MODE_PRIVATE)
        val identity = credentials(prefs) ?: return skipped("CREDENTIALS_UNAVAILABLE")
        val attempt = ledger.begin(callId) ?: return ledger.blocked()
        if (!handler.post {
            refreshSession()
            if (ledger.current(attempt.token)) {
                native.request(repoInstance) { value, error ->
                    handler.post { locationReady(attempt, ticket, identity, value as? Location, error) }
                }
                handler.postDelayed({
                    if (ledger.finish(attempt.token, TmapAcceptResult.NOT_SENT) == TmapAcceptFinish.RELEASED)
                        ModuleMain.module?.log("TMAP: acceptance not sent reason=LOCATION_TIMEOUT")
                }, 5000L)
            }
        }) {
            ledger.finish(attempt.token, TmapAcceptResult.NOT_SENT)
            return false
        }
        return true
    }

    private data class Credentials(val driverId: Long, val token: String)

    private fun skipped(reason: String): Boolean {
        ModuleMain.module?.log("TMAP: acceptance not sent reason=$reason")
        return false
    }

    @Suppress("DEPRECATION")
    private fun supportedHost(context: Context, expectedVersion: Int): Boolean = try {
        context.packageName == "com.tmapmobility.drive.driver" && expectedVersion in setOf(176, 177) &&
            context.packageManager.getPackageInfo(context.packageName, 0).versionCode == expectedVersion
    } catch (_: Throwable) { false }

    private fun credentials(prefs: SharedPreferences): Credentials? = try {
        // Read the exact native keys afresh for each attempt; no user-key scan or ID cache.
        val raw = prefs.all["driverId"]
        val driver = when (raw) {
            is String -> raw.trim().toLongOrNull()
            is Long -> raw
            is Int -> raw.toLong()
            else -> null
        } ?: 0L
        val token = (prefs.all["accessToken"] as? String)?.trim().orEmpty()
        if (driver > 0L && token.isNotEmpty()) Credentials(driver, token) else null
    } catch (_: Throwable) { null }

    private fun locationReady(attempt: TmapAcceptAttempt, ticket: Any, identity: Credentials,
                              location: Location?, error: Throwable?) {
        refreshSession()
        if (!ledger.current(attempt.token)) return
        try {
            require(error == null && location != null) { "NativeLocationUnavailable" }
            val latitude = location.latitude
            val longitude = location.longitude
            require(latitude.isFinite() && longitude.isFinite() && latitude in -90.0..90.0 && longitude in -180.0..180.0)
            require(latitude != 0.0 || longitude != 0.0) { "NativeLocationZero" }
            val context = ModuleMain.getApplicationContext() ?: error("ApplicationUnavailable")
            require(supportedHost(context, bridge?.versionCode ?: -1)) { "UnsupportedPackageOrVersion" }
            val fresh = credentials(context.getSharedPreferences("app_pref", Context.MODE_PRIVATE))
            require(fresh == identity) { "AccountChangedBeforeDispatch" }
            val body = requestBody(ticket, latitude, longitude)
            if (!ledger.dispatch(attempt.token)) return
            try {
                Thread({ post(attempt, identity, body) }, "TMAP-Accept").start()
            } catch (_: Throwable) {
                // Conservatively retain the dispatched reservation if thread launch is uncertain.
                ledger.finish(attempt.token, TmapAcceptResult.UNKNOWN)
            }
        } catch (problem: Throwable) {
            ledger.finish(attempt.token, TmapAcceptResult.NOT_SENT)
            ModuleMain.module?.log("TMAP: acceptance not sent type=${problem.javaClass.simpleName}")
        }
    }

    internal fun requestBody(ticket: Any, latitude: Double, longitude: Double): String {
        val info = readFieldAny(ticket, "callInfo")
        val buyer = (readFieldAny(info, "buyer") as? Enum<*>)?.name
        val paymentInfo = readFieldAny(info, "paymentInfo")
        val payment = readFieldAny(paymentInfo, "paymentType")
        require(payment == null || (payment is Enum<*> && payment.name in setOf("APP", "CASH")))
        val from = readFieldAny(ticket, "acceptFrom") as? Enum<*> ?: error("MissingAcceptFrom")
        require(from.name in setOf("CALLLIST", "CARD", "CARD_BOOSTER_HONEY", "CARD_BOOSTER_PREFER", "UNKNOWN"))
        val fare = if (info == null) null else readFieldAny(info, "fare") as? Int ?: error("MissingFare")
        val bonus = readFieldAny(info, "bonusCallExternalId")
        require(bonus == null || bonus is String)
        return org.json.JSONObject()
            .put("callType", if (buyer == "INSOURCING" || buyer == "CORPORATE") "INSOURCING" else "TMAP")
            .put("currentCoordinate", org.json.JSONObject().put("latitude", latitude).put("longitude", longitude))
            .put("tester", false)
            .put("paymentType", (payment as? Enum<*>)?.name ?: org.json.JSONObject.NULL)
            .put("paymentFare", fare ?: org.json.JSONObject.NULL)
            .put("acceptFrom", from.name)
            .put("bonusCallExternalId", bonus ?: org.json.JSONObject.NULL)
            .toString()
    }

    private fun post(attempt: TmapAcceptAttempt, identity: Credentials, body: String) {
        var connection: java.net.HttpURLConnection? = null
        var outcome = TmapAcceptResult.UNKNOWN
        var code: Int? = null
        try {
            // An OFF/new session before the worker starts must not dispatch.
            refreshSession()
            if (!ledger.current(attempt.token)) {
                ledger.cancelBeforeSend(attempt.token)
                return
            }
            val context = ModuleMain.getApplicationContext()
            if (context == null || !supportedHost(context, bridge?.versionCode ?: -1) ||
                credentials(context.getSharedPreferences("app_pref", Context.MODE_PRIVATE)) != identity) {
                ledger.cancelBeforeSend(attempt.token)
                return
            }
            val url = "https://drive-pub.tmobiapi.com/call-api/v1/drive/drivers/${identity.driverId}/calls/${attempt.callId}/accept"
            connection = java.net.URL(url).openConnection() as java.net.HttpURLConnection
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 8000
            connection.readTimeout = 8000
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${identity.token}")
            connection.setRequestProperty("X-User-Id", identity.driverId.toString())
            val bytes = body.toByteArray(Charsets.UTF_8)
            connection.setFixedLengthStreamingMode(bytes.size)
            connection.outputStream.use { it.write(bytes) }
            code = connection.responseCode
            // Retrofit's native contract returns Unit on a successful HTTP status.
            // A 5xx or transport exception may follow a server-side effect: no retry.
            outcome = when (code) {
                in 200..299 -> TmapAcceptResult.SUCCESS
                401, 403 -> TmapAcceptResult.REJECTED
                else -> TmapAcceptResult.UNKNOWN
            }
        } catch (_: Throwable) {
            outcome = TmapAcceptResult.UNKNOWN
        } finally {
            runCatching { connection?.disconnect() }
            val finalOutcome = outcome
            val finalCode = code
            handler.post {
                refreshSession()
                val context = ModuleMain.getApplicationContext()
                if (context == null || !supportedHost(context, bridge?.versionCode ?: -1) ||
                    credentials(context.getSharedPreferences("app_pref", Context.MODE_PRIVATE)) != identity)
                    ledger.observeSession(false, "")
                val result = ledger.finish(attempt.token, finalOutcome)
                ModuleMain.module?.log("TMAP: acceptance outcome=$finalOutcome status=$finalCode sessionResult=$result")
                if (result == TmapAcceptFinish.SUCCESS) {
                    ConditionClient.stopDetecting("tmap_accept_confirmed")
                    // Preserve the previous matched-call foreground behavior, after success.
                    handler.postDelayed({ ModuleMain.bringAppToFront("com.tmapmobility.drive.driver") }, 450L)
                }
            }
        }
    }

    fun extractCallId(ticket: Any): Long? {
        val value = readFieldAny(ticket, "id") as? Long
            ?: runCatching { ticket.javaClass.getMethod("e").takeIf {
                it.parameterCount == 0 && it.returnType == java.lang.Long.TYPE
            }?.invoke(ticket) as? Long }.getOrNull()
        return value?.takeIf { it > 0L }
    }

    fun readFieldAny(obj: Any?, name: String): Any? {
        var type: Class<*>? = obj?.javaClass
        while (type != null && type != Any::class.java) {
            try { return type.getDeclaredField(name).apply { isAccessible = true }.get(obj) }
            catch (_: NoSuchFieldException) { type = type.superclass }
        }
        return null
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
    // In verified versions 176/177, lb.g.i() is the root diagnostic.
    // Emulator diagnostics and string helpers are not root endpoints.
    try {
        val owner = Class.forName("lb.g", false, classLoader)
        TmapSecurityHooks.installDiagnosticRoot(module, owner)
    } catch (error: Throwable) {
        TmapSecurityHooks.log("unsupported lb.g.i()Z root diagnostic type=${error.javaClass.name}")
    }
    TmapSecurityHooks.installApplicationRoots(module, classLoader)
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
    val module = ModuleMain.module ?: return
    try {
        // Select one verified contract. A present but mismatched v177 mapper fails closed.
        val mapperClass = try {
            Class.forName("re.x", false, classLoader)
        } catch (_: ClassNotFoundException) {
            Class.forName("me.x", false, classLoader)
        }
        val prefix = if (mapperClass.name == "re.x") "re" else "me"
        val dtoClass = Class.forName(if (prefix == "re") "ye.l0" else "te.l0", false, classLoader)
        val wrapperClass = Class.forName("$prefix.m", false, classLoader)
        val ticketClass = Class.forName("$prefix.w", false, classLoader)
        val mapMethod = mapperClass.getDeclaredMethod("b", dtoClass)
        require(Modifier.isStatic(mapMethod.modifiers) && mapMethod.returnType == wrapperClass &&
                !Modifier.isAbstract(mapMethod.modifiers) && !Modifier.isNative(mapMethod.modifiers)) {
            "Unsupported TMAP list mapper signature"
        }
        mapMethod.isAccessible = true
        TmapCallListHooker.configure(mapMethod, wrapperClass, ticketClass)
        module.hook(mapMethod, TmapCallListHooker::class.java)
        module.log("TMAP: call list hook installed ${mapperClass.name}.b(${dtoClass.name}):${wrapperClass.name}")
    } catch (t: Throwable) {
        module.log("TMAP: call list hook FAILED: ${t.javaClass.simpleName}: ${t.message}", t)
    }
}

// ========================================================================
// 아이드라이브 훅 설치 (최종 수정)
