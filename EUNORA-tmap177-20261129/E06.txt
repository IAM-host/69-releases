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
import java.util.Map

internal fun ModuleMain.installIdriveGpsSpoof(classLoader: ClassLoader) {
    try {
        val locationClass = Class.forName("android.location.Location", false, classLoader)
        val getLat = locationClass.getMethod("getLatitude")
        val getLng = locationClass.getMethod("getLongitude")
        ModuleMain.module?.hook(getLat, GpsLatitudeHooker::class.java)
        ModuleMain.module?.hook(getLng, GpsLongitudeHooker::class.java)
        ModuleMain.module?.log("IDRIVE: GPS spoof hooks installed (Location)")
    } catch (t: Throwable) {
        ModuleMain.module?.log("IDRIVE: GPS spoof hook FAILED", t)
    }
}
// BEGIN IDRIVE_OVERLAY_DATA
internal object IdriveOverlayData {
    private val distancePattern = Regex("""^(\d+(?:\.\d+)?|\.\d+)\s*(km|m)?$""", RegexOption.IGNORE_CASE)
    private val submittedOverlays = java.util.WeakHashMap<Any, Boolean>()

    @Synchronized fun reserveOverlay(overlay: Any): Boolean {
        if (submittedOverlays.containsKey(overlay)) return false
        submittedOverlays[overlay] = true
        return true
    }

    fun parseDistanceKm(raw: String?): Double {
        val match = distancePattern.matchEntire(raw?.trim()?.replace(",", "").orEmpty()) ?: return 0.0
        val value = match.groupValues[1].toDoubleOrNull()?.takeIf { it.isFinite() && it >= 0.0 } ?: return 0.0
        return if (match.groupValues[2].equals("m", ignoreCase = true)) value / 1000.0 else value
    }

    fun findAcceptMethod(channelClass: Class<*>, replyClass: Class<*>): Method {
        require(replyClass.isInterface) { "IDRIVE: expected native MethodChannel result interface" }
        return channelClass.getMethod("i", String::class.java, Any::class.java, replyClass).apply {
            require(returnType == Void.TYPE) { "IDRIVE: unexpected native accept method return type" }
            isAccessible = true
        }
    }

    fun buildCallData(map: kotlin.collections.Map<*, *>, view: Any): CallData {
        val num = map["num"]?.toString() ?: map["id"]?.toString() ?: ""
        // The native show payload usually has no order ID; the fallback identifies this view only.
        val localKey = num.takeIf { it.isNotBlank() } ?: "overlay:${System.identityHashCode(view)}"
        return CallData(
            "IDRIVE:$localKey", map["start"] as? String ?: "", map["arrive"] as? String ?: "",
            ModuleMain.parseFareAnyFormat(map["fee"]?.toString()),
            parseDistanceKm(map["distance"]?.toString())
        )
    }

    // The live hook and the local recorder share this path. Only the caller supplies the sink.
    fun processOverlay(
        map: kotlin.collections.Map<*, *>, view: Any,
        match: (CallData) -> Boolean, reserve: (Any) -> Boolean,
        submit: (String, String) -> Unit, log: (String, Throwable?) -> Unit
    ) {
        val callData = buildCallData(map, view)
        log("IDRIVE: overlay start=${callData.origin} arrive=${callData.destination} " +
                "fee=${map["fee"]} distance=${map["distance"]} num=${map["num"] ?: map["id"] ?: ""}", null)
        if (callData.destination.isBlank() && callData.origin.isBlank()) return
        if (!match(callData)) return
        if (!reserve(view)) {
            log("IDRIVE: overlay skipped reason=ALREADY_SUBMITTED", null)
            return
        }
        log("IDRIVE: overlay matched localKey=${callData.callId.removePrefix("IDRIVE:")}", null)
        try {
            submit("overlayAction", "accept")
            log("IDRIVE: overlay accept submitted; server result not yet confirmed", null)
        } catch (error: Throwable) {
            // Keep this view reserved: an invocation error cannot prove no action was sent.
            log("IDRIVE: overlay accept unconfirmed", error)
        }
    }
}
// END IDRIVE_OVERLAY_DATA

internal fun ModuleMain.installIdriveOrderListHook(classLoader: ClassLoader) {
    var installed = false
    try {
        val overlayClass = Class.forName("X0.a", false, classLoader)
        val bClass = Class.forName("A2.b", false, classLoader)
        val replyClass = Class.forName("c3.o", false, classLoader)
        val acceptMethod = IdriveOverlayData.findAcceptMethod(bClass, replyClass)
        val overlayView = overlayClass.getDeclaredField("d").apply { isAccessible = true }
        require(overlayView.type == android.widget.LinearLayout::class.java) { "IDRIVE: unexpected native overlay view field" }
        IdriveOverlayHooker.configure(acceptMethod, overlayView)
        val overlayMethod = overlayClass.getDeclaredMethod("O", Context::class.java, bClass, Map::class.java)
        overlayMethod.isAccessible = true
        val module = ModuleMain.module ?: error("IDRIVE: module unavailable")
        module.hook(overlayMethod, IdriveOverlayHooker::class.java)
        installed = true
        module.log("IDRIVE: X0.a.O overlay hook installed")
    } catch (t: Throwable) {
        ModuleMain.module?.log("IDRIVE: overlay hook FAILED", t)
    }
    // No native overlay is created and no real channel is passed to this diagnostic.
    runCatching { IdriveOverlayDiagnostics.start(installed) }.onFailure {
        ModuleMain.module?.log("IDRIVE_DIAG: startup diagnostic failed", it)
    }
}

@XposedHooker
class IdriveOverlayHooker : XposedInterface.Hooker {
    companion object {
        @Volatile private var acceptMethod: Method? = null
        @Volatile private var overlayView: java.lang.reflect.Field? = null

        fun configure(method: Method, viewField: java.lang.reflect.Field) {
            acceptMethod = method
            overlayView = viewField
        }

        private fun log(message: String, error: Throwable? = null) {
            if (error == null) ModuleMain.module?.log(message)
            else ModuleMain.module?.log(message, error)
        }

        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                // Record entry before the old silent gates so a failed native window is visible.
                log("IDRIVE: overlay hook fired")
                val map = callback.args.getOrNull(2) as? kotlin.collections.Map<*, *>
                if (map == null) { log("IDRIVE: overlay blocked reason=MAP_MISSING"); return }
                val viewField = overlayView
                if (viewField == null) { log("IDRIVE: overlay blocked reason=VIEW_FIELD_MISSING"); return }
                val view = viewField.get(null)
                if (view == null) { log("IDRIVE: overlay blocked reason=VIEW_MISSING"); return }
                val bVar = callback.args.getOrNull(1)
                if (bVar == null) { log("IDRIVE: overlay blocked reason=CHANNEL_MISSING"); return }
                val iMethod = acceptMethod
                if (iMethod == null) { log("IDRIVE: overlay blocked reason=METHOD_MISSING"); return }
                if (!iMethod.declaringClass.isInstance(bVar)) {
                    log("IDRIVE: overlay blocked reason=CHANNEL_TYPE_MISMATCH"); return
                }
                IdriveOverlayData.processOverlay(
                    map, view, ModuleMain::matchAndAccept, IdriveOverlayData::reserveOverlay,
                    { method, action -> iMethod.invoke(bVar, method, action, null); Unit }, ::log
                )
            } catch (t: Throwable) {
                log("IDRIVE: overlay hook error", t)
            }
        }
    }
}

// A bounded startup check with a recorder-only sink. It cannot send to the native channel.
internal object IdriveOverlayDiagnostics {
    private const val BUILD = "20261112.1"
    private val started = java.util.concurrent.atomic.AtomicBoolean(false)

    private fun log(message: String) {
        val text = "IDRIVE_DIAG: $message"
        ModuleMain.module?.log(text)
        android.util.Log.i("IDRIVE_DIAG", text)
    }

    fun runMockChecks(logResult: (String) -> Unit) {
        val matcher = CallMatcher()
        val sets = listOf(ConditionSet(1, MatchCondition("여서", "금호어울림", 15000, 0.6)))
        val reservations = java.util.WeakHashMap<Any, Boolean>()
        val messages = mutableListOf<Pair<String, String>>()
        var cases = 0
        fun payload(destination: String = "여서동원앙", fee: String = "15,000원", distance: String = "500M") =
            mapOf("start" to "진단출발지", "arrive" to destination, "fee" to fee, "distance" to distance)
        fun run(map: kotlin.collections.Map<*, *>, view: Any = Any(), accepted: Boolean) {
            val before = messages.size
            IdriveOverlayData.processOverlay(
                map, view, { matcher.matchAny(it, sets).matched },
                { if (reservations.containsKey(it)) false else { reservations[it] = true; true } },
                { method, action -> messages.add(method to action); Unit },
                { _, error -> if (error != null) throw error }
            )
            check(messages.size - before == if (accepted) 1 else 0) { "case ${cases + 1} outcome mismatch" }
            cases++
        }
        run(payload(), accepted = true)
        run(payload(fee = "15K", distance = "0.5KM"), accepted = true)
        run(payload(distance = "0.6KM"), accepted = true)
        run(payload(destination = "서울시청"), accepted = false)
        run(payload(destination = "여서동 금호어울림"), accepted = false)
        run(payload(fee = "14999"), accepted = false)
        run(payload(distance = "0.7KM"), accepted = false)
        run(payload(distance = ""), accepted = false)
        val repeatedView = Any()
        run(payload(), repeatedView, accepted = true)
        run(payload(), repeatedView, accepted = false)
        check(messages.all { it == ("overlayAction" to "accept") }) { "unexpected recorded action" }
        logResult("MOCK_PASS cases=$cases sink=LOCAL_RECORDER_ONLY fixture=15000won_500m " +
                "liveHookExecution=UNTESTED serverAcceptance=UNTESTED")
    }

    fun start(hookInstalled: Boolean) {
        if (!started.compareAndSet(false, true)) return
        log("BEGIN build=$BUILD overlayHookInstalled=$hookInstalled")
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        handler.post {
            runCatching { runMockChecks(::log) }.onFailure {
                log("MOCK_FAIL type=${it.javaClass.name} message=${it.message}")
            }
        }
        fun snapshot(attempt: Int) {
            try {
                val context = ModuleMain.getApplicationContext()
                val ready = ConditionClient.isReady()
                if ((context == null || !ready) && attempt < 5) {
                    handler.postDelayed({ snapshot(attempt + 1) }, 1000L)
                    return
                }
                val detecting = ConditionClient.isDetecting()
                val sets = ConditionClient.current().toList()
                val overlayAllowed = context?.let { android.provider.Settings.canDrawOverlays(it) }
                val sample = IdriveOverlayData.buildCallData(
                    mapOf("start" to "진단출발지", "arrive" to "여서동원앙", "fee" to "15000", "distance" to "500M"), Any()
                )
                val result = if (ready) CallMatcher().matchAny(sample, sets) else null
                val kindAllowed = CallKindFilter.allows(sample.origin)
                log("STATE build=$BUILD overlayHookInstalled=$hookInstalled conditionsReady=$ready " +
                        "detecting=$detecting activeSets=${sets.map { it.setNumber }} overlayAllowed=$overlayAllowed " +
                        "sampleOnly=true sampleMatched=${result?.matched} sampleKindAllowed=$kindAllowed " +
                        "reason=${result?.reasonCode ?: "CONDITIONS_NOT_READY"} detail=${result?.detail.orEmpty()}")
            } catch (error: Throwable) {
                log("STATE_FAILED type=${error.javaClass.name} message=${error.message}")
            }
        }
        handler.postDelayed({ snapshot(1) }, 1500L)
    }
}

// Exact Java root probes only; native, Flutter and server checks are separate.
private object IdriveSecurityHooks {
    val rootPaths = setOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/app/Superuser.apk", "/data/adb/magisk"
    )
    private val installed = HashSet<java.lang.reflect.Method>()

    fun log(message: String) {
        try { ModuleMain.module?.log("IDRIVE: security $message") } catch (_: Throwable) { }
    }

    @Synchronized fun install(module: ModuleMain, method: java.lang.reflect.Method,
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

    fun rootBoolean(owner: Class<*>, name: String, vararg parameters: Class<*>): java.lang.reflect.Method {
        val method = owner.getDeclaredMethod(name, *parameters)
        require(method.returnType == java.lang.Boolean.TYPE &&
            !java.lang.reflect.Modifier.isAbstract(method.modifiers) &&
            !java.lang.reflect.Modifier.isNative(method.modifiers)) {
            "Expected a concrete primitive Boolean method"
        }
        return method
    }
}

@XposedHooker
class IdriveRootPathHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable != null || callback.result !is Boolean || callback.result != true) return
            val path = (callback.thisObject as? java.io.File)?.path ?: return
            if (path !in IdriveSecurityHooks.rootPaths) return
            callback.result = false
            IdriveSecurityHooks.log("changed File.exists($path) true->false")
        }
    }
}

@XposedHooker
class IdriveRootDiagnosticHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable != null || callback.result !is Boolean || callback.result != true) return
            callback.result = false
            IdriveSecurityHooks.log("changed K1.g.g()Z SDK root diagnostic true->false")
        }
    }
}

internal fun ModuleMain.installIdriveSecurityBypass(classLoader: ClassLoader) {
    val module = ModuleMain.module ?: return
    try {
        val exists = IdriveSecurityHooks.rootBoolean(java.io.File::class.java, "exists")
        IdriveSecurityHooks.install(module, exists, IdriveRootPathHooker::class.java, "File.exists exact root paths")
    } catch (error: Throwable) {
        IdriveSecurityHooks.log("File.exists installation failed type=${error.javaClass.name}")
    }
    try {
        // Verified DEX root check in Crashlytics diagnostics; this is not proof of a service-blocking gate.
        val owner = Class.forName("K1.g", false, classLoader)
        val method = IdriveSecurityHooks.rootBoolean(owner, "g")
        require(java.lang.reflect.Modifier.isStatic(method.modifiers)) { "Expected static SDK root diagnostic" }
        IdriveSecurityHooks.install(module, method, IdriveRootDiagnosticHooker::class.java, "K1.g.g()Z SDK root diagnostic")
    } catch (error: Throwable) {
        IdriveSecurityHooks.log("unsupported K1.g.g()Z SDK root diagnostic type=${error.javaClass.name}")
    }
}

@XposedHooker
class IdriveFlutterMessageHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            try {
                val channel = callback.args.getOrNull(0) as? String ?: return
                val buffer = callback.args.getOrNull(1) as? java.nio.ByteBuffer
                val data = if (buffer != null && buffer.hasRemaining()) {
                    val bytes = ByteArray(buffer.remaining())
                    buffer.get(bytes)
                    buffer.rewind()
                    String(bytes, Charsets.UTF_8)
                } else ""
                if (data.length > 5) {
                    ModuleMain.module?.log("IDRIVE: ch=$channel len=${data.length} data=${data.take(300)}")
                }
            } catch (t: Throwable) {
                ModuleMain.module?.log("IDRIVE: Flutter msg parse error", t)
            }
        }
    }
}

internal fun ModuleMain.installIdriveFlutterHook(classLoader: ClassLoader) {
    try {
        val jniClass = Class.forName("io.flutter.embedding.engine.FlutterJNI", false, classLoader)
        val method = jniClass.getDeclaredMethod(
            "handlePlatformMessage",
            String::class.java,
            java.nio.ByteBuffer::class.java,
            Int::class.javaPrimitiveType,
            Long::class.javaPrimitiveType
        )
        method.isAccessible = true
        ModuleMain.module?.hook(method, IdriveFlutterMessageHooker::class.java)
        ModuleMain.module?.log("IDRIVE: FlutterJNI handlePlatformMessage hook installed")
    } catch (t: Throwable) {
        ModuleMain.module?.log("IDRIVE: FlutterJNI hook FAILED", t)
    }
}