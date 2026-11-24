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

// BEGIN LOGI_PACKAGE_ROUTE
internal object LogiPackageRoute {
    private const val D1 = "com.logisoft.Logi4"
    private const val D2 = "com.logisoft.Logi5"
    @Volatile private var loadedPackage: String? = null

    fun supports(packageName: String): Boolean = packageName == D1 || packageName == D2

    fun attach(packageName: String): Boolean {
        if (!supports(packageName)) return false
        loadedPackage = packageName
        return true
    }

    fun current(): String? = loadedPackage
}
// END LOGI_PACKAGE_ROUTE

// BEGIN LOGI_DATA_AND_STATE
internal object LogiOrderData {
    private val chargePattern = Regex("(?:[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+)(?:\\.[0-9]+)?")

    // ORDER.szCharge is expressed in thousands of won, not won.
    fun fareWon(raw: String): Int {
        val value = raw.trim()
        if (!chargePattern.matches(value)) return 0
        return try {
            java.math.BigDecimal(value.replace(",", ""))
                .multiply(java.math.BigDecimal(1000)).intValueExact().coerceAtLeast(0)
        } catch (_: ArithmeticException) { 0 }
        catch (_: NumberFormatException) { 0 }
    }

    // ORDER.nDistance is already in km. szKM is a status flag, never a fallback distance.
    fun distanceKm(raw: Number?): Double = raw?.toDouble()
        ?.takeIf { it.isFinite() && it > 0.0 } ?: 0.0

    fun isRealOrderId(id: Int): Boolean = id >= 10000 && id !in 99999990..99999999

    // Only explicit initial-response rejection codes prove this request did not
    // allocate. Socket errors, already-owned orders and arbitrary server text
    // leave the outcome uncertain and must retain the reservation.
    fun isDefinitiveRejection(subtype: Int?): Boolean = subtype in setOf(14, 15, 16, 21, 22, 38, 40, 49)

    fun call(
        id: Int, state: Int, origin: String, destination: String,
        charge: String, distance: Number?, kmFlag: String, denied: Boolean
    ): CallData? {
        if (!isRealOrderId(id) || state !in 0..1 || denied || kmFlag.trim() == "3") return null
        if (origin.isBlank() || destination.isBlank()) return null
        return CallData("LOGI:$id", origin, destination, fareWon(charge), distanceKm(distance))
    }

    fun isVerifiedSuccess(
        requestId: Int, responseId: Int?, marker: String?, body: String?, result: String?
    ): Boolean = isRealOrderId(requestId) && responseId == requestId &&
            !marker.isNullOrBlank() && body != null && result == marker + body
}

internal enum class LogiAcceptPhase { QUEUED, PREPARING, SENT, UNKNOWN }
internal enum class LogiAcceptResult { SUCCESS, FAILURE, UNKNOWN }
internal enum class LogiAcceptFinish { IGNORED, SUCCESS, STALE_SUCCESS, FAILURE, UNKNOWN }
internal data class LogiAcceptAttempt(
    val token: Long, val id: Int, val generation: Long,
    var phase: LogiAcceptPhase = LogiAcceptPhase.QUEUED
)

internal class LogiAcceptLedger {
    private var generation = 0L
    private var detecting = false
    private var fingerprint = ""
    private var nextToken = 0L
    private var pending: LogiAcceptAttempt? = null
    private val succeeded = LinkedHashSet<Int>()
    private val rejected = LinkedHashSet<Int>()

    @Synchronized fun observeSession(enabled: Boolean, conditions: String) {
        if (enabled != detecting || (enabled && conditions != fingerprint)) {
            generation++
            detecting = enabled
            fingerprint = conditions
            rejected.clear()
            if (pending?.phase == LogiAcceptPhase.QUEUED) pending = null
        }
    }

    @Synchronized fun canBegin(id: Int): Boolean = detecting && pending == null &&
            LogiOrderData.isRealOrderId(id) && id !in succeeded && id !in rejected

    @Synchronized fun begin(id: Int): LogiAcceptAttempt? {
        if (!canBegin(id)) return null
        return LogiAcceptAttempt(++nextToken, id, generation).also { pending = it }
    }

    @Synchronized fun prepare(token: Long): Boolean {
        val attempt = pending ?: return false
        if (!isCurrent(attempt, token) || attempt.phase != LogiAcceptPhase.QUEUED) return false
        attempt.phase = LogiAcceptPhase.PREPARING
        return true
    }

    @Synchronized fun canSend(token: Long): Boolean {
        val attempt = pending ?: return false
        return isCurrent(attempt, token) && attempt.phase == LogiAcceptPhase.PREPARING
    }

    @Synchronized fun sent(token: Long): Boolean {
        if (!canSend(token)) return false
        pending!!.phase = LogiAcceptPhase.SENT
        return true
    }

    @Synchronized fun abortUnsent(token: Long): Boolean {
        val attempt = pending ?: return false
        if (attempt.token != token || attempt.phase !in setOf(LogiAcceptPhase.QUEUED, LogiAcceptPhase.PREPARING)) return false
        pending = null
        return true
    }

    @Synchronized fun phase(token: Long): LogiAcceptPhase? = pending?.takeIf { it.token == token }?.phase

    @Synchronized fun finish(token: Long, result: LogiAcceptResult, responseId: Int? = null): LogiAcceptFinish {
        val attempt = pending ?: return LogiAcceptFinish.IGNORED
        if (attempt.token != token) return LogiAcceptFinish.IGNORED
        if (result == LogiAcceptResult.UNKNOWN) {
            if (attempt.phase == LogiAcceptPhase.QUEUED) return LogiAcceptFinish.IGNORED
            attempt.phase = LogiAcceptPhase.UNKNOWN
            return LogiAcceptFinish.UNKNOWN
        }
        if (attempt.phase != LogiAcceptPhase.SENT && attempt.phase != LogiAcceptPhase.UNKNOWN) return LogiAcceptFinish.IGNORED
        if (result == LogiAcceptResult.SUCCESS && responseId != attempt.id) {
            attempt.phase = LogiAcceptPhase.UNKNOWN
            return LogiAcceptFinish.UNKNOWN
        }
        pending = null
        if (result == LogiAcceptResult.FAILURE) {
            if (attempt.generation == generation) {
                rejected.add(attempt.id)
                while (rejected.size > 200) rejected.remove(rejected.first())
            }
            return LogiAcceptFinish.FAILURE
        }
        succeeded.add(attempt.id)
        while (succeeded.size > 200) succeeded.remove(succeeded.first())
        return if (detecting && attempt.generation == generation) LogiAcceptFinish.SUCCESS
        else LogiAcceptFinish.STALE_SUCCESS
    }

    private fun isCurrent(attempt: LogiAcceptAttempt, token: Long): Boolean =
        attempt.token == token && detecting && attempt.generation == generation
}
// END LOGI_DATA_AND_STATE

// BEGIN LOGI_ACCEPT_BINDINGS
/** Explicit layouts for the original 21.53 flow and the supplied D1 21.55/code632 DEX. */
internal class LogiAcceptBinding private constructor(
    val modern: Boolean,
    val resource: Class<*>, val host: Class<*>, val normal: Class<*>, val allocated: Class<*>,
    val service: Method, val update: Method, val reject: Method,
    val entry: Method, private val listener: java.lang.reflect.Field?,
    val foreground: Method, val floating: Method,
    private val decoderFactory: Method, private val decoder: Method,
    private val encodedSuccess: String, val okButtonId: Int,
    private val hostReady: java.lang.reflect.Field,
    private val autoAllowed: java.lang.reflect.Field,
    private val autoPanel: java.lang.reflect.Field, private val autoButton: java.lang.reflect.Field,
    private val normalProgress: java.lang.reflect.Field, private val normalId: java.lang.reflect.Field,
    private val confirmationId: java.lang.reflect.Field,
    private val confirmationCancelled: java.lang.reflect.Field, private val confirmationBusy: java.lang.reflect.Field,
    private val detailId: java.lang.reflect.Field, private val detailBody: java.lang.reflect.Field,
    val workerTypes: List<Class<*>>,
    private val directBranch: java.lang.reflect.Field?, private val directOrder: java.lang.reflect.Field?,
    private val directHost: java.lang.reflect.Field?, private val normalBranch: java.lang.reflect.Field?,
    private val normalClick: java.lang.reflect.Field?, private val clickBranch: java.lang.reflect.Field?,
    private val clickHost: java.lang.reflect.Field?
) {
    fun runtimeMatches(context: Context): Boolean {
        if (!modern) return LogiPackageRoute.supports(context.packageName)
        if (LogiPackageRoute.current() != "com.logisoft.Logi4" || context.packageName != "com.logisoft.Logi4") return false
        return try {
            val info = context.packageManager.getPackageInfo(context.packageName, 0)
            info.longVersionCode == 632L && info.versionName == "21.55"
        } catch (_: Throwable) { false }
    }

    fun hostIsReady(activity: Any): Boolean = host.isInstance(activity) && hostReady.get(activity) != null
    fun entryTarget(activity: Any): Any? = listener?.get(activity) ?: if (modern) activity else null
    fun autoOrderAllows(activity: Any, settings: Any, order: Any): Boolean {
        if (autoAllowed.getBoolean(settings)) return true
        val panel = autoPanel.get(activity) as? android.view.View ?: return false
        val button = autoButton.get(activity) as? android.view.View ?: return false
        return panel.visibility != android.view.View.VISIBLE || button.tag == null || button.tag === order
    }
    fun normalMatches(activity: Any, id: Int): Boolean = normal.isInstance(activity) && normalId.getInt(activity) == id
    fun normalIsBusy(activity: Any): Boolean = (normalProgress.get(activity) as? android.app.Dialog)?.isShowing == true
    fun confirmationMatches(activity: Any, id: Int): Boolean = allocated.isInstance(activity) &&
            confirmationId.getInt(activity) == id && !confirmationCancelled.getBoolean(activity) &&
            !confirmationBusy.getBoolean(activity)
    fun responseId(value: Any): Int = detailId.getInt(value)
    fun responseBody(value: Any): String? = detailBody.get(value) as? String
    fun successMarker(): String? = decoder.invoke(decoderFactory.invoke(null), encodedSuccess) as? String

    fun ownsWorker(worker: Any, id: Int, context: Any?): Boolean {
        if (!modern) return workerTypes.any { it == worker.javaClass }
        if (context == null) return false
        return when (worker.javaClass) {
            workerTypes[0] -> {
                val order = directOrder!!.get(worker) ?: return false
                directBranch!!.getInt(worker) == 0 && directHost!!.get(worker) === context &&
                        ((ModuleMain.readField(order, "nTNo") as? Number)?.toInt() == id)
            }
            workerTypes[1] -> {
                if (normalBranch!!.getInt(worker) != 22) false
                else normalClick!!.get(worker)?.let { click ->
                    clickHost!!.declaringClass.isInstance(click) && clickBranch!!.getInt(click) == 0 &&
                            clickHost.get(click) === context && normalMatches(context, id)
                } == true
            }
            else -> false
        }
    }

    companion object {
        private val intType = java.lang.Integer.TYPE
        private val boolType = java.lang.Boolean.TYPE
        private fun field(owner: Class<*>, name: String, type: Class<*>? = null): java.lang.reflect.Field =
            owner.getDeclaredField(name).apply {
                require(!Modifier.isStatic(modifiers) && (type == null || this.type == type)) { "LOGI field contract: $name" }
                isAccessible = true
            }
        private fun method(owner: Class<*>, name: String, result: Class<*>, static: Boolean, vararg args: Class<*>): Method =
            owner.getDeclaredMethod(name, *args).apply {
                require(returnType == result && Modifier.isStatic(modifiers) == static) {
                    "LOGI method contract: $name"
                }
                isAccessible = true
            }
        private fun viewField(owner: Class<*>, name: String): java.lang.reflect.Field = field(owner, name).apply {
            require(android.view.View::class.java.isAssignableFrom(type)) { "LOGI view contract: $name" }
        }

        fun load(loader: ClassLoader): LogiAcceptBinding {
            fun cls(name: String) = Class.forName(name, false, loader)
            val res = cls("com.logisoft.LogiD.Util.Resource")
            val order = cls("com.logisoft.LogiD.Info.ORDER")
            val host = cls("com.logisoft.LogiD.OrderFormView2_1D")
            val normal = cls("com.logisoft.LogiD.NormalAllocateDlg")
            val allocated = cls("com.logisoft.LogiD.AllocateDlg")
            val base = cls("com.logisoft.LogiD.BaseActivity")
            val modern = host.declaredFields.none { it.name == "a2" }
            if (modern) require(LogiPackageRoute.current() == "com.logisoft.Logi4") { "unverified Logi package layout" }
            val listener = if (modern) null else field(host, "a2")
            val detail = cls(if (modern) "y4.a" else "m6.a")
            val packet = cls(if (modern) "com.logisoft.LogiD.Util.t0" else "com.logisoft.LogiD.Util.l0")
            val decode = cls("com.skt.tmap.util.TMapUtil")
            val settings = res.getDeclaredField("m_si").also { require(Modifier.isStatic(it.modifiers)) }.type
            val entry = if (modern) method(host, "B", Void.TYPE, false, order, boolType)
                else method(listener!!.type, "confirmAllocOrder", Void.TYPE, false, order, boolType)
            val encrypted = if (modern) "cFfOXdghmfDC/XLPQduNTw=="
                else cls("m6.e").getDeclaredField("ORDER_SUCCESS").get(null) as String
            val ids = cls(if (modern) "com.logisoft.LogiD.q4" else "com.logisoft.LogiD.s1")
            val button = ids.getDeclaredField("btnOk").apply {
                require(type == intType && Modifier.isStatic(modifiers)); isAccessible = true
            }.getInt(null)
            require(button != 0)
            val ready = field(host, if (modern) "y1" else "R1").apply { require(!type.isPrimitive) }
            val progress = field(normal, if (modern) "o" else "p").apply {
                require(android.app.Dialog::class.java.isAssignableFrom(type))
            }
            val workers = if (modern) listOf(cls("com.logisoft.LogiD.x3"), cls("c5.e"))
                else listOf(cls("com.logisoft.LogiD.OrderFormView2_1D\$g0"), cls("com.logisoft.LogiD.NormalAllocateDlg\$b\$a"))
            workers.forEach { require(Runnable::class.java.isAssignableFrom(it)); method(it, "run", Void.TYPE, false) }
            val click = if (modern) cls("com.logisoft.LogiD.i3") else null
            return LogiAcceptBinding(modern, res, host, normal, allocated,
                method(res, "serviceAllocateDaeri", String::class.java, true, intType, Context::class.java),
                method(res, "UpdateDetailInfo", Void.TYPE, true, detail),
                method(res, "getErrorMsgFromPacket", String::class.java, true, packet), entry, listener,
                method(base, if (modern) "f" else "m", boolType, false),
                method(res, "isFloatingView", boolType, true),
                method(decode, if (modern) "a" else "I", decode, true),
                method(decode, if (modern) "decodeAndDecrypt" else "getDecode", String::class.java, false, String::class.java),
                encrypted, button, ready,
                field(settings, if (modern) "F" else "bAbleAllocateWhileAuto", boolType),
                viewField(host, if (modern) "Y" else "m0"), viewField(host, if (modern) "b0" else "p0"), progress,
                field(normal, "k", intType), field(allocated, if (modern) "r" else "w", intType),
                field(allocated, if (modern) "m" else "r", boolType), field(allocated, if (modern) "s" else "x", boolType),
                field(detail, if (modern) "a" else "nTNo", intType), field(detail, if (modern) "r" else "szNonHtml", String::class.java),
                workers, if (modern) field(workers[0], "a", intType) else null,
                if (modern) field(workers[0], "b", order) else null, if (modern) field(workers[0], "c", host) else null,
                if (modern) field(workers[1], "a", intType) else null,
                if (modern) field(workers[1], "b", Any::class.java) else null,
                if (modern) field(click!!, "a", intType) else null,
                if (modern) field(click!!, "b", normal) else null)
        }
    }
}
// END LOGI_ACCEPT_BINDINGS

internal object LogiAcceptController {
    private val handler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }
    private val ledger = LogiAcceptLedger()
    private val scanQueued = java.util.concurrent.atomic.AtomicBoolean(false)
    private val constructing = ThreadLocal<LogiAcceptAttempt>()
    private val workerAttempt = ThreadLocal<LogiAcceptAttempt>()
    private val workerStack = ThreadLocal<MutableList<LogiAcceptAttempt?>>()
    private val workers = java.util.WeakHashMap<Any, LogiAcceptAttempt>()
    private val serviceFrame = ThreadLocal<ServiceFrame>()
    private var resource: Class<*>? = null
    @Volatile private var binding: LogiAcceptBinding? = null
    @Volatile private var ready = false
    private var mainActivity = java.lang.ref.WeakReference<Activity>(null)
    private var resumed = false
    @Volatile private var active: LogiAcceptAttempt? = null
    @Volatile private var requestContext = java.lang.ref.WeakReference<Activity>(null)
    private var clickedToken: Long? = null
    private var completed: Confirmation? = null
    private var lastFrontRequest = 0L
    private var receiver: android.content.BroadcastReceiver? = null

    private data class Candidate(val order: Any, val call: CallData)
    private data class ServiceFrame(val attempt: LogiAcceptAttempt, val id: Int,
                                    var detailId: Int? = null, var body: String? = null, var rejection: String? = null, var rejectionSubtype: Int? = null)
    private data class Confirmation(val token: Long, val id: Int, val result: String,
                                    val expires: Long, var clicked: Boolean = false)

    fun init(classLoader: ClassLoader) {
        try {
            val module = ModuleMain.module ?: return
            val layout = LogiAcceptBinding.load(classLoader)
            for (name in listOf("onResume", "onPause", "onDestroy")) {
                module.hook(layout.host.getDeclaredMethod(name), LogiActivityHooker::class.java)
            }
            for (screen in listOf(layout.normal, layout.allocated)) {
                module.hook(screen.getDeclaredMethod("onResume"), LogiActivityHooker::class.java)
                module.hook(screen.getDeclaredMethod("onDestroy"), LogiActivityHooker::class.java)
            }
            // Constructors run within our original entry/OK click; synthetic
            // workers are additionally checked for branch, order and owner.
            for (worker in layout.workerTypes) {
                for (constructor in worker.declaredConstructors) {
                    module.hook(constructor, LogiWorkerConstructorHooker::class.java)
                }
                module.hook(worker.getDeclaredMethod("run"), LogiWorkerHooker::class.java)
            }
            module.hook(layout.service, LogiServiceHooker::class.java)
            module.hook(layout.update, LogiDetailHooker::class.java)
            module.hook(layout.reject, LogiRejectionHooker::class.java)
            resource = layout.resource
            binding = layout
            ready = true
            ModuleMain.module?.log("LOGI: exact acceptance hooks installed profile=" + if (layout.modern) "D1_21.55_632" else "LEGACY_21.53")
        } catch (error: Throwable) {
            ready = false
            binding = null
            ModuleMain.module?.log("LOGI: native accept hooks unavailable; no guessed fallback", error)
        }
    }

    private fun fingerprint() = ConditionClient.current().toString() +
            ":${CallKindFilter.allowDaeri}:${CallKindFilter.allowTaksong}" +
            ":${TaksongDateFilter.allowToday}:${TaksongDateFilter.allowTomorrow}"

    private fun refreshSession() = ledger.observeSession(ConditionClient.isDetecting(), fingerprint())

    // API 33+ explicitly exports this cross-app receiver; API 32 uses the legacy overload.
    @android.annotation.SuppressLint("UnspecifiedRegisterReceiverFlag")
    private fun ensureObserver(): Boolean {
        if (receiver != null) return true
        val context = ModuleMain.getApplicationContext() ?: return false
        val observer = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != ConditionBridgeReceiver.ACTION_DELIVER_CONDITIONS) return
                if (!intent.getBooleanExtra(ConditionProvider.KEY_DETECTING, false)) ledger.observeSession(false, "")
                handler.post {
                    refreshSession()
                    val attempt = active
                    if (attempt != null && !ledger.canSend(attempt.token) && ledger.abortUnsent(attempt.token)) {
                        active = null
                        val screen = requestContext.get()
                        if (screen?.javaClass?.name == "com.logisoft.LogiD.NormalAllocateDlg" && alive(screen)) screen.finish()
                    }
                    scheduleScan()
                }
            }
        }
        return try {
            val filter = android.content.IntentFilter(ConditionBridgeReceiver.ACTION_DELIVER_CONDITIONS)
            if (android.os.Build.VERSION.SDK_INT >= 33) context.registerReceiver(observer, filter, Context.RECEIVER_EXPORTED)
            else context.registerReceiver(observer, filter)
            receiver = observer
            true
        } catch (error: Throwable) {
            ModuleMain.module?.log("LOGI: condition observer unavailable", error)
            false
        }
    }

    fun scheduleScan() {
        if (!ready || !scanQueued.compareAndSet(false, true)) return
        if (!handler.post {
                scanQueued.set(false)
                try { scan() } catch (error: Throwable) { ModuleMain.module?.log("LOGI: deferred order scan failed", error) }
            }) scanQueued.set(false)
    }

    private fun staticField(name: String): Any? = resource?.getDeclaredField(name)?.apply { isAccessible = true }?.get(null)
    private fun field(value: Any, name: String): Any? = ModuleMain.readField(value, name)
    private fun bool(name: String) = staticField(name) as? Boolean ?: error("LOGI missing boolean $name")
    private fun alive(activity: Activity) = !activity.isFinishing && !activity.isDestroyed
    private fun foreground(activity: Activity) = alive(activity) && binding?.foreground?.invoke(activity) == true

    private fun candidates(): List<Candidate> {
        val orders = staticField("m_orders") as? List<*> ?: return emptyList()
        // makeDaeriOrder runs inside this monitor. Acquire it after posting so
        // state normalization, deny flags and system-row removal finish first.
        return synchronized(orders) {
            val denied = staticField("m_denyOrders") as? Set<*> ?: return@synchronized emptyList()
            orders.mapNotNull { order ->
                if (order == null) return@mapNotNull null
                val id = (field(order, "nTNo") as? Number)?.toInt() ?: return@mapNotNull null
                val state = (field(order, "byState") as? Number)?.toInt() ?: return@mapNotNull null
                val nativeDeny = field(order, "bDeny") as? Boolean ?: return@mapNotNull null
                val call = LogiOrderData.call(id, state,
                    field(order, "szStart") as? String ?: "",
                    field(order, "szDest") as? String ?: "",
                    field(order, "szCharge") as? String ?: "",
                    field(order, "nDistance") as? Number,
                    field(order, "szKM") as? String ?: "",
                    nativeDeny || id in denied) ?: return@mapNotNull null
                Candidate(order, call)
            }
        }
    }

    private fun scan() {
        if (!ready || !ensureObserver()) return
        refreshSession()
        if (!ConditionClient.isDetecting() || active != null) return
        if (bool("m_bAllocProcess") || bool("bOrderListLock")) return
        val candidate = candidates().firstOrNull {
            ledger.canBegin(it.call.callId.removePrefix("LOGI:").toInt()) && ModuleMain.matchAndAccept(it.call)
        } ?: return
        val layout = binding ?: return
        val activity = mainActivity.get()
        // Do not invoke app-owned methods on an unverified modern runtime.
        if (activity != null && !layout.runtimeMatches(activity)) {
            ModuleMain.module?.log("LOGI: acceptance skipped - unverified runtime package/version")
            return
        }
        if (activity == null || !resumed || !foreground(activity) || layout.floating.invoke(null) == true) {
            val now = android.os.SystemClock.elapsedRealtime()
            if (now - lastFrontRequest > 3000L) {
                lastFrontRequest = now
                LogiPackageRoute.current()?.let { ModuleMain.bringAppToFront(it) }
                ModuleMain.module?.log("LOGI: matching order waiting for native foreground host")
            }
            return
        }
        if (!layout.hostIsReady(activity)) return
        val entryTarget = layout.entryTarget(activity) ?: return
        // Match again against a fresh row immediately before dispatch. Never hold
        // m_orders/m_autoOrders locks while running the native acceptance flow.
        val fresh = candidates().firstOrNull { it.call.callId == candidate.call.callId } ?: return
        if (!ModuleMain.matchAndAccept(fresh.call)) return
        if (bool("m_bAllocProcess") || bool("bOrderListLock")) return
        val settings = staticField("m_si") ?: return
        if (!layout.autoOrderAllows(activity, settings, fresh.order)) return
        refreshSession()
        val id = fresh.call.callId.removePrefix("LOGI:").toIntOrNull() ?: return
        val attempt = ledger.begin(id) ?: return
        active = attempt
        if (!ledger.prepare(attempt.token)) { active = null; return }
        requestContext = java.lang.ref.WeakReference(activity)
        constructing.set(attempt)
        try {
            layout.entry.invoke(entryTarget, fresh.order, false)
            if (!bool("m_bAllocProcess") && ledger.phase(attempt.token) == LogiAcceptPhase.PREPARING) {
                ledger.abortUnsent(attempt.token)
                active = null
            }
        } catch (error: Throwable) {
            if (ledger.abortUnsent(attempt.token)) active = null
            ModuleMain.module?.log("LOGI: native entry failed id=$id", error)
        } finally { constructing.remove() }
        handler.postDelayed({
            if (ledger.phase(attempt.token) != null) {
                ModuleMain.module?.log("LOGI: acceptance not confirmed id=$id phase=${ledger.phase(attempt.token)}; no duplicate dispatch")
            }
        }, 45000L)
    }

    fun activityEvent(activity: Activity, event: String) {
        when (activity.javaClass.name) {
            "com.logisoft.LogiD.OrderFormView2_1D" -> when (event) {
                "onResume" -> { mainActivity = java.lang.ref.WeakReference(activity); resumed = true; scheduleScan() }
                "onPause", "onDestroy" -> if (mainActivity.get() === activity) {
                    resumed = false
                    if (event == "onDestroy") mainActivity.clear()
                }
            }
            "com.logisoft.LogiD.NormalAllocateDlg" -> {
                if (event == "onResume") {
                    val attempt = active
                    if (attempt != null && ledger.phase(attempt.token) == LogiAcceptPhase.PREPARING &&
                        activity.intent?.getIntExtra("nTNo", -1) == attempt.id && binding?.normalMatches(activity, attempt.id) == true) {
                        requestContext = java.lang.ref.WeakReference(activity)
                        handler.post { clickPreparation(activity) }
                    }
                }
                if (event == "onDestroy") {
                    val attempt = active
                    if (attempt != null && activity.intent?.getIntExtra("nTNo", -1) == attempt.id &&
                        requestContext.get() === activity && ledger.abortUnsent(attempt.token)) active = null
                }
            }
            "com.logisoft.LogiD.AllocateDlg" -> if (event == "onResume") handler.post { clickConfirmation(activity) }
        }
    }

    private fun nativeButton(activity: Activity): android.view.View? {
        if (!foreground(activity) || !activity.hasWindowFocus()) return null
        return activity.findViewById<android.view.View>(binding?.okButtonId ?: return null)?.takeIf {
            it.isAttachedToWindow && it.isShown && it.isEnabled && it.hasOnClickListeners()
        }
    }

    private fun clickPreparation(activity: Activity, retry: Int = 0) {
        val attempt = active ?: return
        try {
            refreshSession()
            if (clickedToken == attempt.token || !alive(activity)) return
            if (!ledger.canSend(attempt.token)) { abandonPreparation(activity, attempt, "session_changed"); return }
            val layout = binding ?: return
            if (!layout.runtimeMatches(activity) || activity.intent?.getIntExtra("nTNo", -1) != attempt.id || !layout.normalMatches(activity, attempt.id)) return
            if (layout.normalIsBusy(activity)) return
            val button = nativeButton(activity)
            if (button == null) {
                if (retry < 20) handler.postDelayed({ clickPreparation(activity, retry + 1) }, 100L)
                else abandonPreparation(activity, attempt, "button_unavailable")
                return
            }
            // Revalidate the current call/conditions before the original OK sends.
            val fresh = candidates().firstOrNull { it.call.callId == "LOGI:${attempt.id}" }
            if (fresh == null || !ModuleMain.matchAndAccept(fresh.call)) {
                abandonPreparation(activity, attempt, "call_no_longer_matches")
                return
            }
            clickedToken = attempt.token
            requestContext = java.lang.ref.WeakReference(activity)
            constructing.set(attempt)
            try { button.performClick() } finally { constructing.remove() }
        } catch (error: Throwable) { ModuleMain.module?.log("LOGI: native preparation click failed id=${attempt.id}", error) }
    }

    private fun abandonPreparation(activity: Activity, attempt: LogiAcceptAttempt, reason: String) {
        if (requestContext.get() !== activity || !ledger.abortUnsent(attempt.token)) return
        if (active === attempt) active = null
        if (alive(activity)) activity.finish() // Original onDestroy restores native busy/select flags.
        ModuleMain.module?.log("LOGI: unsent preparation closed id=${attempt.id} reason=$reason")
    }

    private fun clickConfirmation(activity: Activity, retry: Int = 0) {
        val confirmation = completed ?: return
        try {
            if (confirmation.clicked || android.os.SystemClock.elapsedRealtime() > confirmation.expires || !alive(activity)) return
            val layout = binding ?: return
            if (!layout.runtimeMatches(activity) || activity.intent?.getIntExtra("nTNo", -1) != confirmation.id ||
                activity.intent?.getStringExtra("strDataSet") != confirmation.result ||
                !layout.confirmationMatches(activity, confirmation.id)) return
            val button = nativeButton(activity)
            if (button == null) { if (retry < 20) handler.postDelayed({ clickConfirmation(activity, retry + 1) }, 100L); return }
            confirmation.clicked = true
            button.performClick()
            ModuleMain.module?.log("LOGI: native allocation confirmation dispatched id=${confirmation.id}")
        } catch (error: Throwable) { ModuleMain.module?.log("LOGI: native confirmation click failed", error) }
    }

    fun workerCreated(worker: Any) {
        val attempt = constructing.get() ?: return
        if (runCatching { binding?.ownsWorker(worker, attempt.id, requestContext.get()) }.getOrDefault(false) != true) return
        synchronized(workers) { workers[worker] = attempt }
    }
    fun workerStarted(worker: Any) {
        val attempt = synchronized(workers) { workers.remove(worker) }
        val stack = workerStack.get() ?: mutableListOf<LogiAcceptAttempt?>().also { workerStack.set(it) }
        stack.add(workerAttempt.get())
        if (attempt == null) workerAttempt.remove() else workerAttempt.set(attempt)
    }
    fun workerFinished() {
        val stack = workerStack.get() ?: return
        if (stack.isEmpty()) { workerStack.remove(); return }
        val attempt = workerAttempt.get()
        val previous = stack.removeAt(stack.lastIndex)
        if (previous == null) workerAttempt.remove() else workerAttempt.set(previous)
        if (stack.isEmpty()) workerStack.remove()
        if (attempt != null) handler.post {
            if (ledger.abortUnsent(attempt.token) && active === attempt) {
                active = null
                ModuleMain.module?.log("LOGI: native worker finished without sending id=${attempt.id}")
            }
        }
    }

    fun serviceStarting(id: Int, context: Any?): Boolean {
        serviceFrame.remove()
        val attempt = workerAttempt.get() ?: return true // Preserve manual/native requests.
        refreshSession()
        if (id != attempt.id || requestContext.get() !== context || context !is Context ||
            binding?.runtimeMatches(context) != true || !ledger.sent(attempt.token)) {
            handler.post {
                if (ledger.abortUnsent(attempt.token) && active === attempt) active = null
                ModuleMain.module?.log("LOGI: stale or mismatched unsent request blocked id=$id")
            }
            return false
        }
        serviceFrame.set(ServiceFrame(attempt, id))
        return true
    }
    fun detailReceived(detail: Any) {
        val frame = serviceFrame.get() ?: return
        val layout = binding ?: return
        frame.detailId = layout.responseId(detail)
        frame.body = layout.responseBody(detail)
    }
    fun rejectionReceived(packet: Any?, result: String?) {
        val frame = serviceFrame.get() ?: return
        frame.rejection = result
        frame.rejectionSubtype = packet?.let { (field(it, "nSubType") as? Number)?.toInt() }
    }
    fun serviceFinished(result: String?, error: Throwable?) {
        val frame = serviceFrame.get() ?: return
        serviceFrame.remove()
        val marker = runCatching { binding?.successMarker() }.getOrNull()
        val verified = error == null && LogiOrderData.isVerifiedSuccess(frame.id, frame.detailId, marker, frame.body, result)
        // A failure/timeout may follow a server-side allocation. Keep ambiguous
        // attempts reserved and never infer success from a non-null return.
        val rejected = error == null && LogiOrderData.isDefinitiveRejection(frame.rejectionSubtype) &&
                !frame.rejection.isNullOrBlank() && frame.detailId == null && result == frame.rejection
        val outcome = when { verified -> LogiAcceptResult.SUCCESS; rejected -> LogiAcceptResult.FAILURE; else -> LogiAcceptResult.UNKNOWN }
        val confirmationPayload = if (verified) runCatching { result!!.replaceFirst(Regex(marker!!), "") }.getOrNull() else null
        handler.post {
            refreshSession()
            val finish = ledger.finish(frame.attempt.token, outcome, frame.detailId)
            if (finish == LogiAcceptFinish.SUCCESS || finish == LogiAcceptFinish.STALE_SUCCESS) {
                // Finish the original, already verified request even if detection
                // settings changed in flight; only the current session may turn OFF.
                completed = confirmationPayload?.let { Confirmation(frame.attempt.token, frame.id, it, android.os.SystemClock.elapsedRealtime() + 45000L) }
            }
            if (finish == LogiAcceptFinish.SUCCESS) {
                if (active === frame.attempt) active = null
                ModuleMain.module?.log("LOGI: ACCEPT_CONFIRMED id=${frame.id}")
                ConditionClient.stopDetecting("confirmed:LOGI:${frame.id}")
            } else if (finish == LogiAcceptFinish.STALE_SUCCESS) {
                if (active === frame.attempt) active = null
                ModuleMain.module?.log("LOGI: prior-session allocation completed id=${frame.id}; current detection unchanged")
            } else if (finish == LogiAcceptFinish.FAILURE) {
                if (active === frame.attempt) active = null
                ModuleMain.module?.log("LOGI: ACCEPT_REJECTED id=${frame.id}; detection remains active")
                scheduleScan()
            } else {
                ModuleMain.module?.log("LOGI: ACCEPT_UNCONFIRMED id=${frame.id}; detection remains active, reservation retained")
            }
        }
    }
}

@XposedHooker
class LogiActivityHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable != null) return
            val activity = callback.thisObject as? Activity ?: return
            try { LogiAcceptController.activityEvent(activity, callback.member.name) }
            catch (error: Throwable) { ModuleMain.module?.log("LOGI: activity observation failed", error) }
        }
    }
}

@XposedHooker
class LogiWorkerConstructorHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable == null) callback.thisObject?.let { LogiAcceptController.workerCreated(it) }
        }
    }
}

@XposedHooker
class LogiWorkerHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @BeforeInvocation fun before(callback: XposedInterface.BeforeHookCallback) {
            callback.thisObject?.let { LogiAcceptController.workerStarted(it) }
        }
        @JvmStatic @AfterInvocation fun after(callback: XposedInterface.AfterHookCallback) { LogiAcceptController.workerFinished() }
    }
}

@XposedHooker
class LogiServiceHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @BeforeInvocation fun before(callback: XposedInterface.BeforeHookCallback) {
            try {
                val id = callback.args.getOrNull(0) as? Int ?: return
                if (!LogiAcceptController.serviceStarting(id, callback.args.getOrNull(1))) callback.returnAndSkip(null)
            } catch (error: Throwable) { callback.throwAndSkip(error) }
        }
        @JvmStatic @AfterInvocation fun after(callback: XposedInterface.AfterHookCallback) {
            try { LogiAcceptController.serviceFinished(callback.result as? String, callback.throwable) }
            catch (error: Throwable) { ModuleMain.module?.log("LOGI: result observation failed", error) }
        }
    }
}

@XposedHooker
class LogiDetailHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @BeforeInvocation fun before(callback: XposedInterface.BeforeHookCallback) {
            callback.args.getOrNull(0)?.let { LogiAcceptController.detailReceived(it) }
        }
    }
}

@XposedHooker
class LogiRejectionHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable == null) LogiAcceptController.rejectionReceived(callback.args.getOrNull(0), callback.result as? String)
        }
    }
}

// BEGIN LOGI_GPS_INSTALLER
internal fun ModuleMain.installLogiGpsSpoof(classLoader: ClassLoader) {
    val module = ModuleMain.module ?: return
    var coordinateHooks = 0
    val coordinateTargets: List<Pair<String, Class<out XposedInterface.Hooker>>> = listOf(
        "getLatitude" to GpsLatitudeHooker::class.java,
        "getLongitude" to GpsLongitudeHooker::class.java
    )
    for ((name, hooker) in coordinateTargets) {
        try {
            val locationClass = Class.forName("android.location.Location", false, classLoader)
            module.hook(locationClass.getMethod(name), hooker)
            coordinateHooks++
        } catch (error: Throwable) {
            module.log("LOGI_GPS: coordinate hook unavailable method=$name", error)
        }
    }
    module.log("LOGI_GPS: coordinates registered=$coordinateHooks/2 package=${LogiPackageRoute.current()} liveExecution=UNVERIFIED")
}
// END LOGI_GPS_INSTALLER


/**
 * 아이드라이브:
 * 1) Location getLatitude/getLongitude → 스푸프 좌표
 * 2) Utility.LLToTM(lat,lng) 인자 교체 → 앱이 만든 TM이 스푸프 위치 기준
 * 3) StaticObj.dLat/dLon/strTmX/strTmY 갱신 경로를 간접 커버
 */
internal fun ModuleMain.installLogiOrderHook(classLoader: ClassLoader) {
    try {
        val orderClass = Class.forName("com.logisoft.LogiD.Info.ORDER", false, classLoader)
        val makeMethod = orderClass.getDeclaredMethod("makeDaeriOrder", String::class.java).apply { isAccessible = true }
        check(Modifier.isStatic(makeMethod.modifiers) && makeMethod.returnType == orderClass)
        LogiOrderHooker.orderClass = orderClass
        ModuleMain.module?.hook(makeMethod, LogiOrderHooker::class.java)
        ModuleMain.module?.log("LOGI: ORDER.makeDaeriOrder hook installed")
    } catch (t: Throwable) { ModuleMain.module?.log("LOGI: hook installation FAILED", t) }
}





// BEGIN LOGI_SECURITY_RESULTS
/** Exact Java report profiles only. Native SDK checks and installed-app queries are separate paths. */
internal object LogiSecurityResults {
    private const val XPOSED_MAPPING = 1
    private const val XPOSED_CLASS = 2
    private const val XPOSED_STACK = 4
    private const val XPOSED_MODULE = 32
    private const val XPOSED_MASK = XPOSED_MAPPING or XPOSED_CLASS or XPOSED_STACK or XPOSED_MODULE

    private enum class Profile { LEGACY_2153, D1_2155 }
    private data class RootLayout(
        val type: Class<*>, val constructor: java.lang.reflect.Constructor<*>,
        val detected: java.lang.reflect.Field, val hits: java.lang.reflect.Field,
        val profile: Profile, val packageName: String,
        val observed: java.util.concurrent.atomic.AtomicBoolean = java.util.concurrent.atomic.AtomicBoolean(false)
    )
    private data class HookLayout(
        val type: Class<*>, val constructor: java.lang.reflect.Constructor<*>,
        val flags: java.lang.reflect.Field, val hits: java.lang.reflect.Field,
        val modules: java.lang.reflect.Field, val discriminator: java.lang.reflect.Field?,
        val profile: Profile, val packageName: String,
        val observed: java.util.concurrent.atomic.AtomicBoolean = java.util.concurrent.atomic.AtomicBoolean(false)
    )
    private val roots = java.util.concurrent.ConcurrentHashMap<Method, RootLayout>()
    private val reports = java.util.concurrent.ConcurrentHashMap<Method, HookLayout>()
    private val installed = HashSet<Method>()

    fun diagnostic(message: String, module: ModuleMain? = ModuleMain.module) {
        try { module?.log(message) } catch (_: Throwable) { /* Diagnostics must preserve the original call. */ }
    }

    private fun field(owner: Class<*>, name: String, type: Class<*>): java.lang.reflect.Field =
        owner.getDeclaredField(name).apply {
            require(this.type == type && !Modifier.isStatic(modifiers)) { "report field mismatch: $name" }
            isAccessible = true
        }

    private fun shape(owner: Class<*>, names: Set<String>) {
        require(owner.declaredFields.filter { !Modifier.isStatic(it.modifiers) }.map { it.name }.toSet() == names) {
            "unexpected report layout"
        }
    }

    private fun endpoint(owner: Class<*>, name: String, result: Class<*>, vararg args: Class<*>): Method =
        owner.getDeclaredMethod(name, *args).apply {
            require(returnType == result && Modifier.isStatic(modifiers) &&
                    !Modifier.isNative(modifiers) && !Modifier.isAbstract(modifiers)) { "report endpoint mismatch" }
            isAccessible = true
        }

    // Registration may happen before Application exists. Check again on every invocation;
    // never cache a missing context or an unsupported package/version as a positive result.
    private fun allows(profile: Profile, packageName: String): Boolean = try {
        if (LogiPackageRoute.current() != packageName) false
        else {
            val context = ModuleMain.getApplicationContext()
            if (context == null || context.packageName != packageName) false
            else {
                val info = context.packageManager.getPackageInfo(packageName, 0)
                when (profile) {
                    Profile.LEGACY_2153 -> LogiPackageRoute.supports(packageName) && info.versionName == "21.53"
                    Profile.D1_2155 -> packageName == "com.logisoft.Logi4" &&
                            info.versionName == "21.55" && info.longVersionCode == 632L
                }
            }
        }
    } catch (_: Throwable) { false }

    @Synchronized private fun register(module: ModuleMain, method: Method,
        hooker: Class<out XposedInterface.Hooker>, kind: String) {
        if (installed.contains(method)) return
        method.isAccessible = true
        module.hook(method, hooker)
        installed.add(method)
        diagnostic("LOGI_SECURITY: registered kind=$kind execution=UNVERIFIED", module)
    }

    private fun installRoot(module: ModuleMain, loader: ClassLoader, packageName: String, profile: Profile) {
        val modern = profile == Profile.D1_2155
        val owner = Class.forName(if (modern) "com.logisoft.LogiD.Util.a" else "com.logisoft.LogiD.Util.t", false, loader)
        val report = Class.forName(if (modern) "com.google.android.gms.common.internal.f0"
            else "com.logisoft.LogiD.Util.t\$a", false, loader)
        shape(report, if (modern) setOf("a", "b") else setOf("detected", "hits"))
        val detected = field(report, if (modern) "a" else "detected", java.lang.Boolean.TYPE)
        val hits = field(report, if (modern) "b" else "hits", if (modern) Any::class.java else java.util.List::class.java)
        if (modern) require(Modifier.isFinal(hits.modifiers)) { "unexpected merged root slot" }
        val layout = RootLayout(report, report.getDeclaredConstructor().apply { isAccessible = true },
            detected, hits, profile, packageName)
        val empty = layout.constructor.newInstance()
        require(!layout.detected.getBoolean(empty) && strings(layout.hits, empty).isEmpty())
        val method = endpoint(owner, if (modern) "o" else "run", report)
        synchronized(this) {
            if (!installed.contains(method)) {
                roots[method] = layout
                try { register(module, method, LogiRootReportHooker::class.java, "root_report_$profile") }
                catch (error: Throwable) { roots.remove(method, layout); throw error }
            }
        }
    }

    private fun installReport(module: ModuleMain, loader: ClassLoader, packageName: String, profile: Profile) {
        val modern = profile == Profile.D1_2155
        val owner = Class.forName(if (modern) "com.logisoft.LogiD.Util.a" else "com.logisoft.LogiD.Util.u", false, loader)
        if (!modern) {
            val constants = mapOf("FLAG_XPOSED_INJECTED" to 1, "FLAG_XPOSED_CLASS" to 2,
                "FLAG_XPOSED_STACK" to 4, "FLAG_FRIDA_PORT" to 8, "FLAG_DEBUGGER_ATTACH" to 16,
                "FLAG_XPOSED_MODULE" to 32, "FLAG_FRIDA_INJECTED" to 64)
            for ((name, value) in constants) {
                val constant = owner.getDeclaredField(name)
                require(constant.type == java.lang.Integer.TYPE && Modifier.isStatic(constant.modifiers) &&
                        Modifier.isFinal(constant.modifiers) && constant.getInt(null) == value) { "flag contract mismatch" }
            }
        }
        val report = Class.forName(if (modern) "com.logisoft.LogiD.Util.y"
            else "com.logisoft.LogiD.Util.u\$a", false, loader)
        shape(report, if (modern) setOf("a", "b", "c", "d") else setOf("flags", "hits", "modulePackages"))
        val discriminator = if (modern) field(report, "a", java.lang.Integer.TYPE).also {
            require(Modifier.isFinal(it.modifiers) && it.isSynthetic) { "unexpected merged report discriminator" }
        } else null
        val layout = HookLayout(report, report.getDeclaredConstructor().apply { isAccessible = true },
            field(report, if (modern) "b" else "flags", java.lang.Integer.TYPE),
            field(report, if (modern) "c" else "hits", if (modern) Any::class.java else java.util.List::class.java),
            field(report, if (modern) "d" else "modulePackages", if (modern) Any::class.java else java.util.List::class.java),
            discriminator, profile, packageName)
        // The verified no-arg constructor creates the report variant (a=0), unlike
        // y(int), whose Object slots may belong to unrelated merged SDK classes.
        val empty = layout.constructor.newInstance()
        require((discriminator == null || discriminator.getInt(empty) == 0) && layout.flags.getInt(empty) == 0 &&
                strings(layout.hits, empty).isEmpty() && strings(layout.modules, empty).isEmpty())
        val method = endpoint(owner, if (modern) "p" else "run", report, Context::class.java)
        synchronized(this) {
            if (!installed.contains(method)) {
                reports[method] = layout
                try { register(module, method, LogiHookReportHooker::class.java, "hook_report_$profile") }
                catch (error: Throwable) { reports.remove(method, layout); throw error }
            }
        }
    }

    fun install(module: ModuleMain, loader: ClassLoader) {
        val packageName = LogiPackageRoute.current().orEmpty()
        if (!LogiPackageRoute.supports(packageName)) {
            diagnostic("LOGI_SECURITY: registration skipped reason=PACKAGE_NOT_ATTACHED", module)
            return
        }
        try {
            val exists = java.io.File::class.java.getDeclaredMethod("exists")
            require(exists.returnType == java.lang.Boolean.TYPE && !Modifier.isStatic(exists.modifiers))
            register(module, exists, LogiRootPathHooker::class.java, "root_file")
        } catch (error: Throwable) {
            diagnostic("LOGI_SECURITY: root_file unavailable type=${error.javaClass.name}", module)
        }
        val profiles = if (packageName == "com.logisoft.Logi4") listOf(Profile.LEGACY_2153, Profile.D1_2155)
            else listOf(Profile.LEGACY_2153)
        for (profile in profiles) {
            try { installRoot(module, loader, packageName, profile) }
            catch (error: Throwable) { diagnostic("LOGI_SECURITY: root_report_$profile unavailable type=${error.javaClass.name}", module) }
            try { installReport(module, loader, packageName, profile) }
            catch (error: Throwable) { diagnostic("LOGI_SECURITY: hook_report_$profile unavailable type=${error.javaClass.name}", module) }
        }
    }

    private fun strings(field: java.lang.reflect.Field, receiver: Any): List<String> {
        val value = field.get(receiver) as? List<*> ?: throw IllegalArgumentException("report list missing")
        require(value.all { it is String }) { "report list contains unknown values" }
        return value.map { it as String }
    }

    @Suppress("UNCHECKED_CAST")
    private fun fill(field: java.lang.reflect.Field, receiver: Any, values: List<String>) {
        val target = field.get(receiver) as? MutableList<Any?> ?: throw IllegalArgumentException("report list is not mutable")
        require(target.isEmpty()) { "report defaults changed" }
        target.addAll(values)
        require(strings(field, receiver) == values) { "report list write mismatch" }
    }

    private fun rootHit(value: String): Boolean = value in setOf(
        "build:test-keys", "exec:su", "file:Superuser.apk", "mount:system-rw", "write:/data/local/tmp"
    ) || listOf("su:", "busybox:", "magisk:", "prop:ro.secure=", "prop:ro.debuggable=",
        "prop:ro.build.type=").any { value.startsWith(it) }

    private fun xposedClass(value: String): Boolean = value.startsWith("de.robv.android.xposed.") ||
        value.startsWith("org.lsposed.") || value.startsWith("io.github.libxposed.") ||
        value.contains("LSPosed") || value.contains("EdXposed")

    fun rootAfter(callback: XposedInterface.AfterHookCallback) {
        if (callback.throwable != null) return
        val layout = roots[callback.member as? Method ?: return] ?: return
        if (!allows(layout.profile, layout.packageName)) return
        val original = callback.result ?: return
        try {
            require(original.javaClass == layout.type) { "root report instance mismatch" }
            val before = layout.detected.getBoolean(original)
            val hits = strings(layout.hits, original)
            val kept = hits.filterNot(::rootHit)
            val removed = hits.size - kept.size
            if (layout.observed.compareAndSet(false, true)) {
                diagnostic("LOGI_SECURITY: observed kind=root detected=$before selectedHits=$removed preservedHits=${kept.size}")
            }
            // Preserve an unknown positive instead of manufacturing an all-clean report.
            val after = before && (kept.isNotEmpty() || removed == 0)
            if (before == after && removed == 0) {
                if (before) diagnostic("LOGI_SECURITY: root_report unchanged reason=UNVERIFIED_ROOT_EVIDENCE")
                return
            }
            val replacement = layout.constructor.newInstance()
            layout.detected.setBoolean(replacement, after)
            fill(layout.hits, replacement, kept)
            require(layout.detected.getBoolean(replacement) == after)
            callback.result = replacement
            diagnostic("LOGI_SECURITY: root_report changed detected=$before->$after removedHits=$removed preservedHits=${kept.size}")
        } catch (error: Throwable) {
            diagnostic("LOGI_SECURITY: root_report unchanged reason=${error.javaClass.name}")
        }
    }

    fun hookAfter(callback: XposedInterface.AfterHookCallback) {
        if (callback.throwable != null) return
        val layout = reports[callback.member as? Method ?: return] ?: return
        if (!allows(layout.profile, layout.packageName)) return
        val original = callback.result ?: return
        try {
            require(original.javaClass == layout.type) { "hook report instance mismatch" }
            require(layout.discriminator == null || layout.discriminator.getInt(original) == 0) { "unrelated merged result variant" }
            val flags = layout.flags.getInt(original)
            val hits = strings(layout.hits, original)
            val modules = strings(layout.modules, original)
            if (layout.observed.compareAndSet(false, true)) {
                diagnostic("LOGI_SECURITY: observed kind=hook flags=$flags hits=${hits.size} modules=${modules.size}")
            }
            val kept = hits.filterNot { hit ->
                hit == "maps:xposed" ||
                    hit.startsWith("class:") && xposedClass(hit.removePrefix("class:")) ||
                    hit.startsWith("stack:") && xposedClass(hit.removePrefix("stack:")) ||
                    hit.startsWith("module:") && hit.removePrefix("module:") in modules
            }
            var clear = XPOSED_MASK
            // Stack bit 4 is also shared with SMulti/o.* findings. Preserve any
            // category whose remaining evidence is not part of the known profile.
            if (kept.any { it.startsWith("stack:") }) clear = clear and XPOSED_STACK.inv()
            if (kept.any { it.startsWith("class:") }) clear = clear and XPOSED_CLASS.inv()
            if (kept.any { it.startsWith("module:") }) clear = clear and XPOSED_MODULE.inv()
            if (kept.any { it.startsWith("maps:") && it != "maps:frida" }) clear = clear and XPOSED_MAPPING.inv()
            val changedFlags = flags and clear.inv()
            if (changedFlags == flags && kept == hits && modules.isEmpty()) return
            val replacement = layout.constructor.newInstance()
            require(layout.discriminator == null || layout.discriminator.getInt(replacement) == 0) { "report constructor changed" }
            layout.flags.setInt(replacement, changedFlags)
            fill(layout.hits, replacement, kept)
            require(strings(layout.modules, replacement).isEmpty())
            require(layout.flags.getInt(replacement) == changedFlags)
            callback.result = replacement
            diagnostic("LOGI_SECURITY: hook_report changed flags=$flags->$changedFlags removedHits=${hits.size - kept.size} preservedHits=${kept.size} removedModules=${modules.size}")
        } catch (error: Throwable) {
            diagnostic("LOGI_SECURITY: hook_report unchanged reason=${error.javaClass.name}")
        }
    }
}

internal fun ModuleMain.installLogiSecurityBypass(classLoader: ClassLoader) {
    val module = ModuleMain.module ?: return
    LogiSecurityResults.install(module, classLoader)
}

@XposedHooker
class LogiRootPathHooker : XposedInterface.Hooker {
    companion object {
        private val rootPaths = setOf("/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/adb/magisk")
        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable != null || callback.result != true) return
            val file = callback.thisObject as? java.io.File ?: return
            if (file.path.trimEnd('/') !in rootPaths) return
            callback.result = false
            LogiSecurityResults.diagnostic("LOGI_SECURITY: root_file result changed true->false")
        }
    }
}

@XposedHooker
class LogiRootReportHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation fun after(callback: XposedInterface.AfterHookCallback) {
            LogiSecurityResults.rootAfter(callback)
        }
    }
}

@XposedHooker
class LogiHookReportHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation fun after(callback: XposedInterface.AfterHookCallback) {
            LogiSecurityResults.hookAfter(callback)
        }
    }
}
// END LOGI_SECURITY_RESULTS

@XposedHooker
class LogiOrderHooker : XposedInterface.Hooker {
    companion object {
        @Volatile var orderClass: Class<*>? = null

        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable == null && callback.result != null) LogiAcceptController.scheduleScan()
        }
    }
}
