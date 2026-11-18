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














// ########################################################################
// 콜마너, T맵, 아이드라이브, 로지 Hooker 클래스들
// ########################################################################

internal object DirectAcceptController {
    private val ledger = KakaoAcceptLedger()
    private val mainHandler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }
    private val dispatching = ThreadLocal<Dispatch>()
    private data class Dispatch(val host: Any, val attempt: KakaoAcceptAttempt, var linked: Boolean = false, var rejected: Boolean = false)
    @Volatile private var bridge: KakaoNativeAcceptBridge? = null
    @Volatile private var host = java.lang.ref.WeakReference<Any>(null)
    @Volatile private var conditionReceiver: android.content.BroadcastReceiver? = null

    fun configure(nativeBridge: KakaoNativeAcceptBridge) { bridge = nativeBridge }

    fun captureViewModel(candidate: Any?, source: String) {
        if (candidate == null || bridge?.hostClass?.isInstance(candidate) != true) return
        host = java.lang.ref.WeakReference(candidate)
        ensureConditionObserver()
        ModuleMain.module?.log("KAKAO: native accept host captured source=$source")
    }

    private fun fingerprint(): String = ConditionClient.current().toString() +
            ":${CallKindFilter.allowDaeri}:${CallKindFilter.allowTaksong}" +
            ":${TaksongDateFilter.allowToday}:${TaksongDateFilter.allowTomorrow}"

    private fun refreshSession() = ledger.observeSession(ConditionClient.isDetecting(), fingerprint())

    // API 33+ explicitly exports this cross-app receiver; API 32 uses the legacy overload.
    @android.annotation.SuppressLint("UnspecifiedRegisterReceiverFlag")
    @Synchronized fun ensureConditionObserver(): Boolean {
        if (bridge == null) return false // Other target applications keep their existing flow.
        if (conditionReceiver != null) return true
        val context = ModuleMain.getApplicationContext() ?: return false
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != ConditionBridgeReceiver.ACTION_DELIVER_CONDITIONS) return
                if (!intent.getBooleanExtra(ConditionProvider.KEY_DETECTING, false)) {
                    ledger.observeSession(false, "")
                }
                // Let the existing ConditionClient receiver apply the payload first.
                mainHandler.post { refreshSession() }
            }
        }
        return try {
            val filter = android.content.IntentFilter(ConditionBridgeReceiver.ACTION_DELIVER_CONDITIONS)
            if (android.os.Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
            else context.registerReceiver(receiver, filter)
            conditionReceiver = receiver
            mainHandler.post { refreshSession() }
            true
        } catch (error: Throwable) {
            ModuleMain.module?.log("KAKAO: accept condition observer unavailable", error)
            false
        }
    }

    fun accept(callId: String, source: DirectAcceptSource, miniDetail: Boolean = false, vip: Boolean = false): DirectAcceptOutcome {
        val nativeBridge = bridge ?: return DirectAcceptOutcome.VIEW_MODEL_NOT_READY
        val nativeHost = host.get() ?: return DirectAcceptOutcome.VIEW_MODEL_NOT_READY
        if (!ensureConditionObserver()) return DirectAcceptOutcome.VIEW_MODEL_NOT_READY
        refreshSession()
        val (outcome, attempt) = ledger.begin(callId, source, android.os.SystemClock.elapsedRealtime())
        if (attempt == null) return outcome
        if (!mainHandler.post { launch(nativeBridge, nativeHost, attempt, miniDetail, vip) }) {
            ledger.finish(attempt.token, KakaoAcceptResult.FAILURE, null, android.os.SystemClock.elapsedRealtime())
            return DirectAcceptOutcome.FAILED
        }
        return DirectAcceptOutcome.STARTED
    }

    private fun launch(nativeBridge: KakaoNativeAcceptBridge, nativeHost: Any, attempt: KakaoAcceptAttempt, miniDetail: Boolean, vip: Boolean) {
        refreshSession()
        try {
            if (nativeBridge.isBusy(nativeHost)) {
                observe(attempt, KakaoNativeAcceptEvent(KakaoAcceptResult.FAILURE, errorType = "NativeBusyNotSent"))
                return
            }
        } catch (error: Throwable) {
            observe(attempt, KakaoNativeAcceptEvent(KakaoAcceptResult.FAILURE, errorType = "NativeStateUnavailableNotSent"))
            return
        }
        if (!ledger.dispatch(attempt.token)) return
        val dispatch = Dispatch(nativeHost, attempt)
        dispatching.set(dispatch)
        try {
            nativeBridge.start(nativeHost, attempt.callId, attempt.source, miniDetail, vip)
            if (!dispatch.linked) {
                observe(attempt, KakaoNativeAcceptEvent(KakaoAcceptResult.UNKNOWN, errorType = "CallbackNotObserved"))
            }
        } catch (error: Throwable) {
            val cause = (error as? java.lang.reflect.InvocationTargetException)?.cause ?: error
            // Only an explicitly blocked dispatch is known not to have launched.
            observe(attempt, KakaoNativeAcceptEvent(
                if (dispatch.rejected && !dispatch.linked) KakaoAcceptResult.FAILURE else KakaoAcceptResult.UNKNOWN,
                errorType = cause.javaClass.simpleName
            ))
            ModuleMain.module?.log("KAKAO: native accept invocation problem id=${attempt.callId}", cause)
        } finally {
            dispatching.remove()
        }
        mainHandler.postDelayed({
            if (ledger.phase(attempt.token) != null) {
                observe(attempt, KakaoNativeAcceptEvent(KakaoAcceptResult.UNKNOWN, errorType = "OutcomeTimeout"))
            }
        }, 45000L)
    }

    fun wrapNativeDispatch(args: Array<Any?>) {
        val dispatch = dispatching.get() ?: return // Preserve unrelated/manual requests.
        if (dispatch.linked) return // Native callbacks may synchronously launch other jobs.
        try {
            val nativeBridge = bridge ?: error("Native accept bridge unavailable")
            if (!nativeBridge.matches(args.getOrNull(0), dispatch.host, dispatch.attempt)) return
            val wrapped = nativeBridge.wrap(args, dispatch.host, dispatch.attempt) { event -> observe(dispatch.attempt, event) }
            check(ledger.observing(dispatch.attempt.token)) { "Request no longer dispatchable" }
            args[3] = wrapped
            dispatch.linked = true
        } catch (error: Throwable) {
            dispatch.rejected = true
            throw error
        }
    }

    private fun observe(attempt: KakaoAcceptAttempt, event: KakaoNativeAcceptEvent) {
        val action = Runnable {
            refreshSession()
            when (ledger.finish(attempt.token, event.result, event.callId, android.os.SystemClock.elapsedRealtime(), event.terminalRejection)) {
                KakaoAcceptFinish.SUCCESS -> {
                    ledger.observeSession(false, fingerprint())
                    ModuleMain.module?.log("KAKAO: ACCEPT_CONFIRMED id=${attempt.callId} from=${attempt.source.rawValue}")
                    ConditionClient.stopDetecting("confirmed:KAKAO:${attempt.callId}")
                    ModuleMain.bringAppToFront(ModuleMain.KAKAO_PACKAGE)
                }
                KakaoAcceptFinish.STALE_SUCCESS -> ModuleMain.module?.log("KAKAO: accept completed for prior detection session id=${attempt.callId}")
                KakaoAcceptFinish.FAILURE -> ModuleMain.module?.log("KAKAO: ACCEPT_FAILED id=${attempt.callId} error=${event.errorType}; detection remains active; terminalRejection=${event.terminalRejection}")
                KakaoAcceptFinish.UNKNOWN -> ModuleMain.module?.log("KAKAO: ACCEPT_UNCONFIRMED id=${attempt.callId} error=${event.errorType}; reservation retained, no duplicate request")
                KakaoAcceptFinish.IGNORED -> Unit
            }
        }
        if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) action.run()
        else mainHandler.post(action)
    }
}

@XposedHooker
class KakaoNativeDispatchHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            try { DirectAcceptController.wrapNativeDispatch(callback.args) }
            catch (error: Throwable) { callback.throwAndSkip(error) }
        }
    }
}

internal enum class DirectAcceptSource(val rawValue: String) {
    LIST("list"),
    CARD("card"),
    WAY_BACK("way_back")
}

internal enum class DirectAcceptOutcome {
    STARTED, DUPLICATE, BUSY, ALREADY_SUCCEEDED, COOLDOWN, DETECTION_OFF,
    VIEW_MODEL_NOT_READY, FAILED
}

// BEGIN KAKAO_ACCEPT_CORE: JVM-testable request state and native callback adapter.
internal enum class KakaoAcceptPhase { QUEUED, DISPATCHED, OBSERVING, UNKNOWN }
internal enum class KakaoAcceptResult { LOADING, SUCCESS, FAILURE, UNKNOWN }
internal enum class KakaoAcceptFinish { IGNORED, SUCCESS, STALE_SUCCESS, FAILURE, UNKNOWN }

internal data class KakaoAcceptAttempt(
    val token: Long,
    val callId: String,
    val source: DirectAcceptSource,
    val generation: Long,
    var phase: KakaoAcceptPhase = KakaoAcceptPhase.QUEUED
)

internal class KakaoAcceptLedger(private val retryDelayMs: Long = 3000L) {
    private var generation = 0L
    private var detecting = false
    private var fingerprint = ""
    private var nextToken = 0L
    private var pending: KakaoAcceptAttempt? = null
    private val succeeded = LinkedHashSet<String>()
    private val retryAfter = LinkedHashMap<String, Long>()

    @Synchronized fun observeSession(enabled: Boolean, conditions: String) {
        if (enabled != detecting || (enabled && conditions != fingerprint)) {
            generation++
            detecting = enabled
            fingerprint = conditions
            retryAfter.clear()
            // An unsent request can be discarded. A dispatched request remains
            // reserved until its actual outcome, even across OFF -> ON.
            if (pending?.phase == KakaoAcceptPhase.QUEUED) pending = null
        }
    }

    @Synchronized fun begin(callId: String, source: DirectAcceptSource, now: Long): Pair<DirectAcceptOutcome, KakaoAcceptAttempt?> {
        if (callId.isBlank()) return DirectAcceptOutcome.FAILED to null
        if (!detecting) return DirectAcceptOutcome.DETECTION_OFF to null
        if (callId in succeeded) return DirectAcceptOutcome.ALREADY_SUCCEEDED to null
        pending?.let {
            return (if (it.callId == callId) DirectAcceptOutcome.DUPLICATE else DirectAcceptOutcome.BUSY) to null
        }
        if (now < (retryAfter[callId] ?: 0L)) return DirectAcceptOutcome.COOLDOWN to null
        val attempt = KakaoAcceptAttempt(++nextToken, callId, source, generation)
        pending = attempt
        return DirectAcceptOutcome.STARTED to attempt
    }

    @Synchronized fun dispatch(token: Long): Boolean {
        val attempt = pending ?: return false
        if (attempt.token != token || !detecting || attempt.generation != generation) return false
        if (attempt.phase != KakaoAcceptPhase.QUEUED) return false
        attempt.phase = KakaoAcceptPhase.DISPATCHED
        return true
    }

    @Synchronized fun observing(token: Long): Boolean {
        val attempt = pending ?: return false
        if (attempt.token != token || attempt.phase != KakaoAcceptPhase.DISPATCHED) return false
        attempt.phase = KakaoAcceptPhase.OBSERVING
        return true
    }

    @Synchronized fun phase(token: Long): KakaoAcceptPhase? = pending?.takeIf { it.token == token }?.phase

    @Synchronized fun finish(token: Long, result: KakaoAcceptResult, resultCallId: String?, now: Long, terminalRejection: Boolean = false): KakaoAcceptFinish {
        val attempt = pending ?: return KakaoAcceptFinish.IGNORED
        if (attempt.token != token) return KakaoAcceptFinish.IGNORED
        if (result == KakaoAcceptResult.LOADING) return KakaoAcceptFinish.IGNORED
        if (result == KakaoAcceptResult.SUCCESS && attempt.phase != KakaoAcceptPhase.OBSERVING &&
            attempt.phase != KakaoAcceptPhase.UNKNOWN) return KakaoAcceptFinish.IGNORED
        if (result == KakaoAcceptResult.UNKNOWN ||
            (result == KakaoAcceptResult.SUCCESS && resultCallId != attempt.callId)) {
            attempt.phase = KakaoAcceptPhase.UNKNOWN
            return KakaoAcceptFinish.UNKNOWN
        }
        pending = null
        if (result == KakaoAcceptResult.FAILURE) {
            if (attempt.generation == generation) {
                retryAfter[attempt.callId] = if (terminalRejection) Long.MAX_VALUE else now + retryDelayMs
                while (retryAfter.size > 200) retryAfter.remove(retryAfter.keys.first())
            }
            return KakaoAcceptFinish.FAILURE
        }
        succeeded.add(attempt.callId)
        while (succeeded.size > 200) succeeded.remove(succeeded.first())
        return if (detecting && attempt.generation == generation) {
            KakaoAcceptFinish.SUCCESS
        } else KakaoAcceptFinish.STALE_SUCCESS
    }
}

internal data class KakaoNativeAcceptEvent(
    val result: KakaoAcceptResult,
    val callId: String? = null,
    val errorType: String? = null,
    val terminalRejection: Boolean = false
)

internal class KakaoNativeAcceptBridge(
    val hostClass: Class<*>,
    private val sourceClass: Class<*>,
    private val taskClass: Class<*>,
    private val callbackClass: Class<*>,
    private val loadingClass: Class<*>,
    private val successClass: Class<*>,
    private val failureClass: Class<*>,
    private val ongoingClass: Class<*>,
    private val callClass: Class<*>,
    val startMethod: Method,
    val dispatchMethod: Method,
    private val serverErrorClass: Class<*>? = null,
    private val serverErrorParser: Method? = null
) {
    private val callbackMethod = callbackClass.getDeclaredMethod("j", Any::class.java).apply { isAccessible = true }

    fun start(host: Any, callId: String, source: DirectAcceptSource, miniDetail: Boolean, vip: Boolean) {
        startMethod.invoke(host, callId, sourceValue(source), miniDetail, vip)
    }

    fun isBusy(host: Any): Boolean {
        val holder = field(host, "w") ?: error("Native acceptance state unavailable")
        val state = holder.javaClass.getMethod("getValue").apply { isAccessible = true }.invoke(holder)
            ?: error("Native acceptance state empty")
        val result = state.javaClass.getDeclaredMethod("b").apply { isAccessible = true }.invoke(state)
        return loadingClass.isInstance(result)
    }

    fun matches(task: Any?, host: Any, attempt: KakaoAcceptAttempt): Boolean =
        taskClass.isInstance(task) && field(task, "e") == 1 &&
                field(task, "g") === host && field(task, "h") == attempt.callId &&
                field(task, "i") === sourceValue(attempt.source)

    fun wrap(args: Array<out Any?>, host: Any, attempt: KakaoAcceptAttempt, observe: (KakaoNativeAcceptEvent) -> Unit): Any {
        require(args.size == 4) { "Unexpected native dispatch arity" }
        val task = args[0] ?: error("Missing native task")
        require(matches(task, host, attempt)) { "Native accept task did not match request" }
        val original = args[3] ?: error("Missing native result callback")
        require(callbackClass.isInstance(original)) { "Unexpected native callback" }
        return Proxy.newProxyInstance(callbackClass.classLoader, arrayOf(callbackClass)) { proxy, method, values ->
            when {
                method.name == "toString" && method.parameterCount == 0 -> "EunoraNativeAcceptObserver"
                method.name == "hashCode" && method.parameterCount == 0 -> System.identityHashCode(proxy)
                method.name == "equals" && method.parameterCount == 1 -> proxy === values?.getOrNull(0)
                method.name == "j" && method.parameterCount == 1 -> {
                    val value = values?.getOrNull(0)
                    try {
                        callbackMethod.invoke(original, value)
                    } catch (error: java.lang.reflect.InvocationTargetException) {
                        throw (error.cause ?: error)
                    } finally {
                        observe(decode(value))
                    }
                }
                else -> throw UnsupportedOperationException("Unexpected callback method ${method.name}")
            }
        }
    }

    fun decode(value: Any?): KakaoNativeAcceptEvent {
        if (loadingClass.isInstance(value)) return KakaoNativeAcceptEvent(KakaoAcceptResult.LOADING)
        if (failureClass.isInstance(value)) {
            val error = field(value, "b") as? Throwable
            val code = if (serverErrorClass?.isInstance(error) == true && error is Exception) {
                runCatching { field(serverErrorParser?.invoke(null, error), "a") as? Int }.getOrNull()
            } else null
            // Only explicit, documented business rejections establish failure.
            // Network/cancellation/unknown failures can occur after server acceptance.
            val rejected = code in setOf(7015, 7009, 7016, 7041, 7042, 3004, 7011, 7037, 7005, 7017, 3101, 3020)
            return KakaoNativeAcceptEvent(
                if (rejected) KakaoAcceptResult.FAILURE else KakaoAcceptResult.UNKNOWN,
                errorType = if (rejected) "ServerRejected:$code" else error?.javaClass?.simpleName,
                terminalRejection = rejected
            )
        }
        if (successClass.isInstance(value)) {
            val ongoing = field(value, "b")
            val call = if (ongoingClass.isInstance(ongoing)) field(ongoing, "a") else null
            val id = if (callClass.isInstance(call)) field(call, "a") as? String else null
            return KakaoNativeAcceptEvent(KakaoAcceptResult.SUCCESS, id?.takeIf { it.isNotBlank() })
        }
        return KakaoNativeAcceptEvent(KakaoAcceptResult.UNKNOWN)
    }

    private fun sourceValue(source: DirectAcceptSource): Any =
        sourceClass.enumConstants?.firstOrNull { (it as? Enum<*>)?.name == source.name }
            ?: error("Native accept source unavailable: ${source.name}")

    private fun field(instance: Any?, name: String): Any? = instance?.let {
        runCatching { it.javaClass.getDeclaredField(name).apply { isAccessible = true }.get(it) }.getOrNull()
    }

    companion object {
        fun load(loader: ClassLoader): KakaoNativeAcceptBridge {
            fun type(name: String) = Class.forName(name, false, loader)
            val host = type("oy0")
            val source = type("bq0")
            val callback = type("l44")
            require(callback.isInterface && source.isEnum) { "Unsupported native accept contract" }
            val nativeSources = source.enumConstants?.map { (it as Enum<*>).name }
                ?: error("Native accept enum values unavailable")
            require(DirectAcceptSource.values().all { it.name in nativeSources }) { "Native accept source contract changed" }
            val task = type("sj")
            for (name in listOf("e", "g", "h", "i")) task.getDeclaredField(name)
            return KakaoNativeAcceptBridge(
                host, source, task, callback, type("dq5"), type("id9"), type("hk3"), type("hu6"), type("ap0"),
                host.getDeclaredMethod("i", String::class.java, source, Boolean::class.javaPrimitiveType, Boolean::class.javaPrimitiveType).apply { isAccessible = true },
                type("lj3").getDeclaredMethod("v", callback, type("im1"), type("j44"), callback).apply { isAccessible = true },
                type("kl1"), type("k45").getDeclaredMethod("P", Throwable::class.java).apply { isAccessible = true }
            )
        }
    }
}
// END KAKAO_ACCEPT_CORE

data class PlaceInfo(val dongName: String? = null, val additoryAddress: String? = null, val poi: String? = null, val completeAddress: String? = null, val name: String? = null) {
    fun searchText(): String = listOfNotNull(dongName, additoryAddress, poi, completeAddress, name).map { it.trim() }.filter { it.isNotEmpty() }.distinct().joinToString(" ")
}


internal fun ModuleMain.installKakaoAcceptTrace(classLoader: ClassLoader) {
    try {
        val o5Class = Class.forName("o5", false, classLoader)
        val rMethod = o5Class.getDeclaredMethod("r", Any::class.java, Any::class.java)
        rMethod.isAccessible = true
        ModuleMain.module?.hook(rMethod, KakaoAcceptCallHooker::class.java)
        ModuleMain.module?.log("KAKAO: acceptCall hook installed o5.r (case 2)")
    } catch (t: Throwable) {
        ModuleMain.module?.log("KAKAO: acceptCall hook FAILED", t)
    }
}


internal fun ModuleMain.installKakaoListConvertHook(classLoader: ClassLoader) {
    ModuleMain.module?.log("EUNORA: installKakaoListConvertHook stub")
}
internal fun ModuleMain.installKakaoSocketLog(classLoader: ClassLoader) {
    ModuleMain.module?.log("EUNORA: installKakaoSocketLog stub")
}
internal fun ModuleMain.installKakaoArrivalTrace(classLoader: ClassLoader) {
    ModuleMain.module?.log("EUNORA: installKakaoArrivalTrace stub")
}
internal fun ModuleMain.installKakaoAcceptLogHooks(classLoader: ClassLoader) {
    ModuleMain.module?.log("EUNORA: installKakaoAcceptLogHooks stub")
}

internal fun ModuleMain.installViewModelHooks(classLoader: ClassLoader) {
    try {
        val nativeBridge = KakaoNativeAcceptBridge.load(classLoader)
        ModuleMain.module?.hook(nativeBridge.dispatchMethod, KakaoNativeDispatchHooker::class.java)
        DirectAcceptController.configure(nativeBridge)
        for (constructor in nativeBridge.hostClass.declaredConstructors) {
            constructor.isAccessible = true
            ModuleMain.module?.hook(constructor, ViewModelConstructorHooker::class.java)
        }
        ModuleMain.module?.log("KAKAO: native oy0 accept pipeline and result observer installed")
        // 클릭 로그
        try {
            val om6Class = Class.forName("om6", false, classLoader)
            val cMethod = om6Class.getDeclaredMethod("c")
            cMethod.isAccessible = true
            ModuleMain.module?.hook(cMethod, ClickLogHooker::class.java)
            ModuleMain.module?.log("KAKAO: click log hook installed om6.c")
        } catch (t: Throwable) {
            ModuleMain.module?.log("KAKAO: click log hook FAILED", t)
        }
        // OkHttp 스택 트레이스
        try {
            val realCall = Class.forName("okhttp3.internal.connection.RealCall", false, classLoader)
            for (m in realCall.declaredMethods) {
                if (m.name == "execute" || m.name == "enqueue") {
                    m.isAccessible = true
                    ModuleMain.module?.hook(m, KakaoOkHttpStackHooker::class.java)
                }
            }
            ModuleMain.module?.log("KAKAO: OkHttp RealCall stack hook installed")
        } catch (t: Throwable) {
            ModuleMain.module?.log("KAKAO: OkHttp RealCall stack hook FAILED", t)
        }


    } catch (t: Throwable) { ModuleMain.module?.log("EUNORA: direct accept hook installation FAILED", t) }
}

internal fun ModuleMain.installNetworkResponseHook(classLoader: ClassLoader) {
    try {
        val repoClass = Class.forName("b11", false, classLoader)
        val method = repoClass.getDeclaredMethod("o", String::class.java, Class.forName("da2", false, classLoader))
        method.isAccessible = true
        ModuleMain.module?.hook(method, NetworkResponseHooker::class.java)
        ModuleMain.module?.log("EUNORA: call list hook installed at b11.o")
    } catch (t: Throwable) { ModuleMain.module?.log("EUNORA: b11.o hook installation FAILED", t) }
}

internal fun ModuleMain.installPopupResponseHook(classLoader: ClassLoader) {
    // f31.l removed in 1025 APK, popup handling merged into f31.y
    ModuleMain.module?.log("EUNORA: popup hook skipped (merged into f31.y)")
}

/**
 * 리스트 위 미니카드 2종:
 * - CallCard = fp0
 * - n11.d / n11.e = CallRequestManager.setNewCallRequest
 */
internal fun ModuleMain.installKakaoCallRequestHooks(classLoader: ClassLoader) {
    try {
        val managerClass = Class.forName("n11", false, classLoader)
        val callCardClass = resolveKakaoCallCardClass(classLoader)
        KakaoNewCallRequestHooker.configure(callCardClass)
        KakaoWaybackCardHooker.configure(callCardClass)
        for (name in listOf("d", "e")) {
            try {
                val method = managerClass.getDeclaredMethod(name, callCardClass)
                method.isAccessible = true
                ModuleMain.module?.hook(method, KakaoNewCallRequestHooker::class.java)
                ModuleMain.module?.log("EUNORA: mini-card hook installed n11.$name(${callCardClass.name})")
            } catch (t: Throwable) {
                ModuleMain.module?.log("EUNORA: mini-card hook skip n11.$name: ${t.message}")
            }
        }
    } catch (t: Throwable) {
        ModuleMain.module?.log("EUNORA: mini-card n11 hook FAILED", t)
    }
}

/**
 * 귀가지원콜 (내부명 Wayback)
 * - 10/03: dr0.k(dr0, fp0, ky). acceptTimer 로그도 이 메서드에 있다.
 * - zq0는 [I 필드와 clinit만 있어 타이머 생성자가 없다.
 * 매칭/수락은 processGeneralSocketCallCard + my0.i 경로를 탄다.
 */
internal fun ModuleMain.installKakaoWaybackHooks(classLoader: ClassLoader) {
    try {
        val host = Class.forName("dr0", false, classLoader)
        val callCardClass = resolveKakaoCallCardClass(classLoader)
        KakaoNewCallRequestHooker.configure(callCardClass)
        KakaoWaybackCardHooker.configure(callCardClass)
        var hooked = 0
        for (method in host.declaredMethods) {
            val takesCard = method.parameterTypes.any { type ->
                type == callCardClass || type.name == callCardClass.name
            }
            if (!takesCard) continue
            method.isAccessible = true
            ModuleMain.module?.hook(method, KakaoWaybackCardHooker::class.java)
            hooked++
            ModuleMain.module?.log("EUNORA: wayback hook installed ${host.name}.${method.name}(${callCardClass.name})")
        }
        if (hooked == 0) {
            throw NoSuchMethodException("${host.name} method taking ${callCardClass.name} not found")
        }
    } catch (t: Throwable) {
        ModuleMain.module?.log("EUNORA: wayback dr0 hook FAILED", t)
    }
}

internal fun ModuleMain.installKakaoCardPathHooks(classLoader: ClassLoader) {
    ModuleMain.module?.log("EUNORA: card path is f31.l popup detail uv0")
}

// ########################################################################
// 콜마너, T맵, 아이드라이브, 로지 훅 설치
// ########################################################################


// ########################################################################
// T맵 / 아이드라이브 GPS 스푸핑
// ########################################################################

/**
 * T맵: re.a(latitude, longitude) Coordinate 생성 시 좌표 교체
 */
/**
 * 카카오:
 * - Location getLat/getLng (목록 location JSON이 location.getLatitude() 사용)
 * - qh.d.A(Location) → {"lat":..,"lng":..} 최종 문자열 직접 교체
 * - mock 은 공통 GpsMockFalseHooker
 */
internal fun ModuleMain.installKakaoGpsSpoof(classLoader: ClassLoader) {
    try {
        val locationClass = Class.forName("android.location.Location", false, classLoader)
        ModuleMain.module?.hook(locationClass.getMethod("getLatitude"), KakaoGpsLatitudeHooker::class.java)
        ModuleMain.module?.hook(locationClass.getMethod("getLongitude"), KakaoGpsLongitudeHooker::class.java)
        ModuleMain.module?.log("KAKAO: GPS spoof waits for drivers/work success")

        // 1025 APK: g85.l0 / j65.s0 없음. Location 직접 훅만 사용.
        ModuleMain.module?.log("KAKAO: i9a.k map center left original")
        ModuleMain.module?.log("KAKAO: GPS spoof hooks installed (Location only)")
    } catch (t: Throwable) {
        ModuleMain.module?.log("KAKAO: GPS spoof hook FAILED", t)
    }
}

/** Local root and hook-report contracts verified against the supplied 1101 sources. */
internal fun ModuleMain.installKakaoRootingReportBypass(classLoader: ClassLoader) {
    installKakaoSentryRootTestConfig(classLoader)
    KakaoLocalSecurityHooks.install(this, classLoader)
}

internal fun ModuleMain.installKakaoReservedExclusiveHooks(classLoader: ClassLoader) {
    try {
        val reservedApi = Class.forName("e21", false, classLoader)
        val list = reservedApi.declaredMethods.firstOrNull { it.name == "y" }
        if (list != null) {
            list.isAccessible = true
            ModuleMain.module?.hook(list, KakaoReservedCallHooker::class.java)
            ModuleMain.module?.log("KAKAO: reservation list hook installed e21.y")
        }
    } catch (t: Throwable) {
        ModuleMain.module?.log("KAKAO: reservation list hook FAILED", t)
    }
    // f31.g and f31.c removed in 1025 APK, merged into f31.y
    ModuleMain.module?.log("KAKAO: reserved dispatch/exclusive merged into f31.y")
}





internal fun processCallItem(item: Any, source: String): Boolean {
    try {
        // ap0 필드: a=id, n=fixedFare, i=origin(le7), j=destination(le7), K=estimatedDistance
        val id = ModuleMain.readField(item, "a") as? String ?: return false
        val fare = (ModuleMain.readField(item, "c") as? Number)?.toInt() ?: 0
        val origin = ModuleMain.readField(item, "f")
        val dest = ModuleMain.readField(item, "g")
        val dist = (ModuleMain.readField(item, "q") as? Number)?.toDouble() ?: 0.0
        val start = if (origin != null) (ModuleMain.readField(origin, "a") as? String ?: ModuleMain.readField(origin, "b") as? String ?: "") else ""
        val arrive = if (dest != null) (ModuleMain.readField(dest, "d") as? String ?: ModuleMain.readField(dest, "a") as? String ?: ModuleMain.readField(dest, "b") as? String ?: "") else ""
        // dest 객체의 문자열 필드 전부 덤프 (전체 주소가 어느 필드에 있는지 확인)
        if (dest != null) {
            val sb = StringBuilder()
            dest.javaClass.declaredFields.forEach { f ->
                try {
                    f.isAccessible = true
                    val v = f.get(dest)
                    if (v is String && v.isNotBlank()) sb.append("${f.name}=$v | ")
                } catch (_: Throwable) {}
            }
            ModuleMain.module?.log("KAKAO: DEST FIELDS id=$id $sb")
        }
        val callData = CallData("KAKAO:$id", start, arrive, fare, dist / 1000.0)
        ModuleMain.module?.log("KAKAO: $source id=$id fare=$fare start=$start arrive=$arrive distKm=${dist / 1000.0}")
        return ModuleMain.matchAndAccept(callData)
    } catch (t: Throwable) {
        ModuleMain.module?.log("KAKAO: processCallItem error", t)
        return false
    }
}

internal fun processJv0(jv0: Any, source: String): Boolean {
    try {
        val list = ModuleMain.readField(jv0, "a") as? List<*> ?: return false
        list.forEach { item -> if (item != null) processCallItem(item, source) }
        return true
    } catch (t: Throwable) {
        return false
    }
}

@XposedHooker
class NetworkResponseHooker : XposedInterface.Hooker {
    companion object {
        @Volatile private var dtoClass: Class<*>? = null

        fun configure(cls: Class<*>) {
            dtoClass = cls
        }

        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            val result = callback.result ?: return
            try {
                // vy0: a=onDemand jv0, b=reservation jv0, c=previousCallIds (String list)
                val vy0 = result
                val onDemand = ModuleMain.readField(vy0, "a")
                val reservation = ModuleMain.readField(vy0, "b")
                ModuleMain.module?.log("KAKAO: list onDemand=${onDemand != null} reservation=${reservation != null}")
                // jv0.a = List<ap0>
                if (onDemand != null) processJv0(onDemand, "ON_DEMAND")
                if (reservation != null) processJv0(reservation, "RESERVATION")
            } catch (t: Throwable) {
                ModuleMain.module?.log("KAKAO: network response error", t)
            }
        }
    }
}

@XposedHooker
class PopupResponseHooker : XposedInterface.Hooker {
    companion object {
        @Volatile private var popupDtoClass: Class<*>? = null

        fun configure(cls: Class<*>) {
            popupDtoClass = cls
        }

        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            val result = callback.result ?: return
            try {
                val dto = if (result.javaClass.name.contains("Result")) {
                    ModuleMain.readField(result, "value") ?: return
                } else result
                ModuleMain.module?.log("KAKAO: popup response dto=${dto.javaClass.name}")
                ModuleMain.processPopupDto(dto)
            } catch (t: Throwable) {
                ModuleMain.module?.log("KAKAO: popup response error", t)
            }
        }
    }
}

@XposedHooker
class KakaoAcceptCallHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            val thisObj = callback.thisObject ?: return
            val hField = thisObj.javaClass.getDeclaredField("h")
            hField.isAccessible = true
            val h = hField.getInt(thisObj)
            if (h != 2) return
            val args = callback.args
            val callId = args.getOrNull(0) as? String ?: ""
            ModuleMain.module?.log("KAKAO: acceptCall called id=$callId")
            try {
                val stack = Thread.currentThread().stackTrace
                    .take(25)
                    .joinToString("\n") { "  at ${it.className}.${it.methodName}:${it.lineNumber}" }
                ModuleMain.module?.log("KAKAO: acceptCall stack:\n$stack")
            } catch (t: Throwable) {
                ModuleMain.module?.log("KAKAO: stack trace failed", t)
            }
        }
    }
}

@XposedHooker
class AcceptMethodHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            val callId = callback.args.getOrNull(0) as? String
            ModuleMain.module?.log("KAKAO: accept method called callId=$callId")
        }
    }
}

@XposedHooker
class ViewModelConstructorHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            DirectAcceptController.captureViewModel(callback.thisObject, "constructor")
        }
    }
}

@XposedHooker
class KakaoNewCallRequestHooker : XposedInterface.Hooker {
    companion object {
        @Volatile private var callCardClass: Class<*>? = null

        fun configure(cls: Class<*>) {
            callCardClass = cls
        }

        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            val expectedClass = callCardClass ?: return
            val card = KakaoCardData.findArgument(callback.args, expectedClass) ?: return
            try {
                ModuleMain.module?.log("KAKAO: new call request card=${card.javaClass.name}")
                ModuleMain.processGeneralSocketCallCard(card, "MINI_CARD")
            } catch (t: Throwable) {
                ModuleMain.module?.log("KAKAO: new call request error", t)
            }
        }
    }
}

@XposedHooker
class KakaoWaybackCardHooker : XposedInterface.Hooker {
    companion object {
        @Volatile private var callCardClass: Class<*>? = null

        fun configure(cls: Class<*>) {
            callCardClass = cls
        }

        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            val expectedClass = callCardClass ?: return
            val card = KakaoCardData.findArgument(callback.args, expectedClass) ?: return
            try {
                ModuleMain.module?.log("KAKAO: wayback card=${card.javaClass.name}")
                ModuleMain.processGeneralSocketCallCard(card, "WAYBACK")
            } catch (t: Throwable) {
                ModuleMain.module?.log("KAKAO: wayback error", t)
            }
        }
    }
}

@XposedHooker
class KakaoGpsLatitudeHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            val pair = GpsSpoofState.activeLatLng() ?: return
            try {
                callback.result = pair.first
            } catch (t: Throwable) {}
        }
    }
}

@XposedHooker
class KakaoGpsLongitudeHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            val pair = GpsSpoofState.activeLatLng() ?: return
            try {
                callback.result = pair.second
            } catch (t: Throwable) {}
        }
    }
}

@XposedHooker
class KakaoLocationJsonHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            val pair = GpsSpoofState.activeLatLng() ?: return
            ModuleMain.module?.log("KAKAO: location json hook lat=${pair.first}")
        }
    }
}

// BEGIN KAKAO_HOOK_SIGNAL_DIAGNOSTICS
/** Read-only view of the supplied APK's hook report. No raw paths, tokens or user IDs are logged. */
internal object KakaoHookSignalDiagnostics {
    data class Layout(
        val reportClass: Class<*>, val assessmentClass: Class<*>,
        val assessmentField: java.lang.reflect.Field,
        val signalFields: List<java.lang.reflect.Field>, val statusMethod: Method
    )

    data class Snapshot(
        val status: String, val counts: List<Int>,
        val markerHints: Set<String>, val sampleTruncated: Boolean
    )

    private val markers = listOf(
        "EUNORA" to listOf("com.example.wheelprobe"),
        "LSPOSED" to listOf("org.lsposed", "LSPosed", "LSPHooker_", "lspd"),
        "XPOSED" to listOf("de.robv.android.xposed", "XposedBridge"),
        "RIRU" to listOf("riru"), "EPIC" to listOf("me.weishu.epic")
    )

    fun resolve(reportClass: Class<*>, assessmentClass: Class<*>): Layout {
        val assessmentField = reportClass.getDeclaredField("a")
        require(assessmentField.type == assessmentClass && !Modifier.isStatic(assessmentField.modifiers)) {
            "unexpected hook assessment field"
        }
        val probeField = reportClass.getDeclaredField("b")
        require(probeField.type == java.util.LinkedHashMap::class.java && !Modifier.isStatic(probeField.modifiers)) {
            "unexpected hook report shape"
        }
        val fields = listOf("a", "b", "c", "d", "e", "f").map { name ->
            assessmentClass.getDeclaredField(name).apply {
                require(type == java.util.List::class.java && !Modifier.isStatic(modifiers)) {
                    "unexpected hook signal field"
                }
                isAccessible = true
            }
        }
        val statusMethod = reportClass.getDeclaredMethod("c").apply {
            require(returnType == String::class.java && !Modifier.isStatic(modifiers)) {
                "unexpected hook report status method"
            }
            isAccessible = true
        }
        assessmentField.isAccessible = true
        return Layout(reportClass, assessmentClass, assessmentField, fields, statusMethod)
    }

    fun snapshot(report: Any?, layout: Layout): Snapshot {
        require(report != null && layout.reportClass.isInstance(report)) { "unexpected hook report instance" }
        val assessment = layout.assessmentField.get(report)
        require(assessment != null && layout.assessmentClass.isInstance(assessment)) { "missing hook assessment" }
        val lists = layout.signalFields.map { field ->
            field.get(assessment) as? List<*> ?: error("missing hook signal list")
        }
        val rawStatus = layout.statusMethod.invoke(report) as? String
        val status = when (rawStatus) {
            "detected", "not_detected", "unknown" -> rawStatus
            else -> "STATUS_UNEXPECTED"
        }
        val hints = linkedSetOf<String>()
        for (list in lists) {
            for (index in 0 until minOf(list.size, 64)) {
                val entry = list[index] as? String ?: continue
                for ((label, values) in markers) {
                    if (values.any { entry.contains(it, ignoreCase = true) }) hints.add(label)
                }
            }
        }
        return Snapshot(status, lists.map { it.size }, hints, lists.any { it.size > 64 })
    }

    data class StackDetails(
        val total: Int, val classes: List<String>, val redacted: Int, val truncated: Boolean
    )

    fun safeStackClass(value: Any?): String? {
        val name = value as? String ?: return null
        if (name.isEmpty() || name.length > 256) return null
        fun startsIdentifier(c: Char) = c in 'A'..'Z' || c in 'a'..'z' || c == '_' || c == '$'
        if (!name.split('.').all { part ->
                part.isNotEmpty() && startsIdentifier(part[0]) &&
                        part.all { startsIdentifier(it) || it in '0'..'9' }
            }) return null
        val knownPackage = listOf(
            "org.lsposed.", "de.robv.android.xposed.", "com.elderdrivers.riru.",
            "me.weishu.epic.", "com.example.wheelprobe."
        ).any { name.startsWith(it) }
        val generatedClass = '.' !in name &&
                name.substringBefore('$') in setOf("LSPHooker_", "LSPosedBridge", "HookBridge")
        return name.takeIf { knownPackage || generatedClass }
    }

    fun stackDetails(report: Any?, layout: Layout): StackDetails {
        require(report != null && layout.reportClass.isInstance(report)) { "unexpected hook report instance" }
        val assessment = layout.assessmentField.get(report)
        require(assessment != null && layout.assessmentClass.isInstance(assessment)) { "missing hook assessment" }
        val entries = layout.signalFields[0].get(assessment) as? List<*>
            ?: error("missing hook stack list")
        val classes = mutableListOf<String>()
        var redacted = 0
        for (index in 0 until minOf(entries.size, 16)) {
            val name = safeStackClass(entries[index])
            if (name == null) redacted++ else classes.add(name)
        }
        return StackDetails(entries.size, classes, redacted, entries.size > 16)
    }

    fun formatStackDetails(details: StackDetails): List<String> {
        require(details.total >= 0 && details.redacted >= 0 &&
                details.total.toLong() >= details.classes.size.toLong() + details.redacted) {
            "unexpected stack detail counts"
        }
        val sample = details.classes.take(16)
        val safe = sample.mapNotNull { safeStackClass(it) }
        val redacted = details.redacted + sample.size - safe.size
        val truncated = details.truncated || details.classes.size > 16
        return safe.mapIndexed { index, name ->
            "KAKAO_DIAG: STACK_CLASS index=${index + 1} className=$name resultChanged=false"
        } + ("KAKAO_DIAG: STACK_CLASSES total=${details.total} logged=${safe.size} " +
                "redacted=$redacted sampleTruncated=$truncated resultChanged=false")
    }

    fun format(snapshot: Snapshot): String {
        val counts = snapshot.counts
        require(counts.size == 6 && counts.all { it >= 0 }) { "unexpected hook signal count" }
        val status = snapshot.status.takeIf { it in setOf("detected", "not_detected", "unknown", "STATUS_UNEXPECTED") }
            ?: "STATUS_UNEXPECTED"
        val hints = markers.map { it.first }.filter { it in snapshot.markerHints }
        return "KAKAO_DIAG: SIGNALS status=$status " +
                "hook(stack=${counts[0]},classes=${counts[4]}) " +
                "memory(artifacts=${counts[2]},foreign=${counts[3]}) " +
                "api(native=${counts[1]},missing=${counts[5]}) " +
                "markerHints=${hints.joinToString("|").ifEmpty { "NONE_IN_SAMPLE" }} " +
                "sampleTruncated=${snapshot.sampleTruncated} resultChanged=false serverVerdict=UNVERIFIED"
    }
}
// END KAKAO_HOOK_SIGNAL_DIAGNOSTICS

// BEGIN_KAKAO_SENTRY_TEST_CONFIG
/** Use the SDK's supported diagnostic setting; do not manufacture a clean root verdict. */
internal object KakaoSentryRootTestConfig {
    fun resolve(optionsClass: Class<*>): Pair<Method, Method> {
        val setter = optionsClass.getDeclaredMethod("setEnableRootCheck", java.lang.Boolean.TYPE)
        val getter = optionsClass.getDeclaredMethod("isEnableRootCheck")
        require(setter.returnType == Void.TYPE && getter.returnType == java.lang.Boolean.TYPE) {
            "unexpected Sentry diagnostic option signature"
        }
        for (method in listOf(setter, getter)) {
            require(Modifier.isPublic(method.modifiers) && !Modifier.isStatic(method.modifiers)) {
                "expected public instance option methods"
            }
            method.isAccessible = true
        }
        return setter to getter
    }

    fun apply(options: Any, setter: Method, getter: Method): Boolean {
        require(setter.declaringClass.isInstance(options) && getter.declaringClass.isInstance(options)) {
            "unexpected Sentry options instance"
        }
        setter.invoke(options, false)
        return (getter.invoke(options) as? Boolean) == false
    }
}
// END_KAKAO_SENTRY_TEST_CONFIG

// BEGIN_KAKAO_SENTRY_OPTIONS_HOOK
@XposedHooker
class KakaoSentryOptionsHooker : XposedInterface.Hooker {
    companion object {
        private val optionMethods = java.util.concurrent.ConcurrentHashMap<
                java.lang.reflect.Member, Pair<Method, Method>>()

        fun install(module: ModuleMain, constructor: java.lang.reflect.Constructor<*>,
                    setter: Method, getter: Method) {
            synchronized(optionMethods) {
                if (optionMethods.containsKey(constructor)) return
                // Each target class loader keeps its own option methods. Roll back
                // this member only if registration fails; other loaders stay valid.
                optionMethods[constructor] = setter to getter
                try {
                    module.hook(constructor, KakaoSentryOptionsHooker::class.java)
                } catch (error: Throwable) {
                    optionMethods.remove(constructor)
                    throw error
                }
            }
        }

        private fun log(message: String) {
            runCatching { ModuleMain.module?.log(message) }
        }

        @JvmStatic @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            try {
                val methods = optionMethods[callback.member]
                val options = callback.args.getOrNull(1)
                if (methods == null || options == null) {
                    log("KAKAO: Sentry root diagnostic test config NOT_APPLIED reason=MISSING_CONFIGURATION")
                    return
                }
                val applied = KakaoSentryRootTestConfig.apply(options, methods.first, methods.second)
                log("KAKAO: Sentry root diagnostic test config settingApplied=$applied " +
                        "requestedEnableRootCheck=false rootVerdict=NOT_FORGED serverVerdict=UNVERIFIED")
            } catch (error: Throwable) {
                log("KAKAO: Sentry root diagnostic test config APPLY_UNCONFIRMED type=${error.javaClass.name}")
            }
        }
    }
}
// END_KAKAO_SENTRY_OPTIONS_HOOK

private fun ModuleMain.installKakaoSentryRootTestConfig(classLoader: ClassLoader) {
    val module = ModuleMain.module ?: return
    try {
        val optionsClass = Class.forName("io.sentry.android.core.SentryAndroidOptions", false, classLoader)
        val methods = KakaoSentryRootTestConfig.resolve(optionsClass)
        val contextClass = Class.forName("io.sentry.android.core.r0", false, classLoader)
        require(contextClass.getDeclaredField("b").type == optionsClass) { "Sentry context options field mismatch" }
        require(contextClass.getDeclaredField("g").type == Class.forName("io.sentry.protocol.q", false, classLoader)) {
            "Sentry OS context field mismatch"
        }
        val constructor = contextClass.getDeclaredConstructor(Context::class.java, optionsClass)
        constructor.isAccessible = true
        KakaoSentryOptionsHooker.install(module, constructor, methods.first, methods.second)
        runCatching {
            module.log("KAKAO: Sentry root diagnostic test config hook installed " +
                    "option=enableRootCheck target=r0(Context,SentryAndroidOptions) coldStartRequired=true")
        }
    } catch (error: Throwable) {
        runCatching {
            module.log("KAKAO: Sentry root diagnostic test config UNAVAILABLE type=${error.javaClass.name}")
        }
    }
}

// BEGIN KAKAO_ROOT_FILE_PROFILE
internal object KakaoRootFileProfile {
    // File.exists paths in the provided APK: business checks + Sentry/Crashlytics diagnostics.
    // Commands, installed-package checks and other security mechanisms are separate.
    val paths: Set<String> = setOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su", "/su/bin/su",
        "/sbin/.magisk", "/data/adb/magisk",
        "/system/app/Superuser.apk", "/system/app/SuperSU",
        "/su/bin", "/system/xbin/daemonsu"
    )

    fun matches(path: String?): Boolean = path != null && path in paths
}
// END KAKAO_ROOT_FILE_PROFILE

// BEGIN KAKAO_ROOT_FILE_HOOK
@XposedHooker
class KakaoRootFileHooker : XposedInterface.Hooker {
    companion object {
        private val loggedChanges = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                if (callback.throwable != null) return
                val file = callback.thisObject as? java.io.File ?: return
                val path = file.path
                if (!KakaoRootFileProfile.matches(path)) return
                val wasPresent = callback.result as? Boolean ?: return
                if (!wasPresent) return
                callback.result = false
                if (loggedChanges.add(path)) {
                    ModuleMain.module?.log("KAKAO: root file result changed path=$path original=true result=false")
                }
            } catch (error: Throwable) {
                runCatching { ModuleMain.module?.log("KAKAO: root file hook error", error) }
            }
        }
    }
}
// END KAKAO_ROOT_FILE_HOOK

// Shared by E03/Tmap; only exact known root paths and successful Boolean results are changed.
@XposedHooker
class KakaoRootPathHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                if (callback.throwable != null) return
                val file = callback.thisObject as? java.io.File ?: return
                if (!KakaoRootFileProfile.matches(file.path)) return
                val original = callback.result as? Boolean ?: return
                if (original) {
                    callback.result = false
                    runCatching { ModuleMain.module?.log("TMAP: root file result changed original=true result=false") }
                }
            } catch (error: Throwable) {
                runCatching { ModuleMain.module?.log("TMAP: root file result UNCONFIRMED type=${error.javaClass.name}") }
            }
        }
    }
}

/** Exact local layouts from the supplied 3.14.5/1101 sources; no guessed coroutine or request hooks. */
internal object KakaoLocalSecurityHooks {
    data class RootLayout(
        val owner: Class<*>, val modeField: java.lang.reflect.Field,
        val rootedField: java.lang.reflect.Field
    )

    data class ReportLayout(
        val diagnostics: KakaoHookSignalDiagnostics.Layout,
        val assessmentConstructor: java.lang.reflect.Constructor<*>,
        val reportConstructor: java.lang.reflect.Constructor<*>,
        val probesField: java.lang.reflect.Field,
        val checkedAtField: java.lang.reflect.Field,
        val durationField: java.lang.reflect.Field
    )

    data class ReportChange(
        val result: Any, val before: KakaoHookSignalDiagnostics.Snapshot,
        val after: KakaoHookSignalDiagnostics.Snapshot
    )

    data class SdkLayout(
        val kind: String, val paths: java.lang.reflect.Field? = null,
        val packages: java.lang.reflect.Field? = null,
        val runtime: java.lang.reflect.Field? = null
    )

    private val installed = java.util.concurrent.ConcurrentHashMap.newKeySet<java.lang.reflect.Member>()
    private val roots = java.util.concurrent.ConcurrentHashMap<java.lang.reflect.Member, RootLayout>()
    private val reports = java.util.concurrent.ConcurrentHashMap<java.lang.reflect.Member, ReportLayout>()
    private val sdkMethods = java.util.concurrent.ConcurrentHashMap<java.lang.reflect.Member, SdkLayout>()

    internal fun log(message: String) { runCatching { ModuleMain.module?.log(message) } }
    internal fun rootLayout(member: java.lang.reflect.Member) = roots[member]
    internal fun reportLayout(member: java.lang.reflect.Member) = reports[member]
    internal fun sdkLayout(member: java.lang.reflect.Member) = sdkMethods[member]

    private fun <T> register(member: java.lang.reflect.Member, action: () -> T) {
        synchronized(installed) {
            if (member in installed) return
            action()
            installed.add(member)
        }
    }

    private fun installTarget(label: String, action: () -> Unit) {
        try { action() }
        catch (error: Throwable) {
            log("KAKAO_SECURITY: UNAVAILABLE target=$label type=${error.javaClass.name} action=KEEP_ORIGINAL")
        }
    }

    internal fun resolveRoot(owner: Class<*>, mode: Class<*>): RootLayout {
        require(mode.isEnum) { "root mode is not the expected enum" }
        val fields = owner.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }
        require(fields.map { it.name }.toSet() == setOf("a", "b")) { "unexpected root status fields" }
        val modeField = owner.getDeclaredField("a")
        val rootedField = owner.getDeclaredField("b")
        require(modeField.type == mode && rootedField.type == java.lang.Boolean.TYPE) { "root field types differ" }
        modeField.isAccessible = true
        rootedField.isAccessible = true
        return RootLayout(owner, modeField, rootedField)
    }

    internal fun setRootedFalse(value: Any?, layout: RootLayout): Boolean {
        require(value != null && layout.owner.isInstance(value)) { "unexpected root status instance" }
        require(value.toString().startsWith("RootingStatus(")) { "unexpected root status meaning" }
        require(layout.modeField.get(value) != null) { "missing root check mode" }
        val original = layout.rootedField.getBoolean(value)
        if (original) layout.rootedField.setBoolean(value, false)
        check(!layout.rootedField.getBoolean(value)) { "root flag change was not retained" }
        return original
    }

    internal fun resolveReport(report: Class<*>, assessment: Class<*>): ReportLayout {
        require(report.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }.map { it.name }.toSet() ==
                setOf("a", "b", "c", "d")) { "unexpected hook report fields" }
        require(assessment.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }.map { it.name }.toSet() ==
                setOf("a", "b", "c", "d", "e", "f", "g")) { "unexpected hook assessment fields" }
        require(java.util.Set::class.java.isAssignableFrom(assessment.getDeclaredField("g").type)) {
            "unexpected derived signal type"
        }
        val diagnostics = KakaoHookSignalDiagnostics.resolve(report, assessment)
        val assessmentConstructor = assessment.getDeclaredConstructor(*Array(6) { java.util.List::class.java })
            .apply { isAccessible = true }
        val reportConstructor = report.getDeclaredConstructor(
            assessment, java.util.LinkedHashMap::class.java, java.lang.Long.TYPE, java.lang.Long.TYPE
        ).apply { isAccessible = true }
        val probes = report.getDeclaredField("b").apply { isAccessible = true }
        val checkedAt = report.getDeclaredField("c").apply { isAccessible = true }
        val duration = report.getDeclaredField("d").apply { isAccessible = true }
        require(checkedAt.type == java.lang.Long.TYPE && duration.type == java.lang.Long.TYPE) { "unexpected time fields" }
        val empty = emptyList<Any>()
        val probeAssessment = assessmentConstructor.newInstance(empty, empty, empty, empty, empty, empty)
        require(probeAssessment.toString().startsWith("HookDetectionAssessment(")) { "unexpected assessment meaning" }
        val probeReport = reportConstructor.newInstance(probeAssessment, java.util.LinkedHashMap<Any, Any>(), 0L, 0L)
        require(probeReport.toString().startsWith("HookDetectionReport(")) { "unexpected report meaning" }
        require(KakaoHookSignalDiagnostics.snapshot(probeReport, diagnostics).status == "not_detected") {
            "unexpected clean report contract"
        }
        return ReportLayout(diagnostics, assessmentConstructor, reportConstructor, probes, checkedAt, duration)
    }

    internal fun normalizeReport(value: Any?, layout: ReportLayout): ReportChange {
        require(value != null && layout.diagnostics.reportClass.isInstance(value)) { "unexpected hook report instance" }
        require(value.toString().startsWith("HookDetectionReport(")) { "unexpected report meaning" }
        val before = KakaoHookSignalDiagnostics.snapshot(value, layout.diagnostics)
        require(before.status != "STATUS_UNEXPECTED") { "unexpected hook report status" }
        val originalAssessment = layout.diagnostics.assessmentField.get(value)
        require(originalAssessment != null && originalAssessment.toString().startsWith("HookDetectionAssessment(")) {
            "unexpected assessment meaning"
        }
        // The first five lists are hook observations. Genuine missing framework
        // APIs and probe errors remain visible; the constructor recomputes g.
        val missing = (layout.diagnostics.signalFields[5].get(originalAssessment) as? List<*>)
            ?.toList() ?: error("missing framework API list")
        val originalProbes = layout.probesField.get(value) as? java.util.LinkedHashMap<*, *>
            ?: error("missing hook probe statuses")
        val probes = java.util.LinkedHashMap<Any?, Any?>().apply { putAll(originalProbes) }
        val checkedAt = layout.checkedAtField.getLong(value)
        val duration = layout.durationField.getLong(value)
        val empty = emptyList<Any>()
        val assessment = layout.assessmentConstructor.newInstance(empty, empty, empty, empty, empty, missing)
        val result = layout.reportConstructor.newInstance(assessment, probes, checkedAt, duration)
        val after = KakaoHookSignalDiagnostics.snapshot(result, layout.diagnostics)
        require(after.status != "STATUS_UNEXPECTED" && after.counts.take(5).all { it == 0 } &&
                after.counts[5] == before.counts[5]) { "hook assessment normalization differs" }
        require(layout.probesField.get(result) == originalProbes &&
                layout.checkedAtField.getLong(result) == checkedAt && layout.durationField.getLong(result) == duration) {
            "hook report metadata changed"
        }
        return ReportChange(result, before, after)
    }

    internal fun sdkMatches(value: Any?, layout: SdkLayout): Boolean {
        if (layout.kind == "CRASHLYTICS_1101") {
            // ar1 is an obfuscated utility owner. A prototype alone is not a
            // semantic contract across updates; limit it to the supplied build.
            val context = ModuleMain.getApplicationContext() ?: return false
            if (context.packageName != "com.kakao.wheel.driver") return false
            return runCatching {
                context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode == 3145099L
            }.getOrDefault(false)
        }
        if (layout.kind != "SENTRY_ROOTCHECKER" || value == null) return false
        val paths = layout.paths?.get(value) as? Array<*> ?: return false
        val packages = layout.packages?.get(value) as? Array<*> ?: return false
        return layout.runtime?.get(value) is Runtime && paths.any { it == "/system/xbin/su" } &&
                packages.any { it == "eu.chainfire.supersu" || it == "com.koushikdutta.superuser" }
    }

    fun install(module: ModuleMain, loader: ClassLoader) {
        installTarget("qf8(ht7,boolean)") {
            val owner = Class.forName("qf8", false, loader)
            val mode = Class.forName("ht7", false, loader)
            val layout = resolveRoot(owner, mode)
            val constructor = owner.getDeclaredConstructor(mode, java.lang.Boolean.TYPE).apply { isAccessible = true }
            register(constructor) {
                roots[constructor] = layout
                module.hook(constructor, KakaoRootingStatusHooker::class.java)
            }
            log("KAKAO_SECURITY: REGISTERED target=qf8(ht7,boolean) action=ROOTED_FALSE execution=UNVERIFIED")
        }
        installTarget("il4.b()bl4") {
            val owner = Class.forName("il4", false, loader)
            val report = Class.forName("bl4", false, loader)
            val assessment = Class.forName("zk4", false, loader)
            val layout = resolveReport(report, assessment)
            val method = owner.getDeclaredMethod("b").apply {
                require(returnType == report && !Modifier.isStatic(modifiers) &&
                        !Modifier.isAbstract(modifiers) && !Modifier.isNative(modifiers)) { "unexpected detector signature" }
                isAccessible = true
            }
            register(method) {
                reports[method] = layout
                module.hook(method, KakaoHookDetectionHooker::class.java)
            }
            log("KAKAO_SECURITY: REGISTERED target=il4.b action=NORMALIZE_HOOK_SIGNALS preserved=FRAMEWORK_API_AND_PROBE_ERRORS execution=UNVERIFIED")
        }
        installTarget("io.sentry.android.core.internal.util.i.a()boolean") {
            val owner = Class.forName("io.sentry.android.core.internal.util.i", false, loader)
            val paths = owner.getDeclaredField("d").apply { isAccessible = true }
            val packages = owner.getDeclaredField("e").apply { isAccessible = true }
            val runtime = owner.getDeclaredField("f").apply { isAccessible = true }
            require(paths.type == Array<String>::class.java && packages.type == Array<String>::class.java &&
                    runtime.type == Runtime::class.java && listOf(paths, packages, runtime).none { Modifier.isStatic(it.modifiers) }) {
                "unexpected Sentry root checker fields"
            }
            val method = owner.getDeclaredMethod("a").apply {
                require(returnType == java.lang.Boolean.TYPE && !Modifier.isStatic(modifiers) &&
                        !Modifier.isAbstract(modifiers) && !Modifier.isNative(modifiers)) { "unexpected Sentry root signature" }
                isAccessible = true
            }
            register(method) {
                sdkMethods[method] = SdkLayout("SENTRY_ROOTCHECKER", paths, packages, runtime)
                module.hook(method, KakaoSdkRootBooleanHooker::class.java)
            }
            log("KAKAO_SECURITY: REGISTERED target=SENTRY_ROOTCHECKER action=BOOLEAN_FALSE execution=UNVERIFIED")
        }
        installTarget("ar1.I()boolean") {
            val owner = Class.forName("ar1", false, loader)
            val method = owner.getDeclaredMethod("I").apply {
                require(returnType == java.lang.Boolean.TYPE && Modifier.isStatic(modifiers) &&
                        !Modifier.isAbstract(modifiers) && !Modifier.isNative(modifiers)) { "unexpected Crashlytics root signature" }
                isAccessible = true
            }
            register(method) {
                sdkMethods[method] = SdkLayout("CRASHLYTICS_1101")
                module.hook(method, KakaoSdkRootBooleanHooker::class.java)
            }
            log("KAKAO_SECURITY: REGISTERED target=ar1.I action=BOOLEAN_FALSE targetVersion=3145099 execution=UNVERIFIED")
        }
        installTarget("File.exists()boolean") {
            val method = java.io.File::class.java.getDeclaredMethod("exists").apply {
                require(returnType == java.lang.Boolean.TYPE && !Modifier.isStatic(modifiers)) { "unexpected File.exists signature" }
                isAccessible = true
            }
            register(method) { module.hook(method, KakaoRootFileHooker::class.java) }
            log("KAKAO_SECURITY: REGISTERED target=File.exists action=EXACT_ROOT_PATH_FALSE execution=UNVERIFIED")
        }
        log("KAKAO_SECURITY: UNCONFIGURED stages=INTEGRITY_TOKEN,HTTP_BODY,WORK_REQUEST,POLICY_DIALOG reason=NO_VERIFIED_LOCAL_CONTRACT action=KEEP_ORIGINAL")
    }
}

@XposedHooker
class KakaoRootingStatusHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                if (callback.throwable != null) return
                val layout = KakaoLocalSecurityHooks.rootLayout(callback.member) ?: return
                val changed = KakaoLocalSecurityHooks.setRootedFalse(callback.thisObject, layout)
                KakaoLocalSecurityHooks.log("KAKAO_SECURITY: ROOT_STATUS originalRooted=$changed rooted=false resultChanged=$changed checkType=PRESERVED")
            } catch (error: Throwable) {
                KakaoLocalSecurityHooks.log("KAKAO_SECURITY: ROOT_STATUS_UNCONFIRMED type=${error.javaClass.name} action=KEEP_ORIGINAL")
            }
        }
    }
}

@XposedHooker
class KakaoSdkRootBooleanHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                if (callback.throwable != null) return
                val layout = KakaoLocalSecurityHooks.sdkLayout(callback.member) ?: return
                val original = callback.result as? Boolean ?: return
                if (!KakaoLocalSecurityHooks.sdkMatches(callback.thisObject, layout)) {
                    KakaoLocalSecurityHooks.log("KAKAO_SECURITY: SDK_ROOT_UNCONFIRMED profile=${layout.kind} action=KEEP_ORIGINAL")
                    return
                }
                if (original) callback.result = false
                KakaoLocalSecurityHooks.log("KAKAO_SECURITY: SDK_ROOT profile=${layout.kind} original=$original result=false resultChanged=$original")
            } catch (error: Throwable) {
                KakaoLocalSecurityHooks.log("KAKAO_SECURITY: SDK_ROOT_UNCONFIRMED type=${error.javaClass.name} action=KEEP_ORIGINAL")
            }
        }
    }
}

@XposedHooker
class KakaoHookDetectionHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                if (callback.throwable != null) {
                    KakaoLocalSecurityHooks.log("KAKAO_SECURITY: ORIGINAL_CHECK_FAILED type=${callback.throwable?.javaClass?.name} action=KEEP_ORIGINAL")
                    return
                }
                val layout = KakaoLocalSecurityHooks.reportLayout(callback.member) ?: return
                val change = KakaoLocalSecurityHooks.normalizeReport(callback.result, layout)
                callback.result = change.result
                KakaoLocalSecurityHooks.log("KAKAO_SECURITY: HOOK_ASSESSMENT originalStatus=${change.before.status} resultStatus=${change.after.status} " +
                        "signalsBefore=${change.before.counts.take(5).joinToString(",")} signalsAfter=${change.after.counts.take(5).joinToString(",")} " +
                        "missingFrameworkApis=${change.after.counts[5]} probeErrors=PRESERVED resultChanged=true")
            } catch (error: Throwable) {
                KakaoLocalSecurityHooks.log("KAKAO_SECURITY: HOOK_RESULT_UNCONFIRMED type=${error.javaClass.name} action=KEEP_ORIGINAL")
            }
        }
    }
}


@XposedHooker
class KakaoReservedCallHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            val result = callback.result ?: return
            try {
                ModuleMain.module?.log("KAKAO: reserved call response")
                ModuleMain.processDtoGroup(result, "a", "RESERVED")
            } catch (t: Throwable) {
                ModuleMain.module?.log("KAKAO: reserved call error", t)
            }
        }
    }
}

@XposedHooker
class ClickLogHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            ModuleMain.module?.log("KAKAO: click detected om6.c")
        }
    }
}

@XposedHooker
class KakaoOkHttpStackHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            try {
                val request = callback.args?.firstOrNull() ?: return
                val url = request.javaClass.getMethod("url").invoke(request).toString()
                if (url.contains("accept") || url.contains("call")) {
                    val stack = Thread.currentThread().stackTrace
                        .drop(2).take(20)
                        .joinToString("\n") { "  $it" }
                    ModuleMain.module?.log("KAKAO: OkHttp req url=$url\n$stack")
                }
            } catch (t: Throwable) {}
        }
    }
}

// ########################################################################
// 카카오 수락 훅 (oy0.i)
// ########################################################################

@XposedHooker
class KakaoOy0AcceptHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            try {
                val args = callback.args ?: return
                val callId = args.getOrNull(0) as? String ?: ""
                val from = args.getOrNull(1)
                val z1 = args.getOrNull(2) as? Boolean
                val z2 = args.getOrNull(3) as? Boolean
                ModuleMain.module?.log("KAKAO: oy0.i accept called callId=$callId from=$from z1=$z1 z2=$z2")
                // 수락 차단하려면 여기서 throwAndSkip 또는 파라미터 변경
                // callback.throwAndSkip(ClassNotFoundException("accept blocked"))
            } catch (t: Throwable) {
                ModuleMain.module?.log("KAKAO: oy0.i hook error", t)
            }
        }
    }
}

internal fun ModuleMain.installKakaoOy0AcceptHook(classLoader: ClassLoader) {
    try {
        val oy0Class = Class.forName("oy0", false, classLoader)
        val bq0Class = Class.forName("bq0", false, classLoader)
        val method = oy0Class.getDeclaredMethod(
            "i",
            String::class.java,
            bq0Class,
            Boolean::class.javaPrimitiveType,
            Boolean::class.javaPrimitiveType
        )
        method.isAccessible = true
        ModuleMain.module?.hook(method, KakaoOy0AcceptHooker::class.java)
        ModuleMain.module?.log("KAKAO: oy0.i accept hook installed")
    } catch (t: Throwable) {
        ModuleMain.module?.log("KAKAO: oy0.i accept hook FAILED", t)
    }
}