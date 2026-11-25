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

    private val installedHooks = java.util.HashSet<java.lang.reflect.Executable>()

    fun configure(nativeBridge: KakaoNativeAcceptBridge) { bridge = nativeBridge }
    fun isConfigured(): Boolean = bridge != null

    fun installHook(member: java.lang.reflect.Executable,
                    hooker: Class<out XposedInterface.Hooker>): Boolean {
        val module = ModuleMain.module ?: return false
        synchronized(installedHooks) {
            if (installedHooks.contains(member)) return false
            member.isAccessible = true
            when (member) {
                is java.lang.reflect.Method -> module.hook(member, hooker)
                is java.lang.reflect.Constructor<*> -> module.hook(member, hooker)
                else -> throw IllegalArgumentException("Unsupported hook executable")
            }
            installedHooks.add(member)
            return true
        }
    }

    fun captureViewModel(candidate: Any?, source: String) {
        if (candidate == null || bridge?.hostClass?.isInstance(candidate) != true) return
        val changed = host.get() !== candidate
        host = java.lang.ref.WeakReference(candidate)
        ensureConditionObserver()
        if (changed) kakao315Log("KAKAO315: accept event host captured source=$source")
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
            kakao315Log("KAKAO: accept condition observer unavailable", error)
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
            kakao315Log("KAKAO: native accept invocation problem id=${attempt.callId}", cause)
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
                    kakao315Log("KAKAO: ACCEPT_CONFIRMED id=${attempt.callId} from=${attempt.source.rawValue}")
                    ConditionClient.stopDetecting("confirmed:KAKAO:${attempt.callId}")
                    ModuleMain.bringAppToFront(ModuleMain.KAKAO_PACKAGE)
                }
                KakaoAcceptFinish.STALE_SUCCESS -> kakao315Log("KAKAO: accept completed for prior detection session id=${attempt.callId}")
                KakaoAcceptFinish.FAILURE -> kakao315Log("KAKAO: ACCEPT_FAILED id=${attempt.callId} error=${event.errorType}; detection remains active; terminalRejection=${event.terminalRejection}")
                KakaoAcceptFinish.UNKNOWN -> kakao315Log("KAKAO: ACCEPT_UNCONFIRMED id=${attempt.callId} error=${event.errorType}; reservation retained, no duplicate request")
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

internal class KakaoNativeAcceptBridge private constructor(
    val hostClass: Class<*>,
    private val stateClass: Class<*>,
    private val stateHolder: java.lang.reflect.Field,
    private val stateResult: Method,
    private val eventConstructor: java.lang.reflect.Constructor<*>,
    private val sources: Map<DirectAcceptSource, Any>,
    private val taskClass: Class<*>,
    private val taskKind: java.lang.reflect.Field,
    private val taskHost: java.lang.reflect.Field,
    private val taskId: java.lang.reflect.Field,
    private val taskSource: java.lang.reflect.Field,
    private val callbackClass: Class<*>,
    private val callbackMethod: Method,
    private val loadingClass: Class<*>,
    private val successClass: Class<*>,
    private val failureClass: Class<*>,
    private val successValue: java.lang.reflect.Field,
    private val failureError: java.lang.reflect.Field,
    private val ongoingClass: Class<*>,
    private val ongoingCall: java.lang.reflect.Field,
    private val callClass: Class<*>,
    private val acceptedId: java.lang.reflect.Field,
    val startMethod: Method,
    val dispatchMethod: Method,
    private val serverErrorClass: Class<*>,
    private val serverErrorParser: Method,
    private val serverErrorCode: java.lang.reflect.Field,
    private val onObserverError: (Throwable) -> Unit
) {
    fun start(host: Any, callId: String, source: DirectAcceptSource, miniDetail: Boolean, vip: Boolean) {
        require(hostClass.isInstance(host) && callId.isNotBlank()) { "Invalid accept event owner or identity" }
        // f01's constructor order is premium, then mini-card. Keep the public
        // EUNORA API's miniDetail/vip order at this single conversion boundary.
        val event = eventConstructor.newInstance(callId, sourceValue(source), vip, miniDetail)
        startMethod.invoke(host, event)
    }

    fun isBusy(host: Any): Boolean {
        require(hostClass.isInstance(host)) { "Unexpected accept state owner" }
        val holder = stateHolder.get(host) ?: error("Acceptance state holder unavailable")
        val getter = holder.javaClass.getMethod("getValue").apply { isAccessible = true }
        val state = getter.invoke(holder) ?: error("Acceptance state unavailable")
        require(stateClass.isInstance(state)) { "Unexpected acceptance state value" }
        return loadingClass.isInstance(stateResult.invoke(state))
    }

    fun matches(task: Any?, host: Any, attempt: KakaoAcceptAttempt): Boolean =
        taskClass.isInstance(task) && (taskKind.get(task) as? Number)?.toInt() == 3 &&
                taskHost.get(task) === host && taskId.get(task) == attempt.callId &&
                taskSource.get(task) === sourceValue(attempt.source)

    fun wrap(args: Array<out Any?>, host: Any, attempt: KakaoAcceptAttempt,
             observe: (KakaoNativeAcceptEvent) -> Unit): Any {
        require(args.size == 4) { "Unexpected acceptance dispatch arity" }
        require(matches(args[0], host, attempt)) { "Acceptance task does not belong to this request" }
        val original = args[3] ?: error("Missing original acceptance callback")
        require(callbackClass.isInstance(original)) { "Unexpected acceptance callback type" }
        return Proxy.newProxyInstance(callbackClass.classLoader, arrayOf(callbackClass)) { proxy, method, values ->
            when {
                method.name == "toString" && method.parameterCount == 0 -> "EunoraAccept315Observer"
                method.name == "hashCode" && method.parameterCount == 0 -> System.identityHashCode(proxy)
                method.name == "equals" && method.parameterCount == 1 -> proxy === values?.getOrNull(0)
                method.name == "i" && method.parameterTypes.contentEquals(arrayOf(Any::class.java)) -> {
                    val value = values?.getOrNull(0)
                    try {
                        // Preserve the real qs callback's return value and its
                        // exception. Observation must never invoke it twice.
                        callbackMethod.invoke(original, value)
                    } catch (error: java.lang.reflect.InvocationTargetException) {
                        throw (error.cause ?: error)
                    } finally {
                        try { observe(decode(value)) }
                        catch (error: Throwable) { runCatching { onObserverError(error) } }
                    }
                }
                else -> {
                    try { method.invoke(original, *(values ?: emptyArray())) }
                    catch (error: java.lang.reflect.InvocationTargetException) { throw (error.cause ?: error) }
                }
            }
        }
    }

    fun decode(value: Any?): KakaoNativeAcceptEvent {
        if (loadingClass.isInstance(value)) return KakaoNativeAcceptEvent(KakaoAcceptResult.LOADING)
        if (failureClass.isInstance(value)) {
            val failure = failureError.get(value) as? Throwable
            // Only the confirmed ClientException -> AcceptCallError path and
            // the same 12 business rejections handled by this APK prove failure.
            // Network errors and unrecognised/undecodable responses remain held.
            val code = if (serverErrorClass.isInstance(failure)) runCatching {
                val parsed = serverErrorParser.invoke(null, failure)
                if (parsed == null) null else serverErrorCode.getInt(parsed)
            }.getOrNull() else null
            val rejected = code in setOf(7015, 7009, 7016, 7041, 7042, 3004,
                7011, 7037, 7005, 7017, 3101, 3020)
            return KakaoNativeAcceptEvent(if (rejected) KakaoAcceptResult.FAILURE else KakaoAcceptResult.UNKNOWN,
                errorType = if (rejected) "ServerRejected:$code" else failure?.javaClass?.simpleName ?: "AcceptFailureWithoutException",
                terminalRejection = rejected)
        }
        if (successClass.isInstance(value)) {
            val ongoing = successValue.get(value)
            if (!ongoingClass.isInstance(ongoing)) {
                return KakaoNativeAcceptEvent(KakaoAcceptResult.UNKNOWN, errorType = "UnexpectedAcceptedPayload")
            }
            val call = ongoingCall.get(ongoing)
            val id = if (callClass.isInstance(call)) (acceptedId.get(call) as? String)?.takeIf { it.isNotBlank() } else null
            return if (id != null) KakaoNativeAcceptEvent(KakaoAcceptResult.SUCCESS, id)
            else KakaoNativeAcceptEvent(KakaoAcceptResult.UNKNOWN, errorType = "AcceptedIdentityUnavailable")
        }
        return KakaoNativeAcceptEvent(KakaoAcceptResult.UNKNOWN, errorType = "UnknownAcceptState")
    }

    private fun sourceValue(source: DirectAcceptSource): Any = sources[source]
        ?: error("Acceptance source unavailable: ${source.name}")

    companion object {
        fun load(loader: ClassLoader, onObserverError: (Throwable) -> Unit = {}): KakaoNativeAcceptBridge {
            fun type(name: String) = Class.forName(name, false, loader)
            fun field(owner: Class<*>, name: String, expected: Class<*>) = owner.getDeclaredField(name).apply {
                require(this.type == expected && !Modifier.isStatic(modifiers)) { "Unexpected accept field: $name" }
                isAccessible = true
            }
            fun concrete(method: Method, result: Class<*>, static: Boolean = false): Method = method.apply {
                require(returnType == result && Modifier.isStatic(modifiers) == static &&
                        !Modifier.isAbstract(modifiers) && !Modifier.isNative(modifiers)) { "Unexpected accept method contract" }
                isAccessible = true
            }
            val host = type("r41")
            val state = type("d41")
            val result = type("d40")
            val source = type("tu0")
            val event = type("f01")
            val eventContract = type("y01")
            val callback = type("eh4")
            require(source.isEnum && callback.isInterface && eventContract.isInterface &&
                    eventContract.isAssignableFrom(event)) { "Unsupported Kakao 3.15 accept contracts" }
            val sourceSerializer = concrete(source.getDeclaredMethod("a"), String::class.java)
            val values = source.enumConstants ?: error("Acceptance source enum unavailable")
            val sources = DirectAcceptSource.values().associateWith { expected ->
                val value = values.singleOrNull { (it as? Enum<*>)?.name == expected.name }
                    ?: error("Missing acceptance source: ${expected.name}")
                require(sourceSerializer.invoke(value) == expected.rawValue) { "Acceptance source value changed" }
                value
            }
            val eventConstructor = event.getDeclaredConstructor(String::class.java, source,
                java.lang.Boolean.TYPE, java.lang.Boolean.TYPE).apply { isAccessible = true }
            field(event, "a", String::class.java)
            field(event, "b", source)
            field(event, "c", java.lang.Boolean.TYPE)
            field(event, "d", java.lang.Boolean.TYPE)
            val start = concrete(host.getDeclaredMethod("e", eventContract), Void.TYPE)
            val stateHolder = field(host, "s", type("mu9"))
            val stateResult = concrete(state.getDeclaredMethod("b"), result)
            val task = type("fl")
            val kind = field(task, "e", java.lang.Byte.TYPE)
            val taskHost = field(task, "g", Any::class.java)
            val taskId = field(task, "h", Any::class.java)
            val taskSource = field(task, "i", Any::class.java)
            val callbackMethod = callback.getDeclaredMethod("i", Any::class.java).apply {
                require(returnType == Any::class.java && !Modifier.isStatic(modifiers) &&
                        Modifier.isAbstract(modifiers)) { "Unexpected acceptance callback signature" }
                isAccessible = true
            }
            val dispatcher = concrete(type("qm1").getDeclaredMethod("D", callback, type("gm2"), type("ch4"), callback),
                type("rt9"), static = true)
            val loading = type("j66")
            val success = type("d0a")
            val failure = type("qv3")
            require(listOf(loading, success, failure).all { result.isAssignableFrom(it) }) { "Acceptance result hierarchy changed" }
            val successValue = field(success, "c", Any::class.java)
            val failureError = field(failure, "c", Exception::class.java)
            val ongoing = type("kd7")
            val call = type("rt0")
            val ongoingCall = field(ongoing, "a", call)
            val acceptedId = field(call, "a", String::class.java)
            val clientError = type("jw1")
            require(Exception::class.java.isAssignableFrom(clientError)) { "Unexpected client error type" }
            field(clientError, "a", java.lang.Integer.TYPE)
            field(clientError, "b", String::class.java)
            field(clientError, "c", String::class.java)
            val errorBody = type("xgb")
            val errorParser = concrete(type("hp3").getDeclaredMethod("H", Throwable::class.java), errorBody, static = true)
            val errorCode = field(errorBody, "a", java.lang.Integer.TYPE)
            return KakaoNativeAcceptBridge(host, state, stateHolder, stateResult, eventConstructor, sources,
                task, kind, taskHost, taskId, taskSource, callback, callbackMethod, loading, success, failure,
                successValue, failureError, ongoing, ongoingCall, call, acceptedId, start, dispatcher,
                clientError, errorParser, errorCode, onObserverError)
        }
    }
}

// END KAKAO_ACCEPT_CORE

data class PlaceInfo(val dongName: String? = null, val additoryAddress: String? = null, val poi: String? = null, val completeAddress: String? = null, val name: String? = null) {
    fun searchText(): String = listOfNotNull(dongName, additoryAddress, poi, completeAddress, name).map { it.trim() }.filter { it.isNotEmpty() }.distinct().joinToString(" ")
}


internal fun ModuleMain.installKakaoAcceptTrace(classLoader: ClassLoader) {
    // Result observation is attached only to EUNORA's matching fl variant-3
    // dispatch. It does not add global HTTP or unrelated callback hooks.
    kakao315Log("KAKAO315: accept result observer configured=${DirectAcceptController.isConfigured()} path=qm1.D/qs.i")
}

internal fun ModuleMain.installViewModelHooks(classLoader: ClassLoader) {
    if (ModuleMain.module == null) return
    try {
        val nativeBridge = KakaoNativeAcceptBridge.load(classLoader) { error ->
            kakao315Log("KAKAO315: accept observation failed type=${error.javaClass.name}", error)
        }
        DirectAcceptController.installHook(nativeBridge.dispatchMethod, KakaoNativeDispatchHooker::class.java)
        DirectAcceptController.configure(nativeBridge)
        for (constructor in nativeBridge.hostClass.declaredConstructors) {
            DirectAcceptController.installHook(constructor, ViewModelConstructorHooker::class.java)
        }
        kakao315Log("KAKAO315: r41/f01 accept pipeline and managed async observer installed")
    } catch (error: Throwable) {
        kakao315Log("KAKAO315: direct accept installation FAILED type=${error.javaClass.name}", error)
    }
}

// Exact contracts verified from com.kakao.wheel.driver 3.15.0 / 3150099.
// Package/version/hash gating is performed before these installers are called.
internal object Kakao315DetectionData {
    data class Profile(
        val loader: ClassLoader,
        val wrapper: Class<*>, val group: Class<*>, val item: Class<*>,
        val route: Class<*>, val card: Class<*>, val manager: Class<*>,
        val origin: Class<*>, val destination: Class<*>, val display: Class<*>,
        val listMethod: Method, val resumedListMethod: Method,
        val receiveCardMethod: Method, val publishCardMethod: Method,
        val stateValue: Method,
        val fields: Map<String, java.lang.reflect.Field>
    )
    data class CardCapture(
        val manager: Any?, val card: Any?, val wayback: Boolean, val permitted: Boolean
    )

    @Volatile private var active: Profile? = null

    @Synchronized fun bind(loader: ClassLoader): Profile {
        active?.takeIf { it.loader === loader }?.let { return it }
        fun type(name: String) = Class.forName(name, false, loader)
        val wrapper = type("y41")
        val group = type("yz0")
        val item = type("z01")
        val route = type("x09")
        val card = type("wt0")
        val manager = type("g81")
        val origin = type("wu0")
        val destination = type("pu0")
        val display = type("b86")
        val state = type("mu9")
        val fields = linkedMapOf<String, java.lang.reflect.Field>()
        fun field(key: String, owner: Class<*>, name: String, expected: Class<*>) {
            fields[key] = owner.getDeclaredField(name).apply {
                require(!Modifier.isStatic(modifiers) && this.type == expected) {
                    "Kakao 3.15 field contract mismatch: $key"
                }
                isAccessible = true
            }
        }
        field("wrapper.a", wrapper, "a", group)
        field("wrapper.b", wrapper, "b", group)
        field("group.a", group, "a", java.util.List::class.java)
        field("item.a", item, "a", String::class.java)
        field("item.c", item, "c", java.lang.Integer.TYPE)
        field("item.f", item, "f", route)
        field("item.g", item, "g", route)
        field("item.q", item, "q", java.lang.Double.TYPE)
        for (name in listOf("a", "b", "c", "d", "e")) {
            field("route.$name", route, name, String::class.java)
        }
        field("card.o", card, "o", String::class.java)
        field("card.r", card, "r", java.lang.Integer.TYPE)
        field("card.y", card, "y", java.lang.Integer.TYPE)
        field("card.e", card, "e", origin)
        field("card.f", card, "f", destination)
        field("card.E", card, "E", route)
        field("card.m", card, "m", type("acb"))
        field("card.j", card, "j", type("mt0"))
        field("origin.c", origin, "c", String::class.java)
        field("origin.e", origin, "e", display)
        field("destination.d", destination, "d", display)
        field("display.a", display, "a", String::class.java)
        field("display.b", display, "b", String::class.java)
        field("manager.j", manager, "j", state)
        field("manager.m", manager, "m", state)
        field("manager.h", manager, "h", java.util.concurrent.PriorityBlockingQueue::class.java)
        fun method(owner: Class<*>, name: String, result: Class<*>, vararg args: Class<*>): Method =
            owner.getDeclaredMethod(name, *args).apply {
                require(returnType == result && !Modifier.isStatic(modifiers) &&
                        !Modifier.isNative(modifiers) && !Modifier.isAbstract(modifiers)) {
                    "Kakao 3.15 method contract mismatch: ${owner.name}.$name"
                }
                isAccessible = true
            }
        val profile = Profile(
            loader, wrapper, group, item, route, card, manager, origin, destination, display,
            method(type("r71"), "p", Any::class.java, String::class.java, type("ik2")),
            method(type("i71"), "z", Any::class.java, Any::class.java),
            method(manager, "d", java.lang.Void.TYPE, card),
            method(manager, "f", java.lang.Void.TYPE),
            method(state, "getValue", Any::class.java), fields
        )
        active = profile
        return profile
    }

    fun cardClass(loader: ClassLoader): Class<*> = bind(loader).card
    fun isWrapper(value: Any?): Boolean = value != null && active?.wrapper == value.javaClass
    fun isCard(value: Any?): Boolean = value != null && active?.card == value.javaClass

    private fun value(profile: Profile, key: String, owner: Any?): Any? =
        if (owner == null) null else profile.fields.getValue(key).get(owner)

    fun group(wrapper: Any, name: String): Any? {
        val profile = active ?: return null
        if (wrapper.javaClass != profile.wrapper || name !in listOf("a", "b")) return null
        return value(profile, "wrapper.$name", wrapper)?.takeIf { it.javaClass == profile.group }
    }

    fun items(group: Any): List<Any> {
        val profile = active ?: return emptyList()
        if (group.javaClass != profile.group) return emptyList()
        return (value(profile, "group.a", group) as? Collection<*>)
            ?.filterNotNull()?.filter { it.javaClass == profile.item } ?: emptyList()
    }

    private fun text(value: Any?): String = (value as? String)?.trim().orEmpty()
    private fun join(values: List<Any?>): String = values.map(::text)
        .filter { it.isNotEmpty() }.distinct().joinToString(" ")

    private fun routeText(profile: Profile, route: Any?): String {
        if (route == null || route.javaClass != profile.route) return ""
        return join(listOf("a", "b", "c", "d", "e").map { value(profile, "route.$it", route) })
    }

    private fun displayText(profile: Profile, display: Any?): String {
        if (display == null || display.javaClass != profile.display) return ""
        return join(listOf(value(profile, "display.a", display), value(profile, "display.b", display)))
    }

    fun listCall(item: Any): CallData? {
        val profile = active ?: return null
        if (item.javaClass != profile.item) return null
        val id = text(value(profile, "item.a", item)).takeIf { it.isNotEmpty() } ?: return null
        val fare = (value(profile, "item.c", item) as? Number)?.toInt()?.takeIf { it >= 0 } ?: return null
        val meters = (value(profile, "item.q", item) as? Number)?.toDouble()
            ?.takeIf { it.isFinite() && it >= 0.0 } ?: return null
        val origin = routeText(profile, value(profile, "item.f", item))
        val destination = routeText(profile, value(profile, "item.g", item))
        if (origin.isEmpty() || destination.isEmpty()) return null
        return CallData("KAKAO:$id", origin, destination, fare, meters / 1000.0)
    }

    fun cardData(card: Any): KakaoCardData? {
        val profile = active ?: return null
        if (card.javaClass != profile.card) return null
        val id = text(value(profile, "card.o", card)).takeIf { it.isNotEmpty() } ?: return null
        val fare = (value(profile, "card.r", card) as? Number)?.toInt()?.takeIf { it >= 0 } ?: return null
        val meters = (value(profile, "card.y", card) as? Number)?.toDouble()
            ?.takeIf { it.isFinite() && it >= 0.0 } ?: return null
        val originObject = value(profile, "card.e", card)?.takeIf { it.javaClass == profile.origin }
        val origin = text(value(profile, "origin.c", originObject)).ifBlank {
            displayText(profile, value(profile, "origin.e", originObject))
        }
        val destinationObject = value(profile, "card.f", card)?.takeIf { it.javaClass == profile.destination }
        val destination = routeText(profile, value(profile, "card.E", card)).ifBlank {
            // pu0.e is a duration string; only pu0.d is the address display.
            displayText(profile, value(profile, "destination.d", destinationObject))
        }
        if (origin.isEmpty() || destination.isEmpty()) return null
        return KakaoCardData(
            CallData(id, origin, destination, fare, meters / 1000.0),
            if (value(profile, "card.m", card) != null) DirectAcceptSource.WAY_BACK else DirectAcceptSource.CARD
        )
    }

    private fun current(profile: Profile, manager: Any): Any? =
        profile.stateValue.invoke(value(profile, "manager.j", manager))

    fun capture(manager: Any?, card: Any?): CardCapture {
        val profile = active ?: return CardCapture(manager, card, false, false)
        if (manager == null || manager.javaClass != profile.manager || card == null || card.javaClass != profile.card) {
            return CardCapture(manager, card, false, false)
        }
        val wayback = value(profile, "card.m", card) != null
        if (!wayback) return CardCapture(manager, card, false, true)
        val current = current(profile, manager)
        if (current != null && current.javaClass != profile.card) return CardCapture(manager, card, true, false)
        val auto = profile.stateValue.invoke(value(profile, "manager.m", manager))
        // Same guard as g81.d: an active wayback or auto-accept rejects this incoming card.
        val permitted = (current == null || value(profile, "card.m", current) == null) && auto == null
        return CardCapture(manager, card, true, permitted)
    }

    fun wasPublished(capture: CardCapture): Boolean {
        val profile = active ?: return false
        val manager = capture.manager ?: return false
        val card = capture.card ?: return false
        if (!capture.permitted || manager.javaClass != profile.manager || card.javaClass != profile.card) return false
        if (capture.wayback && profile.stateValue.invoke(value(profile, "manager.m", manager)) != null) return false
        if (current(profile, manager) === card) return true
        if (capture.wayback) return false
        // Normal/premium cards may be accepted into the manager's actual pending queue.
        return (value(profile, "manager.h", manager) as? Collection<*>)?.any { it === card } == true
    }

    fun publishedCard(manager: Any?): Any? {
        val profile = active ?: return null
        if (manager == null || manager.javaClass != profile.manager) return null
        return current(profile, manager)?.takeIf { it.javaClass == profile.card }
    }
}

private object Kakao315DetectionHooks {
    private val installed = java.util.HashSet<Method>()
    private val captures = object : ThreadLocal<java.util.ArrayDeque<Kakao315DetectionData.CardCapture>>() {
        override fun initialValue() = java.util.ArrayDeque<Kakao315DetectionData.CardCapture>()
    }

    @Synchronized private fun register(module: ModuleMain, method: Method, hooker: Class<out XposedInterface.Hooker>) {
        if (installed.contains(method)) return
        module.hook(method, hooker)
        installed.add(method)
    }

    fun installLists(module: ModuleMain, loader: ClassLoader) {
        val profile = Kakao315DetectionData.bind(loader)
        register(module, profile.listMethod, NetworkResponseHooker::class.java)
        // p can initially return COROUTINE_SUSPENDED. i71.z re-enters p, then returns
        // the terminal y41. Observe both exact exits; never treat suspension as a list.
        register(module, profile.resumedListMethod, NetworkResponseHooker::class.java)
        kakao315Log("KAKAO: list observers installed r71.p + i71.z; immediate/resumed y41 only")
    }

    fun installCards(module: ModuleMain, loader: ClassLoader) {
        val profile = Kakao315DetectionData.bind(loader)
        register(module, profile.receiveCardMethod, KakaoNewCallRequestHooker::class.java)
        register(module, profile.publishCardMethod, KakaoWaybackCardHooker::class.java)
        kakao315Log("KAKAO: guarded card observers installed g81.d(wt0) + queue publication g81.f")
    }

    fun beforeCard(manager: Any?, card: Any?) {
        val capture = try { Kakao315DetectionData.capture(manager, card) }
        catch (_: Throwable) { Kakao315DetectionData.CardCapture(manager, card, false, false) }
        captures.get().addLast(capture)
    }

    fun afterCard(manager: Any?, card: Any?, failed: Boolean) {
        val stack = captures.get()
        if (stack.isEmpty()) { captures.remove(); return }
        val capture = stack.removeLast()
        if (stack.isEmpty()) captures.remove()
        if (failed || capture.manager !== manager || capture.card !== card) return
        if (!Kakao315DetectionData.wasPublished(capture)) {
            kakao315Log("KAKAO: card eligibility/publication not confirmed; no submission")
            return
        }
        ModuleMain.processGeneralSocketCallCard(card ?: return, "MINI_CARD")
    }
}

internal fun ModuleMain.installNetworkResponseHook(classLoader: ClassLoader) {
    try {
        val module = ModuleMain.module ?: return
        Kakao315DetectionHooks.installLists(module, classLoader)
    } catch (error: Throwable) {
        kakao315Log("KAKAO: 3.15 list observer installation failed", error)
    }
}

internal fun ModuleMain.installPopupResponseHook(classLoader: ClassLoader) {
    kakao315Log("KAKAO: popup cards observed through verified g81/wt0 data path")
}

internal fun ModuleMain.installKakaoCallRequestHooks(classLoader: ClassLoader) {
    try {
        val module = ModuleMain.module ?: return
        Kakao315DetectionHooks.installCards(module, classLoader)
    } catch (error: Throwable) {
        kakao315Log("KAKAO: 3.15 guarded card observer installation failed", error)
    }
}

internal fun ModuleMain.installKakaoWaybackHooks(classLoader: ClassLoader) {
    // g81.d explicitly branches on wt0.m != null. The same verified early data
    // observer preserves that branch's rejection guard; there is no dr0 scan.
    installKakaoCallRequestHooks(classLoader)
}

internal fun ModuleMain.installKakaoCardPathHooks(classLoader: ClassLoader) {
    kakao315Log("KAKAO: card profile=wt0; shared normal/premium/wayback manager=g81")
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
 * - 3.15 ll3.i0(Location) reads these same framework latitude/longitude getters.
 * - mock 은 공통 GpsMockFalseHooker
 */
internal fun ModuleMain.installKakaoGpsSpoof(classLoader: ClassLoader) {
    try {
        val locationClass = Class.forName("android.location.Location", false, classLoader)
        ModuleMain.module?.hook(locationClass.getMethod("getLatitude"), KakaoGpsLatitudeHooker::class.java)
        ModuleMain.module?.hook(locationClass.getMethod("getLongitude"), KakaoGpsLongitudeHooker::class.java)
        ModuleMain.module?.log("KAKAO: GPS getters use enabled EUNORA coordinates")

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
    // Reservation is y41.b in the same verified r71.p list result. The old
    // e21.y continuation belonged to calls/{id}/resume (Unit), not a call list.
    kakao315Log("KAKAO: reservation group uses r71.p/y41.b; premium cards use guarded g81/wt0")
}

internal fun processCallItem(item: Any, source: String): Boolean {
    return try {
        val call = Kakao315DetectionData.listCall(item) ?: return false
        kakao315Log("KAKAO: list item source=$source id=${call.callId} fare=${call.fare} distanceKm=${call.distanceKm}")
        ModuleMain.matchAndAccept(call)
    } catch (error: Throwable) {
        kakao315Log("KAKAO: list item processing failed source=$source", error)
        false
    }
}

internal fun processJv0(group: Any, source: String): Boolean {
    for (item in Kakao315DetectionData.items(group)) {
        if (processCallItem(item, source)) return true
    }
    return false
}

@XposedHooker
class NetworkResponseHooker : XposedInterface.Hooker {
    companion object {
        internal fun observe(result: Any?, source: String) {
            // Suspension sentinels, failure payloads and unrelated objects never
            // become an order. No identity dedup: cached objects must be checked
            // again when a later request completes under changed conditions.
            if (!Kakao315DetectionData.isWrapper(result)) return
            val wrapper = result ?: return
            val onDemand = Kakao315DetectionData.group(wrapper, "a")
            val reservation = Kakao315DetectionData.group(wrapper, "b")
            if (onDemand != null && processJv0(onDemand, "$source:ON_DEMAND")) return
            if (reservation != null) processJv0(reservation, "$source:RESERVATION")
        }

        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable != null) return
            try {
                observe(callback.result, callback.member.name)
            } catch (error: Throwable) {
                kakao315Log("KAKAO: list completion observation failed", error)
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
class ViewModelConstructorHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable != null) return
            try { DirectAcceptController.captureViewModel(callback.thisObject, "r41.constructor") }
            catch (error: Throwable) { kakao315Log("KAKAO315: accept host capture failed type=${error.javaClass.name}", error) }
        }
    }
}

@XposedHooker
class KakaoNewCallRequestHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            try {
                Kakao315DetectionHooks.beforeCard(callback.thisObject, callback.args.firstOrNull())
            } catch (error: Throwable) {
                kakao315Log("KAKAO: card eligibility capture failed", error)
            }
        }

        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            try {
                Kakao315DetectionHooks.afterCard(callback.thisObject, callback.args.firstOrNull(), callback.throwable != null)
            } catch (error: Throwable) {
                kakao315Log("KAKAO: published card observation failed", error)
            }
        }
    }
}

@XposedHooker
class KakaoWaybackCardHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @AfterInvocation
        fun after(callback: XposedInterface.AfterHookCallback) {
            if (callback.throwable != null) return
            try {
                // Exact g81.f() publishes a card removed from the original queue.
                val card = Kakao315DetectionData.publishedCard(callback.thisObject) ?: return
                ModuleMain.processGeneralSocketCallCard(card, "MINI_CARD")
            } catch (error: Throwable) {
                kakao315Log("KAKAO: queued card publication observation failed", error)
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

    // Only existing, recognizable marker entries are eligible for normalization.
    // Other libraries, native-method findings and unknown values remain visible.
    internal fun isKnownHookEntry(value: Any?): Boolean = value is String &&
            markers.any { (_, names) -> names.any { value.contains(it, ignoreCase = true) } }

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
        val statusMethod = reportClass.getDeclaredMethod("a").apply {
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
                if (!KakaoLocalSecurityHooks.currentBuildMatches(callback.args.getOrNull(0) as? Context)) {
                    log("KAKAO: Sentry root diagnostic test config NOT_APPLIED reason=UNVERIFIED_BUILD")
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

/** Exact Java contracts from the supplied 3.15.0/3150099 APK. Original checks still execute. */
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
        val durationField: java.lang.reflect.Field,
        val derivedSignalsField: java.lang.reflect.Field,
        val signalClass: Class<*>
    )

    data class ReportChange(
        val result: Any, val before: KakaoHookSignalDiagnostics.Snapshot,
        val after: KakaoHookSignalDiagnostics.Snapshot
    )

    data class SdkLayout(
        val kind: String, val paths: java.lang.reflect.Field? = null,
        val packages: java.lang.reflect.Field? = null,
        val runtime: java.lang.reflect.Field? = null,
        val context: java.lang.reflect.Field? = null
    )

    private val installed = java.util.concurrent.ConcurrentHashMap.newKeySet<java.lang.reflect.Member>()
    private val roots = java.util.concurrent.ConcurrentHashMap<java.lang.reflect.Member, RootLayout>()
    private val reports = java.util.concurrent.ConcurrentHashMap<java.lang.reflect.Member, ReportLayout>()
    private val sdkMethods = java.util.concurrent.ConcurrentHashMap<java.lang.reflect.Member, SdkLayout>()

    private const val VERIFIED_VERSION = 3150099L
    private val signalNames = listOf(
        "STACK_HOOK_MARKER", "NATIVE_HOOKED_METHOD", "HOOK_ARTIFACT_MAPPING",
        "FOREIGN_CODE_MAPPING", "XPOSED_CLASS_LOADED", "FRAMEWORK_API_MISMATCH"
    )
    private val signalCodes = listOf(
        "stack_hook_marker", "native_hooked_method", "hook_artifact_mapping",
        "foreign_code_mapping", "xposed_class_loaded", "framework_api_mismatch"
    )

    internal fun currentBuildMatches(context: Context? = ModuleMain.getApplicationContext()): Boolean =
        context != null && runCatching {
            context.packageName == "com.kakao.wheel.driver" &&
                    context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode == VERIFIED_VERSION
        }.getOrDefault(false)

    internal fun log(message: String) { runCatching { kakao315Log(message) } }
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
        val derived = assessment.getDeclaredField("g").apply { isAccessible = true }
        require(java.util.Set::class.java.isAssignableFrom(derived.type) && !Modifier.isStatic(derived.modifiers)) {
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
        // The six constructor inputs map to named enum categories, not guessed bit values.
        // Probe each category with inert text and verify names plus wire codes from this APK.
        var signalClass: Class<*>? = null
        for (index in signalNames.indices) {
            val inputs = Array(6) { slot -> if (slot == index) listOf("contract-probe") else emptyList<String>() }
            val sample = assessmentConstructor.newInstance(*inputs)
            val signals = derived.get(sample) as? Set<*> ?: error("missing derived signals")
            require(signals.size == 1) { "unexpected signal category mapping" }
            val signal = signals.single() as? Enum<*> ?: error("signal is not an enum")
            require(signal.name == signalNames[index]) { "signal category differs" }
            val owner = signal.javaClass
            if (signalClass == null) signalClass = owner
            require(owner == signalClass && owner.isEnum) { "mixed signal category types" }
            val code = owner.getDeclaredField("a").apply { isAccessible = true }
            require(code.type == String::class.java && !Modifier.isStatic(code.modifiers) &&
                    code.get(signal) == signalCodes[index]) { "signal wire code differs" }
            require(owner.enumConstants.map { (it as Enum<*>).name }.toSet() == signalNames.toSet()) {
                "unknown signal categories"
            }
        }
        return ReportLayout(diagnostics, assessmentConstructor, reportConstructor, probes, checkedAt, duration,
            derived, signalClass ?: error("missing signal enum"))
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
        val originalLists = layout.diagnostics.signalFields.map { field ->
            (field.get(originalAssessment) as? List<*>)?.toList() ?: error("missing signal list")
        }
        val originalSignals = layout.derivedSignalsField.get(originalAssessment) as? Set<*>
            ?: error("missing derived signals")
        val actualNames = originalSignals.map { signal ->
            require(layout.signalClass.isInstance(signal)) { "unknown signal category type" }
            (signal as? Enum<*>)?.name ?: error("unknown signal category value")
        }.toSet()
        val expectedNames = signalNames.filterIndexed { index, _ -> originalLists[index].isNotEmpty() }.toSet()
        require(actualNames == expectedNames) { "unverified or inconsistent signal categories" }
        // Preserve unknown findings, framework API mismatches and all probe metadata.
        val retained = originalLists.mapIndexed { index, entries ->
            if (index < 5) entries.filterNot { KakaoHookSignalDiagnostics.isKnownHookEntry(it) } else entries
        }
        if (retained == originalLists) return ReportChange(value, before, before)
        val originalProbes = layout.probesField.get(value) as? java.util.LinkedHashMap<*, *>
            ?: error("missing hook probe statuses")
        val probes = java.util.LinkedHashMap<Any?, Any?>().apply { putAll(originalProbes) }
        val checkedAt = layout.checkedAtField.getLong(value)
        val duration = layout.durationField.getLong(value)
        val assessment = layout.assessmentConstructor.newInstance(*retained.toTypedArray())
        val result = layout.reportConstructor.newInstance(assessment, probes, checkedAt, duration)
        val after = KakaoHookSignalDiagnostics.snapshot(result, layout.diagnostics)
        require(after.status != "STATUS_UNEXPECTED" && after.counts == retained.map { it.size } &&
                after.counts[5] == before.counts[5]) { "hook assessment normalization differs" }
        require(layout.probesField.get(result) == originalProbes &&
                layout.checkedAtField.getLong(result) == checkedAt && layout.durationField.getLong(result) == duration) {
            "hook report metadata changed"
        }
        return ReportChange(result, before, after)
    }

    internal fun sdkMatches(value: Any?, layout: SdkLayout): Boolean {
        if (layout.kind == "CRASHLYTICS_3150") return currentBuildMatches()
        val context = runCatching { layout.context?.get(value) as? Context }.getOrNull()
        if (!currentBuildMatches(context ?: ModuleMain.getApplicationContext())) return false
        if (layout.kind != "SENTRY_ROOTCHECKER" || value == null) return false
        val paths = layout.paths?.get(value) as? Array<*> ?: return false
        val packages = layout.packages?.get(value) as? Array<*> ?: return false
        return layout.runtime?.get(value) is Runtime && paths.any { it == "/system/xbin/su" } &&
                packages.any { it == "eu.chainfire.supersu" || it == "com.koushikdutta.superuser" }
    }

    fun install(module: ModuleMain, loader: ClassLoader) {
        // RootingStatus no longer exists in the supplied 3.15.0 APK. Never guess its replacement.
        log("KAKAO_SECURITY: UNSUPPORTED target=LEGACY_ROOTING_STATUS reason=MODEL_REMOVED_OR_RESTRUCTURED action=KEEP_ORIGINAL")
        installTarget("d05.a()wz4") {
            val owner = Class.forName("d05", false, loader)
            val report = Class.forName("wz4", false, loader)
            val assessment = Class.forName("uz4", false, loader)
            val layout = resolveReport(report, assessment)
            val method = owner.getDeclaredMethod("a").apply {
                require(returnType == report && !Modifier.isStatic(modifiers) &&
                        !Modifier.isAbstract(modifiers) && !Modifier.isNative(modifiers)) { "unexpected detector signature" }
                isAccessible = true
            }
            register(method) {
                reports[method] = layout
                try { module.hook(method, KakaoHookDetectionHooker::class.java) }
                catch (error: Throwable) { reports.remove(method); throw error }
            }
            log("KAKAO_SECURITY: REGISTERED target=d05.a action=NORMALIZE_KNOWN_MARKER_ENTRIES preserved=UNKNOWN_FINDINGS_FRAMEWORK_APIS_AND_PROBE_ERRORS execution=UNVERIFIED")
        }
        installTarget("io.sentry.android.core.internal.util.k.a()boolean") {
            val owner = Class.forName("io.sentry.android.core.internal.util.k", false, loader)
            val context = owner.getDeclaredField("a").apply { isAccessible = true }
            val paths = owner.getDeclaredField("d").apply { isAccessible = true }
            val packages = owner.getDeclaredField("e").apply { isAccessible = true }
            val runtime = owner.getDeclaredField("f").apply { isAccessible = true }
            require(context.type == Context::class.java && paths.type == Array<String>::class.java &&
                    packages.type == Array<String>::class.java && runtime.type == Runtime::class.java &&
                    listOf(context, paths, packages, runtime).none { Modifier.isStatic(it.modifiers) }) {
                "unexpected Sentry root checker fields"
            }
            val method = owner.getDeclaredMethod("a").apply {
                require(returnType == java.lang.Boolean.TYPE && !Modifier.isStatic(modifiers) &&
                        !Modifier.isAbstract(modifiers) && !Modifier.isNative(modifiers)) { "unexpected Sentry root signature" }
                isAccessible = true
            }
            register(method) {
                sdkMethods[method] = SdkLayout("SENTRY_ROOTCHECKER", paths, packages, runtime, context)
                try { module.hook(method, KakaoSdkRootBooleanHooker::class.java) }
                catch (error: Throwable) { sdkMethods.remove(method); throw error }
            }
            log("KAKAO_SECURITY: REGISTERED target=SENTRY_ROOTCHECKER action=BOOLEAN_FALSE execution=UNVERIFIED")
        }
        installTarget("j12.x()boolean") {
            val owner = Class.forName("j12", false, loader)
            val method = owner.getDeclaredMethod("x").apply {
                require(returnType == java.lang.Boolean.TYPE && Modifier.isStatic(modifiers) &&
                        !Modifier.isAbstract(modifiers) && !Modifier.isNative(modifiers)) { "unexpected Crashlytics root signature" }
                isAccessible = true
            }
            register(method) {
                sdkMethods[method] = SdkLayout("CRASHLYTICS_3150")
                try { module.hook(method, KakaoSdkRootBooleanHooker::class.java) }
                catch (error: Throwable) { sdkMethods.remove(method); throw error }
            }
            log("KAKAO_SECURITY: REGISTERED target=j12.x action=BOOLEAN_FALSE targetVersion=3150099 execution=UNVERIFIED")
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
                if (!KakaoLocalSecurityHooks.currentBuildMatches()) {
                    KakaoLocalSecurityHooks.log("KAKAO_SECURITY: HOOK_RESULT_UNCONFIRMED reason=UNVERIFIED_BUILD action=KEEP_ORIGINAL")
                    return
                }
                val original = callback.result
                val change = KakaoLocalSecurityHooks.normalizeReport(original, layout)
                val changed = change.result !== original
                if (changed) callback.result = change.result
                KakaoLocalSecurityHooks.log("KAKAO_SECURITY: HOOK_ASSESSMENT originalStatus=${change.before.status} resultStatus=${change.after.status} " +
                        "signalsBefore=${change.before.counts.take(5).joinToString(",")} signalsAfter=${change.after.counts.take(5).joinToString(",")} " +
                        "missingFrameworkApis=${change.after.counts[5]} unknownFindings=PRESERVED probeErrors=PRESERVED resultChanged=$changed")
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
            if (callback.throwable != null) return
            try {
                NetworkResponseHooker.observe(callback.result, "RESERVATION_COMPLETION")
            } catch (error: Throwable) {
                kakao315Log("KAKAO: reservation completion observation failed", error)
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
class Kakao315AcceptEventHooker : XposedInterface.Hooker {
    companion object {
        @JvmStatic
        @BeforeInvocation
        fun before(callback: XposedInterface.BeforeHookCallback) {
            // Capture an already-created host too. Leave every SDK/manual
            // event, argument, return value and exception unchanged.
            try { DirectAcceptController.captureViewModel(callback.thisObject, "r41.e") }
            catch (error: Throwable) { kakao315Log("KAKAO315: accept event host unavailable type=${error.javaClass.name}", error) }
        }
    }
}

// Retain the existing installer entry name used by ModuleMain.
internal fun ModuleMain.installKakaoOy0AcceptHook(classLoader: ClassLoader) {
    if (ModuleMain.module == null) return
    try {
        val host = Class.forName("r41", false, classLoader)
        val event = Class.forName("y01", false, classLoader)
        val method = host.getDeclaredMethod("e", event).apply {
            require(event.isInterface && returnType == Void.TYPE && !Modifier.isStatic(modifiers) &&
                    !Modifier.isAbstract(modifiers) && !Modifier.isNative(modifiers)) { "Unexpected accept event entry" }
            isAccessible = true
        }
        DirectAcceptController.installHook(method, Kakao315AcceptEventHooker::class.java)
        kakao315Log("KAKAO315: accept event entry installed target=r41.e(y01)")
    } catch (error: Throwable) {
        kakao315Log("KAKAO315: accept event entry FAILED type=${error.javaClass.name}", error)
    }
}

// BEGIN KAKAO315_RUNTIME_PROFILE
/** Exact supplied APK identity; avoids resolving reused obfuscated names in other builds. */
internal object Kakao315RuntimeProfile {
    const val PACKAGE_NAME = "com.kakao.wheel.driver"
    const val VERSION_CODE = 3150099L
    private const val APK_BYTES = 110215873L
    private const val APK_SHA256 = "cf38573177afbbb4ac0ed94165e225b6743c40087d70e76e440f30927df98b89"

    fun matches(info: android.content.pm.ApplicationInfo): Boolean {
        if (info.packageName != PACKAGE_NAME) {
            kakao315Log("KAKAO: profile rejected reason=PACKAGE")
            return false
        }
        val source = info.sourceDir?.takeIf { it.isNotBlank() }
        if (source == null) {
            kakao315Log("KAKAO: profile rejected reason=APK_PATH_MISSING")
            return false
        }
        return try {
            val apk = java.io.File(source)
            if (!apk.isFile || apk.length() != APK_BYTES) {
                kakao315Log("KAKAO: profile rejected reason=APK_SIZE expectedVersion=$VERSION_CODE")
                false
            } else if (sha256(apk) != APK_SHA256) {
                kakao315Log("KAKAO: profile rejected reason=APK_HASH expectedVersion=$VERSION_CODE")
                false
            } else {
                kakao315Log("KAKAO: profile verified versionCode=$VERSION_CODE")
                true
            }
        } catch (error: Throwable) {
            kakao315Log("KAKAO: profile verification failed type=${error.javaClass.name}", error)
            false
        }
    }

    private fun sha256(file: java.io.File): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(1024 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer, 0, read)
            }
        }
        val digits = "0123456789abcdef"
        return buildString(64) {
            for (byte in digest.digest()) {
                val value = byte.toInt() and 0xff
                append(digits[value ushr 4])
                append(digits[value and 15])
            }
        }
    }
}

/** Important diagnostics remain visible in logcat without changing a hook's outcome. */
internal fun kakao315Log(message: String, error: Throwable? = null) {
    try {
        if (error == null) ModuleMain.module?.log(message)
        else ModuleMain.module?.log(message, error)
    } catch (_: Throwable) { }
    try {
        if (error == null) android.util.Log.i("EUNORA_KAKAO", message)
        else android.util.Log.e("EUNORA_KAKAO", message, error)
    } catch (_: Throwable) { }
}
// END KAKAO315_RUNTIME_PROFILE
