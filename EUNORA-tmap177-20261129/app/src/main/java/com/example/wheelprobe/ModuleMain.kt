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

class ModuleMain(
    base: XposedInterface,
    param: XposedModuleInterface.ModuleLoadedParam
) : XposedModule(base, param) {

    private val moduleProcessName = runCatching { param.processName }.getOrNull().orEmpty()

    init {
        module = this
        val processName = try {
            android.app.Application.getProcessName()
        } catch (t: Throwable) {
            "unknown"
        }
        log("EUNORA: module loaded; process=$processName")

        // GPS 스푸핑 상태 초기 로드 (EUNORA prefs)
        try {
            GpsSpoofState.forceRefresh()
            val pair = GpsSpoofState.activeLatLng()
            log(
                "EUNORA: GPS spoof state loaded: active=${pair != null}" +
                        if (pair != null) ", lat=${pair.first}, lng=${pair.second}" else ""
            )
        } catch (t: Throwable) {
            log("EUNORA: GPS spoof state init FAILED", t)
        }

        // 공통 GPS Mock 탐지 우회 (libxposed hook 방식)
        try {
            val locationClass = Location::class.java
            // isFromMockProvider() → 항상 false
            val isFromMockProviderMethod = locationClass.getDeclaredMethod("isFromMockProvider")
            isFromMockProviderMethod.isAccessible = true
            hook(isFromMockProviderMethod, GpsMockFalseHooker::class.java)

            // isMock() → 항상 false (API 31+)
            try {
                val isMockMethod = locationClass.getDeclaredMethod("isMock")
                isMockMethod.isAccessible = true
                hook(isMockMethod, GpsMockFalseHooker::class.java)
            } catch (_: NoSuchMethodException) {
                // API 30 이하는 isMock() 메서드가 없을 수 있음
            }
            log("EUNORA: global mock location bypass installed (libxposed)")
        } catch (t: Throwable) {
            log("EUNORA: global mock bypass FAILED", t)
        }
    }

    override fun onPackageLoaded(
        param: XposedModuleInterface.PackageLoadedParam
    ) {
        super.onPackageLoaded(param)

        val classLoader = param.classLoader
        val pkg = param.packageName
        val process = try {
            android.app.Application.getProcessName()
        } catch (t: Throwable) {
            "unknown"
        }

        // ====================================================================
        // 카카오 대리 (원본 그대로 유지)
        // ====================================================================
        if (pkg == KAKAO_PACKAGE && param.isFirstPackage) {
            if (!Kakao315RuntimeProfile.matches(param.applicationInfo)) return
            kakao315Log("EUNORA: Kakao 3.15.0 package loaded")
            installKakaoRootingReportBypass(classLoader)
            log("EUNORA: card path hook START")
            try {
                installKakaoCardPathHooks(classLoader)
            } catch (t: Throwable) {
                log("EUNORA: card path hook CALL FAILED", t)
            }
            log("EUNORA: card path hook END")

            // 감지 ON 전이라도 GPS 브로드캐스트 수신 가능하도록 조건 수신기 등록
            try {
                ConditionClient.initialize { msg -> log(msg) }
            } catch (t: Throwable) {
                log("EUNORA: ConditionClient.initialize FAILED", t)
            }
            installViewModelHooks(classLoader)
            installNetworkResponseHook(classLoader)
            installPopupResponseHook(classLoader)
            installKakaoCallRequestHooks(classLoader)
            installKakaoWaybackHooks(classLoader)
            installKakaoReservedExclusiveHooks(classLoader)
            installKakaoGpsSpoof(classLoader)
            installKakaoAcceptTrace(classLoader)
            installKakaoOy0AcceptHook(classLoader)
        }

        // ====================================================================
        // 콜마너 (원본 그대로 유지)
        // ====================================================================
        if (CallmanerPackageRoute.supports(pkg)) {
            log("EUNORA: Callmaner process loaded package=$pkg")

            // 감지 ON 전이라도 GPS 브로드캐스트 수신 가능하도록 조건 수신기 등록
            try {
                ConditionClient.initialize { msg -> log(msg) }
            } catch (t: Throwable) {
                log("EUNORA: ConditionClient.initialize FAILED", t)
            }
            CallmanerAcceptController.init(classLoader, pkg)
            installCallmanerGpsSpoof(classLoader)
            installCallmanerSecurityBypass(classLoader)
        }

        // ====================================================================
        // T맵 대리 (콜 감지/수락 + GPS 스푸핑)
        // ====================================================================
        if (pkg == TMAP_PACKAGE) {
            log("EUNORA: Tmap package loaded isFirst=${param.isFirstPackage} process=$process")

            // 감지 ON 전이라도 GPS 브로드캐스트 수신 가능하도록 조건 수신기 등록
            try {
                ConditionClient.initialize { msg -> log(msg) }
            } catch (t: Throwable) {
                log("EUNORA: ConditionClient.initialize FAILED", t)
            }
            installTmapGpsSpoof(classLoader)
            installTmapRootChecks(classLoader)
            installTmapCallListHook(classLoader)
            try {
                TmapAcceptController.init(classLoader)
            } catch (t: Throwable) {
                log("TMAP: AcceptController.init FAILED", t)
            }
        }

        // ====================================================================
        // 아이드라이브 (GPS 스푸핑 준비 완료)
        // ====================================================================
        if (pkg == IDRIVE_PACKAGE && param.isFirstPackage) {
            log("EUNORA: iDriver package loaded")

            // 감지 ON 전이라도 GPS 브로드캐스트 수신 가능하도록 조건 수신기 등록
            try {
                ConditionClient.initialize { msg -> log(msg) }
            } catch (t: Throwable) {
                log("EUNORA: ConditionClient.initialize FAILED", t)
            }
            installIdriveOrderListHook(classLoader)
            installIdriveGpsSpoof(classLoader)
            installIdriveSecurityBypass(classLoader)
            installIdriveFlutterHook(classLoader)
        }

        // ====================================================================
        // 로지 (원본 그대로 유지)
        // ====================================================================
        if (LogiPackageRoute.supports(pkg) && param.isFirstPackage) {
            LogiPackageRoute.attach(pkg)
            installLogiNativeAdapter(param.applicationInfo, moduleProcessName)
            log("EUNORA: Logi package loaded package=$pkg")

            // 감지 ON 전이라도 GPS 브로드캐스트 수신 가능하도록 조건 수신기 등록
            try {
                ConditionClient.initialize { msg -> log(msg) }
            } catch (t: Throwable) {
                log("EUNORA: ConditionClient.initialize FAILED", t)
            }
            installLogiOrderHook(classLoader)
            LogiAcceptController.init(classLoader)
            installLogiGpsSpoof(classLoader)
            installLogiSecurityBypass(classLoader)
        }
    }

    companion object {
        const val KAKAO_PACKAGE = "com.kakao.wheel.driver"
        const val CALLMANER_PACKAGE = "com.callmanerdriver2sharp1"
        const val CALLMANER_PROCESS = "android.callmaner.process"
        const val TMAP_PACKAGE = "com.tmapmobility.drive.driver"
        const val IDRIVE_PACKAGE = "com.idriver"
        const val LOGI_PACKAGE = "com.logisoft.Logi4"

        internal var module: ModuleMain? = null
        internal val callMatcher = CallMatcher()

        internal fun getApplicationContext(): Context? {
            return try {
                val at = Class.forName("android.app.ActivityThread")
                val method = at.getDeclaredMethod("currentApplication")
                method.isAccessible = true
                method.invoke(null) as? Context
            } catch (t: Throwable) {
                null
            }
        }

        /** 수락된 앱을 맨 앞으로. 런처 재실행/RESET 은 콜마너를 홈으로 떨어뜨린다. */
        internal fun bringAppToFront(packageName: String) {
            val context = getApplicationContext() ?: return
            var moved = false
            try {
                val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? android.app.ActivityManager
                val tasks = am?.appTasks
                if (!tasks.isNullOrEmpty()) {
                    val self = context.packageName
                    if (self == packageName || packageName.isBlank()) {
                        tasks.forEach { task ->
                            try {
                                task.moveToFront()
                                moved = true
                            } catch (_: Throwable) {
                            }
                        }
                    }
                }
            } catch (t: Throwable) {
                module?.log("EUNORA: moveToFront skip: ${t.message}")
            }
            if (moved) {
                module?.log("EUNORA: brought to front → $packageName moved=true via task")
                return
            }
            try {
                val launchIntent = context.packageManager.getLaunchIntentForPackage(packageName)
                if (launchIntent != null) {
                    launchIntent.addFlags(
                        Intent.FLAG_ACTIVITY_REORDER_TO_FRONT or
                                Intent.FLAG_ACTIVITY_NEW_TASK or
                                Intent.FLAG_ACTIVITY_SINGLE_TOP
                    )
                    context.startActivity(launchIntent)
                    moved = true
                }
            } catch (t: Throwable) {
                module?.log("EUNORA: bring startActivity FAILED package=$packageName", t)
            }
            module?.log("EUNORA: brought to front → $packageName moved=$moved")
        }

        internal fun packageFromCallId(callId: String): String? {
            return when {
                callId.startsWith("CALLMANER:") -> CallmanerAcceptController.foregroundPackage()
                callId.startsWith("TMAP:") -> TMAP_PACKAGE
                callId.startsWith("IDRIVE:") -> IDRIVE_PACKAGE
                callId.startsWith("LOGI:") -> LogiPackageRoute.current()
                else -> KAKAO_PACKAGE
            }
        }

        /**
         * 포그라운드 Activity를 recreate 해서 리스트 등 UI를 강제 새로고침.
         * 콜마너처럼 수락 후에도 리스트에 콜이 남는 문제를 완화한다.
         */
        fun refreshForegroundActivityPublic() {
            refreshForegroundActivity()
        }

        internal fun refreshForegroundActivity() {
            try {
                val atClass = Class.forName("android.app.ActivityThread")
                val currentAt = atClass.getMethod("currentActivityThread").invoke(null) ?: return
                val activitiesField = atClass.getDeclaredField("mActivities").apply { isAccessible = true }
                @Suppress("UNCHECKED_CAST")
                val activities = activitiesField.get(currentAt) as? Map<Any, Any> ?: return

                // resumed / 가장 위 Activity 우선
                var target: Activity? = null
                for (record in activities.values) {
                    try {
                        val recClass = record.javaClass
                        val activityField = recClass.getDeclaredField("activity").apply { isAccessible = true }
                        val activity = activityField.get(record) as? Activity ?: continue
                        if (activity.isFinishing) continue
                        // paused 여부
                        val pausedField = runCatching {
                            recClass.getDeclaredField("paused").apply { isAccessible = true }
                        }.getOrNull()
                        val paused = pausedField?.getBoolean(record) ?: false
                        if (!paused) {
                            target = activity
                            break
                        }
                        if (target == null) target = activity
                    } catch (_: Throwable) {
                    }
                }
                val act = target ?: return
                act.runOnUiThread {
                    try {
                        if (!act.isFinishing && !act.isDestroyed) {
                            act.recreate()
                            module?.log("EUNORA: activity recreated class=${act.javaClass.name}")
                        }
                    } catch (t: Throwable) {
                        module?.log("EUNORA: activity recreate failed class=${act.javaClass.name}", t)
                    }
                }
            } catch (t: Throwable) {
                module?.log("EUNORA: refreshForegroundActivity failed", t)
            }
        }

        internal fun matchAndAccept(callData: CallData): Boolean {
            initializeConditions()
            if (!canProcessConditions("")) return false
            val sets = ConditionClient.current()
            if (sets.isEmpty()) {
                module?.log(
                    "EUNORA: match skipped id=${callData.callId} reason=NO_ACTIVE_SET " +
                            "origin=${callData.origin} dest=${callData.destination} " +
                            "fare=${callData.fare} distanceKm=${callData.distanceKm}"
                )
                return false
            }
            if (!CallKindFilter.allows(callData.origin)) {
                module?.log(
                    "EUNORA: match skipped id=${callData.callId} reason=KIND_FILTER " +
                            "taksong=${CallKindFilter.isTaksong(callData.origin)} " +
                            "allowDaeri=${CallKindFilter.allowDaeri} allowTaksong=${CallKindFilter.allowTaksong} " +
                            "origin=${callData.origin} dest=${callData.destination}"
                )
                return false
            }
            if (!TaksongDateFilter.allows(callData.callId, callData.origin)) {
                module?.log(
                    "EUNORA: match skipped id=${callData.callId} reason=DATE_FILTER " +
                            "day=${TaksongDateFilter.classify(callData.origin)} " +
                            "allowToday=${TaksongDateFilter.allowToday} allowTomorrow=${TaksongDateFilter.allowTomorrow} " +
                            "origin=${callData.origin} dest=${callData.destination}"
                )
                return false
            }
            val result = callMatcher.matchAny(callData, sets)
            // 카카오 DTO MATCH와 동일 수준으로 콜마너/공통 매칭 상세 로그
            module?.log(
                "EUNORA: match result id=${callData.callId} matched=${result.matched} " +
                        "set=${result.matchedSetNumber} reason=${result.reasonCode} detail=${result.detail} " +
                        "fare=${callData.fare} distanceKm=${callData.distanceKm}"
            )
            if (result.matched) {
                // 카카오 리스트 경로: 수락 성공 시에만 감지 중지
                if (callData.callId.startsWith("KAKAO:")) {
                    val rawId = callData.callId.removePrefix("KAKAO:")
                    return handleDirectAccept(rawId, DirectAcceptSource.LIST, "list_match")
                } else if (!callData.callId.startsWith("CALLMANER:") &&
                    !callData.callId.startsWith("IDRIVE:") &&
                    !callData.callId.startsWith("TMAP:") &&
                    !callData.callId.startsWith("LOGI:")) {
                    ConditionClient.stopDetecting("accepted:${callData.callId}")
                    val pkg = packageFromCallId(callData.callId)
                    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                        pkg?.let { bringAppToFront(it) }
                    }, 450)
                }
            }
            return result.matched
        }

        fun log(message: String, throwable: Throwable? = null) {
            if (throwable != null) android.util.Log.e("EUNORA", message, throwable)
            else android.util.Log.d("EUNORA", message)
        }

        @Volatile private var lastConditionInitMs: Long = 0L

        internal fun initializeConditions() {
            DirectAcceptController.ensureConditionObserver()
            val now = System.currentTimeMillis()
            val ready = runCatching { ConditionClient.isReady() }.getOrDefault(false)
            if (ready && now - lastConditionInitMs < 3000L) return
            lastConditionInitMs = now
            ConditionClient.initialize { msg -> log("EUNORA: $msg") }
        }

        internal fun canProcessConditions(sourceName: String): Boolean {
            if (!ConditionClient.isReady()) { log("EUNORA: $sourceName skipped - CONDITIONS_NOT_READY"); return false }
            if (!ConditionClient.isDetecting()) { log("EUNORA: $sourceName skipped - DETECTION_OFF"); return false }
            return true
        }

        internal fun processDtoGroup(dto: Any, fieldName: String, groupName: String): Boolean {
            val group = Kakao315DetectionData.group(dto, fieldName) ?: return false
            return processJv0(group, groupName)
        }

        internal fun processSingleCall(card: Any, groupName: String): Boolean {
            return processDtoCall(groupName, 0, card)
        }

        internal fun processDtoCall(groupName: String, index: Int, item: Any): Boolean {
            // z01.q is distanceToStart. z01.r is reservationWrapper, not a number.
            return processCallItem(item, "$groupName:$index")
        }

        internal fun processPopupDto(item: Any): Boolean {
            // Only the verified wt0 card contract is accepted by the shared parser.
            return processGeneralSocketCallCard(item, "CARD")
        }

        internal fun processGeneralSocketCallCard(item: Any, logSource: String): Boolean {
            initializeConditions()
            if (!canProcessConditions("KAKAO")) return false
            val card = KakaoCardData.from(item) ?: run {
                log("EUNORA: SOCKET CARD skipped no callId source=$logSource")
                return false
            }
            val callData = card.call
            val callId = callData.callId
            val fare = callData.fare
            val distanceKm = callData.distanceKm
            val origin = callData.origin
            val destination = callData.destination
            if (!CallKindFilter.allows(callData.origin)) {
                log("EUNORA: SOCKET CARD MATCH skipped source=$logSource callId=$callId reason=KIND_FILTER origin=${clean(origin)}")
                return false
            }
            val result = callMatcher.matchAny(callData, ConditionClient.current())
            log("EUNORA: SOCKET CARD MATCH result source=$logSource callId=$callId fare=$fare distanceKm=$distanceKm origin=${clean(origin)} destination=${clean(destination)} matched=${result.matched}")
            if (!result.matched) return false
            val isMini = logSource == "MINI_CARD"
            // Native mini-popup callbacks use LIST, except for WAY_BACK cards.
            val nativeSource = if (card.source == DirectAcceptSource.WAY_BACK) {
                DirectAcceptSource.WAY_BACK
            } else if (isMini) DirectAcceptSource.LIST else DirectAcceptSource.CARD
            val vip = (readField(item, "j") as? Enum<*>)?.name == "VIP"
            return handleDirectAccept(callId, nativeSource, logSource, miniDetail = isMini, vip = vip)
        }

        internal fun handleDirectAccept(callId: String, source: DirectAcceptSource, logSource: String, miniDetail: Boolean = false, vip: Boolean = false): Boolean {
            val outcome = DirectAcceptController.accept(callId, source, miniDetail, vip)
            log("KAKAO: ACCEPT_SUBMISSION id=$callId from=${source.rawValue} source=$logSource status=$outcome; server confirmation pending")
            // A submitted request stops this scan; it never switches detection OFF.
            // Duplicates, cooldown and busy status are not success and do not fall back.
            return outcome == DirectAcceptOutcome.STARTED
        }

        internal fun readPlaceInfo(value: Any?): PlaceInfo {
            if (value == null) return PlaceInfo()
            return PlaceInfo(readField(value, "a") as? String, readField(value, "b") as? String, readField(value, "c") as? String, readField(value, "d") as? String, readField(value, "e") as? String)
        }

        fun readField(instance: Any, fieldName: String): Any? = runCatching { instance.javaClass.getDeclaredField(fieldName).apply { isAccessible = true }.get(instance) }.getOrNull()

        fun invokeNoArg(instance: Any, methodName: String): Any? {
            return runCatching {
                instance.javaClass.methods.firstOrNull { it.name == methodName && it.parameterCount == 0 }
                    ?.apply { isAccessible = true }
                    ?.invoke(instance)
            }.getOrNull() ?: runCatching {
                instance.javaClass.declaredMethods.firstOrNull { it.name == methodName && it.parameterCount == 0 }
                    ?.apply { isAccessible = true }
                    ?.invoke(instance)
            }.getOrNull()
        }

        internal fun numberToInt(value: Any?): Int? = (value as? Number)?.toInt()
        internal fun numberToDouble(value: Any?): Double? = (value as? Number)?.toDouble()
        internal fun clean(value: String?): String = value.orEmpty().replace("\n", " ").replace("\r", " ").trim()
        internal fun safeText(value: Any?): String = clean(value?.toString())

        fun parseFareAnyFormat(raw: String?): Int {
            if (raw.isNullOrBlank()) return 0
            val cleaned = raw.trim().replace(",", "")
            return when {
                cleaned.lowercase().endsWith("k") -> ((cleaned.dropLast(1).toDoubleOrNull() ?: 0.0) * 1000).toInt()
                cleaned.lowercase().endsWith("m") -> ((cleaned.dropLast(1).toDoubleOrNull() ?: 0.0) * 1000000).toInt()
                else -> cleaned.replace(Regex("[^0-9]"), "").toIntOrNull() ?: 0
            }
        }

        fun parseCallmanerListFare(raw: String?): Int {
            if (raw.isNullOrBlank()) return 0
            val kMatch = Regex("""(\d+(?:\.\d+)?)\s*[kK]""").find(raw)
            if (kMatch != null) {
                return (kMatch.groupValues[1].toDouble() * 1000.0).toInt()
            }
            return parseFareAnyFormat(raw)
        }

        fun parseDistanceKm(raw: String?): Double {
            if (raw.isNullOrBlank()) return 0.0
            val cleaned = raw.trim().replace(",", "")
            return Regex("""(\d+(?:\.\d+)?)""").find(cleaned)?.value?.toDoubleOrNull() ?: 0.0
        }

        // 아이드라이브 fee=80 → 8만원. 세 자리 미만이면 천원 단위로 본다.
        fun parseIdriveFee(raw: String?): Int {
            val n = parseFareAnyFormat(raw)
            return if (n in 1..999) n * 1000 else n
        }
    }

    internal fun resolveCallCardFrom(callCardFromClass: Class<*>, expectedRawValue: String, displayName: String): Any {
        val valueMethod = callCardFromClass.declaredMethods.firstOrNull { it.parameterCount == 0 && it.returnType == String::class.java } ?: throw NoSuchMethodException("${callCardFromClass.name} string value method not found")
        valueMethod.isAccessible = true
        for (field in callCardFromClass.declaredFields) {
            if (Modifier.isStatic(field.modifiers) && field.type == callCardFromClass) {
                field.isAccessible = true
                val candidate = field.get(null) ?: continue
                val rawValue = valueMethod.invoke(candidate) as? String
                if (rawValue == expectedRawValue) { log("EUNORA: ${callCardFromClass.name} $displayName resolved field=${field.name} rawValue=$rawValue"); return candidate }
            }
        }
        throw IllegalStateException("${callCardFromClass.name} $displayName value not found rawValue=$expectedRawValue")
    }

    /** Verified Kakao 3.15 CallCard. The package gate precedes this resolver. */
    internal fun resolveKakaoCallCardClass(classLoader: ClassLoader): Class<*> {
        val cls = Kakao315DetectionData.cardClass(classLoader)
        log("EUNORA: kakao 3.15 CallCard resolved ${cls.name}")
        return cls
    }

    internal fun resolveContinuationClass(classLoader: ClassLoader): Class<*> {
        val names = arrayOf("w92", "w00.c", "u00.c", "kotlin.coroutines.Continuation")
        var last: Throwable? = null
        for (name in names) {
            try {
                return Class.forName(name, false, classLoader)
            } catch (t: Throwable) {
                last = t
            }
        }
        throw ClassNotFoundException("Continuation class not found", last)
    }

    // ########################################################################
    // 앱 별 Accept Controller
    // ########################################################################

}

/** Static field adapter for the supplied Kakao fp0 card model. */
internal data class KakaoCardData(
    val call: CallData,
    val source: DirectAcceptSource
) {
    companion object {
        fun from(card: Any): KakaoCardData? = Kakao315DetectionData.cardData(card)

        fun findArgument(args: Array<out Any?>, cardClass: Class<*>): Any? =
            args.firstOrNull { cardClass.isInstance(it) }

    }
}
