package com.example.wheelprobe

import android.annotation.SuppressLint
import android.app.Application
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.Looper

object ConditionClient {

    @Volatile
    private var cachedConditionSets: List<ConditionSet> = emptyList()

    @Volatile
    private var detecting = false

    @Volatile
    private var conditionsReady = false

    @Volatile
    private var initialized = false

    private var conditionReceiver: BroadcastReceiver? = null

    private val mainHandler = Handler(Looper.getMainLooper())

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    fun initialize(log: (String) -> Unit) {
        if (initialized) {
            return
        }

        val context = getCurrentApplication()

        if (context == null) {
            log("condition initialization deferred: application is null, retrying")
            mainHandler.postDelayed({
                if (!initialized) {
                    initialize(log)
                }
            }, 1000L)
            return
        }

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(receiverContext: Context, intent: Intent) {
                if (intent.action != ConditionBridgeReceiver.ACTION_DELIVER_CONDITIONS) {
                    return
                }

                // Old deliveries have three slots (DAERI 1/2, TAKSONG 1).
                // Version 2 keeps those keys for old hook processes and adds six grouped slots.
                val setGroupsVersion = intent.getIntExtra(
                    ConditionProvider.KEY_SET_GROUPS_VERSION, 1
                )
                val grouped = setGroupsVersion == ConditionProvider.SET_GROUPS_VERSION
                val receivedSlotCount = when (setGroupsVersion) {
                    1 -> 3
                    ConditionProvider.SET_GROUPS_VERSION -> ConditionProvider.SET_COUNT
                    else -> 0
                }
                val checkedSets = intent.getBooleanArrayExtra(
                    if (grouped) ConditionProvider.KEY_GROUPED_CHECKED_SETS else ConditionProvider.KEY_CHECKED_SETS
                ) ?: BooleanArray(0)
                val includeWords = intent.getStringArrayExtra(
                    if (grouped) ConditionProvider.KEY_GROUPED_INCLUDE_WORDS else ConditionProvider.KEY_INCLUDE_WORDS
                ) ?: emptyArray()
                val excludeWords = intent.getStringArrayExtra(
                    if (grouped) ConditionProvider.KEY_GROUPED_EXCLUDE_WORDS else ConditionProvider.KEY_EXCLUDE_WORDS
                ) ?: emptyArray()
                val minFares = intent.getStringArrayExtra(
                    if (grouped) ConditionProvider.KEY_GROUPED_MIN_FARES else ConditionProvider.KEY_MIN_FARES
                ) ?: emptyArray()
                val maxDistances = intent.getStringArrayExtra(
                    if (grouped) ConditionProvider.KEY_GROUPED_MAX_DISTANCES else ConditionProvider.KEY_MAX_DISTANCES
                ) ?: emptyArray()
                val allowDaeri = intent.getBooleanExtra(ConditionProvider.KEY_ALLOW_DAERI, true)
                val allowTaksong = intent.getBooleanExtra(ConditionProvider.KEY_ALLOW_TAKSONG, true)
                val taksongToday = intent.getBooleanExtra(ConditionProvider.KEY_TAKSONG_TODAY, true)
                val taksongTomorrow = intent.getBooleanExtra(ConditionProvider.KEY_TAKSONG_TOMORROW, true)
                CallKindFilter.apply(allowDaeri, allowTaksong)
                TaksongDateFilter.apply(taksongToday, taksongTomorrow)

                val hasExpectedShape = receivedSlotCount > 0 &&
                        checkedSets.size == receivedSlotCount &&
                        includeWords.size == receivedSlotCount &&
                        excludeWords.size == receivedSlotCount &&
                        minFares.size == receivedSlotCount &&
                        maxDistances.size == receivedSlotCount
                val receivedConditionSets = buildList {
                    if (!hasExpectedShape) return@buildList
                    for (index in 0 until receivedSlotCount) {
                        val checked = index < checkedSets.size && checkedSets[index]

                        if (!checked) {
                            continue
                        }

                        val groupedIndex = if (setGroupsVersion == 1 && index == 2) {
                            ConditionProvider.SETS_PER_KIND
                        } else {
                            index
                        }
                        val isTaksong = ConditionProvider.isTaksongIndex(groupedIndex)
                        if (isTaksong) {
                            if (!allowTaksong || (!taksongToday && !taksongTomorrow)) continue
                        } else if (!allowDaeri) {
                            continue
                        }

                        val condition = MatchCondition(
                            includeWord = includeWords.getOrNull(index).orEmpty(),
                            excludeWord = excludeWords.getOrNull(index).orEmpty(),
                            minFare = minFares.getOrNull(index)?.trim()?.takeIf { it.isNotEmpty() }?.toIntOrNull(),
                            maxDistanceKm = maxDistances.getOrNull(index)?.trim()?.takeIf { it.isNotEmpty() }?.toDoubleOrNull()
                        )

                        if (condition.hasAnyCondition()) {
                            add(
                                ConditionSet(
                                    setNumber = ConditionProvider.localSetNumber(groupedIndex),
                                    condition = condition,
                                    callKind = if (ConditionProvider.isTaksongIndex(groupedIndex)) {
                                        CallKind.TAKSONG
                                    } else {
                                        CallKind.DAERI
                                    }
                                )
                            )
                        }
                    }
                }

                val requestedDetecting = intent.getBooleanExtra(
                    ConditionProvider.KEY_DETECTING, false
                )

                cachedConditionSets = receivedConditionSets

                detecting = requestedDetecting && receivedConditionSets.isNotEmpty()

                conditionsReady = true

                val gpsEnabled = intent.getBooleanExtra(
                    ConditionProvider.KEY_GPS_ENABLED,
                    false
                )
                val gpsLat = intent.getStringExtra(ConditionProvider.KEY_GPS_LAT)
                val gpsLng = intent.getStringExtra(ConditionProvider.KEY_GPS_LNG)

                GpsSpoofState.applyFromDelivery(
                    detectingValue = requestedDetecting,
                    gpsEnabled = gpsEnabled,
                    latStr = gpsLat,
                    lngStr = gpsLng
                )

                log(
                    "conditions received: " +
                            "detecting=$detecting, " +
                            "activeSetCount=${receivedConditionSets.size}, " +
                            "gpsEnabled=$gpsEnabled, gpsLat=$gpsLat, gpsLng=$gpsLng"
                )

                for (conditionSet in receivedConditionSets) {
                    val condition = conditionSet.condition
                    log(
                        "condition ${conditionSet.callKind} SET ${conditionSet.setNumber}: " +
                                "include=${condition.includeWord}, " +
                                "exclude=${condition.excludeWord}, " +
                                "minFare=${condition.minFare}, " +
                                "maxDistanceKm=${condition.maxDistanceKm}"
                    )
                }
            }
        }

        try {
            val filter = IntentFilter(
                ConditionBridgeReceiver.ACTION_DELIVER_CONDITIONS
            )

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                context.registerReceiver(receiver, filter)
            }

            conditionReceiver = receiver

            val requestIntent = Intent(
                ConditionBridgeReceiver.ACTION_REQUEST_CONDITIONS
            ).apply {
                component = ComponentName(
                    BRIDGE_PACKAGE,
                    "$BRIDGE_PACKAGE.ConditionBridgeReceiver"
                )
            }

            context.sendBroadcast(requestIntent)

            initialized = true
            log("condition broadcast receiver registered")
            log("condition request broadcast sent")

        } catch (throwable: Throwable) {
            runCatching {
                context.unregisterReceiver(receiver)
            }

            conditionReceiver = null
            initialized = false
            conditionsReady = false
            detecting = false
            cachedConditionSets = emptyList()

            log(
                "condition initialization failed: " +
                        "${throwable.javaClass.name}: ${throwable.message}"
            )

            // 실패해도 1초 뒤 재시도
            mainHandler.postDelayed({
                if (!initialized) {
                    initialize(log)
                }
            }, 1000L)
        }
    }

    fun isReady(): Boolean {
        return conditionsReady
    }

    fun isDetecting(): Boolean {
        return conditionsReady && detecting
    }

    fun current(): List<ConditionSet> {
        return cachedConditionSets
    }

    fun stopDetecting(reason: String = "accepted") {
        // 훅 프로세스(카카오 등)의 로컬 플래그 먼저 OFF
        detecting = false
        android.util.Log.d("EUNORA_CONDITION", "Detecting stopped. reason=$reason")

        try {
            GpsSpoofState.applyFromDelivery(
                detectingValue = false,
                gpsEnabled = false,
                latStr = null,
                lngStr = null
            )
        } catch (_: Throwable) {
        }

        // EUNORA 앱 프로세스로 명시 전달 (prefs 갱신 + UI)
        // 예전: 패키지 미지정 브로드캐스트 → 수신 실패하면 화면이 DETECTING에 고정됨
        try {
            val context = getCurrentApplication() ?: return

            val stopIntent = Intent(ConditionBridgeReceiver.ACTION_STOP_DETECTING).apply {
                setPackage(BRIDGE_PACKAGE)
                putExtra("reason", reason)
                putExtra("detecting", false)
            }
            context.sendBroadcast(stopIntent)

            val uiIntent = Intent("com.example.wheelprobe.DETECTING_CHANGED").apply {
                setPackage(BRIDGE_PACKAGE)
                putExtra("detecting", false)
            }
            context.sendBroadcast(uiIntent)

            android.util.Log.d(
                "EUNORA_CONDITION",
                "stopDetecting broadcast sent to $BRIDGE_PACKAGE reason=$reason"
            )
        } catch (t: Throwable) {
            android.util.Log.w(
                "EUNORA_CONDITION",
                "stopDetecting broadcast failed: ${t.message}"
            )
        }
    }

    private fun getCurrentApplication(): Application? {
        return try {
            val activityThreadClass = Class.forName("android.app.ActivityThread")
            val currentApplicationMethod = activityThreadClass.getDeclaredMethod("currentApplication")
            currentApplicationMethod.isAccessible = true
            currentApplicationMethod.invoke(null) as? Application
        } catch (_: Throwable) {
            null
        }
    }

    private const val BRIDGE_PACKAGE = "com.example.wheelprobe"
}
