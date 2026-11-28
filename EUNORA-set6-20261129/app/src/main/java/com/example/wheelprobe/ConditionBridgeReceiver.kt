package com.example.wheelprobe

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class ConditionBridgeReceiver : BroadcastReceiver() {

    override fun onReceive(
        context: Context,
        intent: Intent
    ) {
        when (intent.action) {
            ACTION_REQUEST_CONDITIONS -> sendCurrentConditions(context)
            ACTION_STOP_DETECTING -> handleStopDetecting(context, intent)
            else -> return
        }
    }

    companion object {

        const val ACTION_REQUEST_CONDITIONS =
            "com.example.wheelprobe.action.REQUEST_CONDITIONS"

        const val ACTION_DELIVER_CONDITIONS =
            "com.example.wheelprobe.action.DELIVER_CONDITIONS"

        /** 훅 프로세스(카카오 등) → EUNORA 프로세스로 감지 OFF 요청 */
        const val ACTION_STOP_DETECTING =
            "com.example.wheelprobe.action.STOP_DETECTING"

        private const val LOG_TAG = "EUNORA"

        private fun handleStopDetecting(context: Context, intent: Intent) {
            val reason = intent.getStringExtra("reason") ?: "accepted"
            try {
                val preferences = context.getSharedPreferences(
                    ConditionProvider.PREF_FILE_NAME,
                    Context.MODE_PRIVATE
                )
                preferences.edit()
                    .putBoolean(ConditionProvider.PREF_DETECTING, false)
                    .commit()

                // MainActivity UI
                val uiIntent = Intent("com.example.wheelprobe.DETECTING_CHANGED").apply {
                    setPackage(context.packageName)
                    putExtra("detecting", false)
                }
                context.sendBroadcast(uiIntent)

                // 대상 앱 프로세스 캐시도 false 로 맞춤
                sendCurrentConditions(context)

                Log.i(LOG_TAG, "STOP_DETECTING handled reason=$reason prefs+UI updated")
            } catch (t: Throwable) {
                Log.e(LOG_TAG, "STOP_DETECTING failed reason=$reason", t)
            }
        }

        fun sendCurrentConditions(context: Context) {
            val preferences = context.getSharedPreferences(
                ConditionProvider.PREF_FILE_NAME,
                Context.MODE_PRIVATE
            )
            val payload = try {
                ConditionProvider.buildConditionsPayload(preferences)
            } catch (t: Throwable) {
                Log.e(LOG_TAG, "conditions broadcast skipped: set migration/read failed", t)
                return
            }
            val detecting = payload.getBoolean(ConditionProvider.KEY_DETECTING, false)
            val gpsEnabled = payload.getBoolean(ConditionProvider.KEY_GPS_ENABLED, false)
            val gpsLat = payload.getString(ConditionProvider.KEY_GPS_LAT)
            val gpsLng = payload.getString(ConditionProvider.KEY_GPS_LNG)

            for (target in ConditionProvider.ALLOWED_PACKAGES) {
                val responseIntent = Intent(ACTION_DELIVER_CONDITIONS).apply {
                    setPackage(target)

                    putExtras(payload)
                }

                try {
                    context.sendBroadcast(responseIntent)
                } catch (t: Throwable) {
                    Log.w(LOG_TAG, "conditions broadcast failed target=$target: ${t.message}")
                }
            }

            Log.i(
                LOG_TAG,
                "conditions broadcast sent detecting=$detecting " +
                        "gpsEnabled=$gpsEnabled gpsLat=$gpsLat gpsLng=$gpsLng"
            )
        }
    }
}
