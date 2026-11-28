package com.example.wheelprobe

data class CallData(
    val callId: String,
    val origin: String,
    val destination: String,
    val fare: Int,
    val distanceKm: Double
)

data class MatchCondition(
    val includeWord: String,
    val excludeWord: String,
    val minFare: Int?,
    val maxDistanceKm: Double?
) {
    fun hasAnyCondition(): Boolean {
        return includeWord.isNotBlank() ||
                excludeWord.isNotBlank() ||
                minFare != null ||
                maxDistanceKm != null
    }
}

enum class CallKind { DAERI, TAKSONG }

data class ConditionSet(
    val setNumber: Int,
    val condition: MatchCondition,
    val callKind: CallKind = CallKind.DAERI
)

data class MatchResult(
    val matched: Boolean,
    val reason: String,
    val reasonCode: String
)

data class MultiSetMatchResult(
    val matched: Boolean,
    val matchedSetNumber: Int?,
    val reasonCode: String,
    val detail: String
)

class CallMatcher {

    /*
     * 대리와 탁송은 각각 별도의 SET 1, 2, 3을 사용한다.
     * 콜 종류와 일치하는 그룹의 로컬 SET 번호만 검사한다.
     */
    fun matchAny(
        call: CallData,
        conditionSets: List<ConditionSet>
    ): MultiSetMatchResult {
        if (conditionSets.isEmpty()) {
            return MultiSetMatchResult(
                matched = false,
                matchedSetNumber = null,
                reasonCode = "NO_ACTIVE_SET",
                detail = "no active set"
            )
        }

        val callKind = if (CallKindFilter.isTaksong(call.origin)) {
            CallKind.TAKSONG
        } else {
            CallKind.DAERI
        }
        val allowedSets = conditionSets.filter { set ->
            set.callKind == callKind && set.setNumber in 1..3
        }

        if (allowedSets.isEmpty()) {
            return MultiSetMatchResult(
                matched = false,
                matchedSetNumber = null,
                reasonCode = "NO_SET_FOR_KIND",
                detail = "${callKind.name.lowercase()} but no SET 1/2/3"
            )
        }

        val failureDetails = mutableListOf<String>()

        for (conditionSet in allowedSets) {
            val result = match(
                call = call,
                condition = conditionSet.condition
            )

            if (result.matched) {
                return MultiSetMatchResult(
                    matched = true,
                    matchedSetNumber = conditionSet.setNumber,
                    reasonCode = "ALL_CONDITIONS_MATCH",
                    detail = "SET_${conditionSet.setNumber}:" + result.reasonCode
                )
            }

            failureDetails.add(
                "SET_${conditionSet.setNumber}:" + result.reasonCode
            )
        }

        return MultiSetMatchResult(
            matched = false,
            matchedSetNumber = null,
            reasonCode = "NO_SET_MATCH",
            detail = failureDetails.joinToString(separator = "|")
        )
    }

    /*
     * 하나의 SET 안에서는 모든 조건이 AND 관계다.
     *
     * 단어 조건은 출발지가 아니라 도착지만 검사한다.
     *
     * 단어감지와 제외단어는 쉼표(,)로 여러 개 입력할 수 있다.
     *
     * 예:
     * 단어감지 = "국동,여서동"
     * → 국동 또는 여서동 중 하나라도 도착지에 있으면 통과
     *
     * 제외단어 = "서울,광주"
     * → 서울 또는 광주 중 하나라도 도착지에 있으면 제외
     */
    fun match(
        call: CallData,
        condition: MatchCondition
    ): MatchResult {
        val destinationText = call.destination.trim().lowercase()

        val includeWords = splitKeywords(condition.includeWord)
        val excludeWords = splitKeywords(condition.excludeWord)

        /*
         * 포함 단어가 하나 이상 설정돼 있으면
         * 그중 하나라도 도착지에 포함되어야 통과한다.
         */
        if (includeWords.isNotEmpty()) {
            val includeMatched = includeWords.any { word ->
                destinationText.contains(word)
            }

            if (!includeMatched) {
                return MatchResult(
                    matched = false,
                    reason = "포함 단어 불일치",
                    reasonCode = "INCLUDE_MISMATCH"
                )
            }
        }

        /*
         * 제외 단어가 하나 이상 설정돼 있으면
         * 그중 하나라도 도착지에 포함되는 순간 제외한다.
         */
        if (excludeWords.isNotEmpty()) {
            val foundExcludeWord = excludeWords.firstOrNull { word ->
                destinationText.contains(word)
            }

            if (foundExcludeWord != null) {
                return MatchResult(
                    matched = false,
                    reason = "제외 단어 발견: $foundExcludeWord",
                    reasonCode = "EXCLUDE_FOUND"
                )
            }
        }

        condition.minFare?.let { minFare ->
            if (call.fare < minFare) {
                return MatchResult(
                    matched = false,
                    reason = "최소 금액 미달",
                    reasonCode = "MIN_FARE_FAIL"
                )
            }
        }

        condition.maxDistanceKm?.let { maxDistance ->
            // 거리 정보 없음/실패(0 이하)면 거리 조건을 통과시키지 않음
            if (call.distanceKm <= 0.0) {
                return MatchResult(
                    matched = false,
                    reason = "거리 정보 없음",
                    reasonCode = "DISTANCE_UNKNOWN"
                )
            }
            if (call.distanceKm > maxDistance) {
                return MatchResult(
                    matched = false,
                    reason = "최대 거리 초과",
                    reasonCode = "MAX_DISTANCE_FAIL"
                )
            }
        }

        return MatchResult(
            matched = true,
            reason = "모든 조건 일치",
            reasonCode = "ALL_CONDITIONS_MATCH"
        )
    }

    /*
     * 영문 쉼표(,)를 기준으로 단어를 나눈다.
     *
     * - 앞뒤 공백 제거
     * - 대소문자 구분 제거
     * - 빈 항목 제거
     * - 중복 단어 제거
     *
     * 예:
     * "국동, 여서동,,국동,"
     * → ["국동", "여서동"]
     */
    private fun splitKeywords(rawValue: String): List<String> {
        return rawValue
            .split(',')
            .map { word -> word.trim().lowercase() }
            .filter { word -> word.isNotEmpty() }
            .distinct()
    }
}
