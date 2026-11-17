"""Application profiles and parsing patterns shared by the desktop UI."""
import re

APP_LABELS = {
    "kakao": "카카오 대리",
    "callmaner": "콜마너1",
    "callmaner2": "콜마너2",
    "tmap": "T맵 대리",
    "logi": "로지D1",
    "logi2": "로지D2",
    "idrive": "아이드라이브",
}

DRIVER_APPS = {
    "kakao": {
        "package": "com.kakao.wheel.driver",
        "needles": ["yi.i", "gj.z0.k", "ON_DEMAND", "com.kakao.wheel.driver"],
    },
    "callmaner": {
        "package": "com.callmanerdriver2sharp1",
        "needles": ["Lls0;", "Lci;", "CallCardHolder", "_221_01_rq"],
    },
    "callmaner2": {
        "package": "com.callmanerdriver2sharp2",
        "needles": ["Lls0;", "Lci;", "CallCardHolder", "_221_01_rq"],
    },
    "tmap": {
        "package": "com.tmapmobility.drive.driver",
        "needles": ["me.x.b", "te.l0", "me.w", "com.tmapmobility.drive.driver"],
    },
    "logi": {
        "package": "com.logisoft.Logi4",
        "needles": ["Lcom/logisoft/LogiD/Info/ORDER;", "makeDaeriOrder", "OrderFormView2_1D"],
    },
    "logi2": {
        "package": "com.logisoft.Logi5",
        "needles": ["Lcom/logisoft/LogiD/Info/ORDER;", "makeDaeriOrder", "OrderFormView2_1D"],
    },
    "idrive": {
        "package": "com.idriver",
        "needles": ["LX0/a;", "LA2/b;", "overlayAction", "accept"],
    },
}

# Keep the original history keys. Variants share default analysis rules, while
# captures and APK snapshots remain separated by the selected application key.
APP_FAMILIES = {
    "kakao": "kakao",
    "callmaner": "callmaner",
    "callmaner2": "callmaner",
    "tmap": "tmap",
    "logi": "logi",
    "logi2": "logi",
    "idrive": "idrive",
}


def family_for(app_key: str) -> str:
    return APP_FAMILIES.get(app_key, app_key)

DEFAULT_HOOKS = {
    "kakao": [
        {
            "id": "kakao_network_dto",
            "note": "네트워크 DTO 매칭",
            "keywords": ["EUNORA", "DTO MATCH", "ON_DEMAND", "NETWORK", "yi.i"],
        },
        {
            "id": "kakao_call_list",
            "note": "콜리스트 화면",
            "keywords": ["CallListActivity", "com.kakao.wheel.driver"],
        },
    ],
    "callmaner": [
        {"id": "cm_match", "note": "matchAndAccept", "keywords": ["CALLMANER", "MATCH", "ACCEPT"]},
    ],
    "tmap": [
        {"id": "tmap_match", "note": "TMAP match", "keywords": ["TMAP", "MATCH", "ACCEPT"]},
    ],
    "logi": [
        {"id": "logi_match", "note": "LOGI match", "keywords": ["LOGI", "MATCH", "ACCEPT"]},
    ],
    "idrive": [
        {"id": "idrive_overlay", "note": "자동·즉시배차", "keywords": ["IDRIVE", "overlay", "ACCEPT"]},
    ],
}

DTO_RE = re.compile(
    r"DTO MATCH.*?group=(\S+)\s+index=(\d+)\s+callId=(\S+)\s+fare=(\S+)\s+"
    r"distanceKm=(\S+)\s+destination=(.*?)\s+matched=(\S+)",
    re.IGNORECASE,
)

NET_RE = re.compile(
    r"EUNORA:\s*NETWORK\s+(\S+)\s+RETURNED\s+source=(\S+)\s+class=(\S+)",
    re.IGNORECASE,
)

CLASS_LIKE = re.compile(
    r"^(?:[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+|(?:[a-z]{1,3}\.)+[A-Za-z0-9_]+|[A-Za-z][\w$]{2,80})$"
)

SKIP_PREFIX = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
    "com.google.", "com.samsung.", "com.android.", "dalvik.", "org.",
    "okhttp", "okio", "retrofit", "gson", "glide",
)

