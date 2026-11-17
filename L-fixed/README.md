# L — REA 분석과 EUNORA 관찰용 훅 생성

기존 L의 6개 탭과 화면 스타일을 유지하면서 REA 분석, 7개 앱 프로필, 관찰용 훅 생성과 생성본 빌드 검사를 추가했습니다. AI 모델 연결은 이번 범위에서 제외했습니다.

**`main.py`만 교체하지 마세요. ZIP 전체를 새 폴더에 풀어 사용해야 합니다.** 기존 L의 사용자 데이터는 ZIP에 포함하지 않습니다.

## Windows에서 실행

1. Python 3.10 이상을 설치하고 `run_L.bat`를 실행합니다. 첫 실행은 인터넷으로 이 폴더의 `.venv`에 PySide6를 설치합니다.
2. REA 기능에는 지원되는 Node.js와 **전체 JDK 17 이상**이 필요합니다. Node.js 24 LTS와 JDK 21을 권장합니다. Android Studio의 `jbr`도 `jdk.compiler`를 포함하면 사용할 수 있습니다.
3. `setup_rea.bat`를 실행합니다. REA 6.8.0을 이 폴더의 `tools/rea`에 설치하고, 전용 `jadx-headless-mcp 0.7.1` JAR를 내려받아 SHA-256을 확인합니다. Node/JDK 자체는 자동 설치하지 않습니다. 설치에는 인터넷이 필요합니다.
4. 프로그램의 **구조 분석 → REA 설정**에서 경로와 사전 검사를 확인합니다. 기본 분석 제한 시간은 300초이며 큰 APK는 설정에서 늘릴 수 있습니다.

지원되는 Node 버전은 22.23.4 이상인 22.x, 24.22.1 이상인 24.x, 또는 26.12.1 이상입니다. 일반 JADX 설치와 REA의 전용 headless JAR는 서로 다릅니다. 기존 JADX XREF 기능은 별도 JADX 경로를 계속 사용합니다.

자동으로 경로를 찾지 못하면 다음처럼 지정할 수 있습니다.

```cmd
.venv\Scripts\python.exe install_rea.py --node "C:\Program Files\nodejs\node.exe" --java-home "C:\Program Files\Android\Android Studio\jbr"
```

USB 추출·로그 기능에는 Android SDK platform-tools의 `adb.exe`가 필요합니다. 직접 Python으로 실행할 때는 `python -m pip install -r requirements.txt` 이후 `python main.py`를 실행합니다.

## REA 분석 사용

1. **구조 분석** 탭에서 APK를 선택합니다.
2. **REA 분석**을 누르고 APK 정보, 클래스 검색, 클래스 정보, 메서드 분석, 참조 분석 중 하나를 선택합니다.
3. 클래스·메서드·오버로드 등 필요한 대상을 입력해 실행합니다. 결과는 기존 분석 결과창에 표시하고 전체 JSON은 `rea_results`에 저장합니다.

실제 REA CLI를 실행합니다. 실패를 기존 분석 성공 결과로 바꾸지 않으며, 오류와 부분 결과를 구분합니다. 분석은 작업 스레드에서 실행하고 창을 닫으면 진행 중인 작업에 취소를 요청합니다.

## AI 없는 EUNORA 코드 생성

현재 생성 범위는 **선택한 정확한 메서드의 실행을 기록하는 관찰용 훅**입니다. 임의의 새 기능이나 콜 수락 로직을 추론하는 생성기는 아닙니다. 인자·반환값·예외를 변경하지 않고 호출 여부, 인자 개수, 결과 타입 등을 로그로 남깁니다.

1. REA로 대상의 **클래스 정보**를 분석합니다. 검색 결과나 메서드 본문만으로 생성하지 않습니다.
2. **훅 지도 → 훅 코드 생성**에서 앱 프로필, 기존 EUNORA 프로젝트 또는 그 안의 `ModuleMain.kt`, 정확한 메서드·오버로드를 선택합니다. APK는 구조 분석에서 선택한 파일입니다.
3. 생성 시 APK 패키지와 SHA-256을 대조하고 DEX의 실제 선언 클래스·원형·접근 플래그를 확인합니다. 클래스 별칭은 실제 DEX 대상이 하나일 때만 해석합니다.
4. `generated_hooks`에 **전체 ModuleMain.kt와 해당 E파일 사본**, 같은 내용의 TXT, `changes.diff`, `manifest.json`을 만듭니다. 원본 프로젝트를 덮어쓰지 않습니다. 같은 대상의 기존 생성 블록은 중복 추가하지 않고 갱신합니다.
5. **생성본 빌드 검사**를 누르면 프로젝트를 별도 폴더에 복사하고 생성본만 적용하여 `:app:compileDebugKotlin`을 실행합니다. 결과와 로그 경로를 표시합니다. 원본·생성본이 생성 후 바뀌면 검사를 중단하고 다시 생성을 요구합니다.

프로필은 카카오(E02), T맵(E03), 콜마너1·2(E04), 로지D1·D2(E05), 아이드라이브(E06)입니다. 기존 `onPackageLoaded`와 설치 함수 위치를 확인할 수 있는 프로젝트만 지원합니다. 자동으로 불명확한 위치에 삽입하지 않습니다. 생성 폴더는 Android 원본 프로젝트 밖에 있어야 합니다.

빌드에는 프로젝트의 Gradle wrapper JAR, 해당 프로젝트에 맞는 JDK·Android SDK·의존성·로컬 설정이 필요합니다. 일반 Debug 변형을 기준으로 Kotlin 컴파일을 검사합니다. 다른 flavor를 사용하는 프로젝트는 생성 사본에서 해당 변형을 별도로 빌드하세요. 빌드 성공과 기기에서의 훅 실행 확인은 별도입니다. 실제 기기에서 새 APK 설치·LSPosed 적용·프로세스 재시작 후 `L_OBSERVER` 로그를 확인해야 합니다.

## L.exe 만들기와 데이터 위치

Windows에서 `build_L.bat`를 실행하면 PyInstaller가 `dist\L.exe`를 만들고 **이 소스 폴더의 `L.exe`로 복사**합니다. `setup_rea.bat`를 실행한 같은 폴더의 `L.exe`를 사용하세요. 현재 전달물은 소스이며 Windows에서 빌드한 EXE를 포함하지 않습니다.

프로그램은 실행 파일 옆의 `rea_settings.json`, `tools`, `sessions`, `apks`, `hooks.json`, `eunora_hooks.json`을 사용합니다. 다른 폴더로 이동할 때에는 필요한 설정·도구·데이터도 함께 이동하고 **REA 설정에서 절대 경로를 다시 확인**하세요. 소스로 실행하면 `main.py` 옆을 사용합니다. `L_APP_DATA_DIR`로 별도 데이터 폴더를 지정할 수도 있습니다.

분석 원문, 생성 코드, 로그는 사용자 데이터입니다. APK 분석 원문에는 앱 내 문자열·설정이 포함될 수 있으므로 공개 저장소에 그대로 올리지 마세요. 배포 ZIP에는 이 데이터나 설치된 외부 도구를 넣지 않습니다.

## 내부 구조와 유지된 기능

- `main.py`: 실행 진입점, `l_app/ui.py`, `rea_dialogs.py`: 기존 화면과 추가 기능 대화상자
- `rea.py`: REA 실행·환경 검사·근거 저장, `install_rea.py`: 고정 버전 로컬 설치
- `generator.py`, `eunora_profiles.json`: 검증된 대상의 관찰용 Kotlin 사본 생성
- `build_validation.py`: 원본 해시 확인과 격리된 Android 빌드 검사
- `analysis.py`, `adb.py`: 기존 APK/DEX/JADX 분석·USB 기능
- `jobs.py`, `processes.py`: 작업 스레드와 취소 가능한 외부 명령
- `logs.py`, `state.py`, `paths.py`, `workflows.py`, `config.py`: 로그·저장·대조·원본 보존·앱 정보

기존 로그·세션·후보군·추출/비교·구조 분석·훅 지도 기능을 유지했습니다. 한글 로그 청크 복원, 실패 시 원본 보존, 정확한 Kotlin 문자열 치환, 오래된 분석 결과의 복사본 생성 중단도 유지합니다. 정적 문자열 발견은 실행된 훅의 증거로 표시하지 않습니다.

## 검증

`run_tests.bat` 또는 `python -m pytest -q`로 검사합니다. GUI 검사는 Qt offscreen 모드입니다. 검사 환경·결과와 전달 파일 해시는 `VALIDATION.json`에 기록합니다.

실제 APK로 REA 정보·클래스·검색·메서드·참조 분석을 실행하고, 확인된 메서드의 관찰용 훅 사본을 생성하여 Android Kotlin 컴파일을 검사했습니다. 합성 APK/프로세스·실제 Qt 작업 스레드로 오류·취소·파일 보존·UI 연결도 검사합니다. Windows EXE 실행과 실제 휴대폰에서의 훅 실행은 별도 확인이 필요합니다.
