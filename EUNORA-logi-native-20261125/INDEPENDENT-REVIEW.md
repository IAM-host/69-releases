# Independent review of actual implementation

Reviewed 2026-11-24 UTC, refreshed after the final diagnostic-only E05 update. **No blocking implementation issue found in the reviewed sources.** Current release ZIP packaging was independently rechecked; final selected artifact/signature checks belong to the parent, and runtime behavior remains unverified. This reviewer did not edit production sources, execute Android/SDK/ARM64 target code, contact app servers, or publish anything.

## Frozen sources

Project: `/workspace/projects/WheelProbe-logi-native-20261125`

| File | SHA256 |
| --- | --- |
| `app/src/main/java/com/example/wheelprobe/E05.kt` | `323519395979e91284a63d6d1dc9b905f4dbfe0fdf96533cff29a95db3e5c345` |
| `app/src/main/java/com/example/wheelprobe/ModuleMain.kt` | `1b560c055be5c4fa86666a2d0e16b9e5efad372c6751dd31f3e67f2f76dcb412` |
| `app/src/main/cpp/eunora_logi_native.c` | `80d850da062e93024097811ab4c92527b8f941616ce180e9404963689000f678` |
| `app/src/main/cpp/eunora_logi_native.h` | `09397597cc487660f5c07b1b19946cba609f8f9bd9c95f9f3b591cc754e58d14` |
| `app/proguard-rules.pro` | `38fd53491eec68aff0f4e67f361ae19be95647f3c631f9c39507fa66553f0502` |
| `app/src/main/resources/META-INF/xposed/native_init.list` | `4ea33bdd15e33533b37ada7882d44b3ac301cb5f9bb2a5bf24265b444d01d3dc` |

The project C/header copies match the frozen component files byte-for-byte. `actual-review-snapshot.json` records the file hashes, all four helper hashes, 16K LOAD alignments, and byte-preservation checks.

## Java integration

- `ModuleMain.kt:24` saves the supplied API100 process name using `runCatching { param.processName }.getOrNull().orEmpty()`. A failed or absent early process value becomes an empty string and cannot pass the exact process guard. This adds a guarded getter invocation to module construction, without changing the existing initialization branches.
- The install call is inside the existing Logi supported-package/first-package branch, immediately after route attachment and before the previous Logi class installation calls. The native bridge itself rejects D2 and every package except `com.logisoft.Logi4`, so those calls do no identity I/O or native loading for the other Logi package. Other application branches are unchanged.
- `LogiNativeBridge.identityFailure` checks attached route, target `ApplicationInfo.packageName`, saved main process name, 64-bit process, `os.arch` equal to aarch64/arm64, exact base APK SHA256, and exact ARM64 target library SHA256. The supplied base APK SHA256 was independently reproduced as `f499048003d97075eef65c732566e68659c6d3e55fc0df473bcc23594a860f5b`. The supplied native ELF SHA256 independently matches `49be73b2b264f56e823c1a786468e26f9174493fee68b25d947b38f7af2f5d85`.
- An existing extracted target library is authoritative: its mismatch does not fall back to a valid APK copy. ZIP candidates come from host `sourceDir` and `splitSourceDirs`; the first present target entry must match. Invalid ZIP/input errors reject the identity. The bridge does not query PackageManager or depend on an Application context.
- Helper paths use **module** `module.applicationInfo`, including a module-package check. They never use target `nativeLibraryDir` for the helper. Candidate order is module extracted file, then module base/split APK entries; helper ZIP entries must be nonempty and STORED. A direct-load failure tries the next ZIP candidate. This matches the official LSPosed module-loader convention established in `REVIEW.md`.
- Successful `System.load` only records that the helper is loaded. JNI `status()` determines the reported state. API-unavailable and armed/waiting messages do not claim ACTIVE; only native state 2 does. The outer error message says bridge/status unavailable and makes no blanket claim that a successfully initialized helper is unchanged.
- Final diagnostics send the same message to the module logger and Android tag `EUNORA_LOGI_NATIVE`, with a separate catch around each sink. Removing this helper and reversing its four call-site replacements reproduces the exact previously reviewed E05 hash `5e5d821589af0b79c697e5c1ea199938c3bc29920ababb6495b2410702ed6b58`; identity, load and status logic are byte-identical after that reversal. See `diagnostic-delta-verification.json`.
- The modern native metadata contains exactly `libeunora_logi_native.so` plus newline. The keep rule preserves the exact JNI class and native method names. The parent release report confirms the retained signature `public static native int LogiNativeBridge.status()` after R8.

## Native component

The frozen source has one target replacement: `_Z17get_rooting_checkv`, a DWARF-proven `bool(void)` leaf. It adds no global getuid/access/filesystem/package/shell/stack/memory hooks. The only `/proc` read is the helper's own `/proc/self/cmdline` process guard.

- **Timing and framework:** `native_init` accepts the known v1/v2 API prefix with non-null hook/unhook pointers, exact `/proc/self/cmdline` main process (NUL included), and compile-time AArch64 support. Before registering its callback it checks already-loaded module names. A target already present produces `LATE_UNSUPPORTED`; it does not pretend to recover an already executed report. The normal state after initialization is `WAIT_TARGET`. The manual Java load occurs at the supported API100 package callback point, after framework entrypoint registration.
- **Image validation:** Target callback name and handle are checked. `dlsym` must resolve the exact symbol; `dladdr` must identify that symbol exactly; `dl_iterate_phdr` must locate the same image base and matching target image name. For path-bearing callbacks, the callback path must match the image path reported by the loader. The symbol address must be exactly image base plus `0x29fa38`; its entire 312-byte range must be in a readable/executable file-backed LOAD segment. The GNU Build ID must match the actual supplied ELF, with bounded and file-backed note parsing, and the initial 16-byte prologue must match before installation.
- **Real input acceptance:** Build ID is `f33ca221a410357b0c01f355bbbccf5d69790f57`; prologue bytes are `ff4302d1fd7b07a9f44f08a9fdc30191`. Both match the supplied ELF. The implementation uses virtual-address/load-bias validation; it does not mistake virtual `0x29fa38` for raw file offset `0x29ba38`.
- **Installation and publication:** The callback uses `pthread_mutex_trylock`, so recursive backend `dlopen` callbacks do not wait on their own installation mutex. Status enters INSTALLING before the backend call. The atomic original trampoline is published before ACTIVE. Installation logging occurs after unlocking; incoming callback/native-init errno is restored. There is a conservative publication window where a replacement reached before the trampoline exists returns true, never a manufactured clean false.
- **Original execution:** Once the original pointer is present, the wrapper calls it first on every invocation, preserves its side effects, saves its resulting errno, logs first normalization once, restores that errno, and normalizes only this returned boolean to false. The wrapper does not skip `initUtil` or its remaining report/encryption/native work.
- **Failure behavior:** A failed hook or success without a trampoline never sets ACTIVE. A success without backup, or failure with a possible backup, attempts unhook and distinguishes HOOK_FAILED from ROLLBACK_FAILED. An absent original pointer returns true; failure therefore does not return false-clean. A backend nonzero result with a null backup relies on the backend's failure contract and is not treated as successful installation.
- **Repeated loads/reloads:** A repeated callback for the same installed image compares the installed prologue bytes and does not hook twice. A different base or restored/changed installed prologue yields RELOAD_REJECTED. Repeated initialization only returns the existing callback for matching valid hook/unhook entries and an already viable state; invalid/different backend entries are rejected without clearing a successful existing state. Candidate validation errors record TARGET_REJECTED and prevent a later blind retry.

## Verification reviewed and independently added

The final Java agent report reran all 35 cases successfully against E05 SHA `323519395979e91284a63d6d1dc9b905f4dbfe0fdf96533cff29a95db3e5c345`. I inspected the production extraction boundary and fixtures: only JNI status and `System.load` are replaced; production guard, hash, route and candidate-selection bodies are compiled. It includes actual supplied base/split acceptance, extracted-native acceptance, wrong process/ABI/package/hash rejection, authoritative native mismatch, malformed/missing inputs, helper fallback order, and status reporting. This is host Kotlin execution with Android stubs, not Android app execution.

The native component report covers 39 host cases under AddressSanitizer/UndefinedBehaviorSanitizer. I inspected the cases for wrong process/API/image/symbol/prologue/build ID/range, malformed notes, reentrant callbacks, original side effects/errno, pre-trampoline fallback, hook/rollback failures, repeated initialization/load and same/different-base reloads. LeakSanitizer is disabled because of the managed environment's ptrace monitor.

I added and ran `actual_elf_image_test.c` with ASan/UBSan. It copies the **actual ARM64 ELF's LOAD segments into ordinary non-executable heap data**, passes its actual program headers through the frozen component's real validation functions, and substitutes host loader/hook/original primitives. It passed actual PT_NOTE/Build ID/prologue acceptance, one-time installation, host-original side effects/errno, and restored-prologue reload rejection. It executes no ARM64 target instruction or Android SDK function.

The four project helpers are built from byte-identical frozen C/header sources with the parent build flags; their binary hashes differ from the component agent’s build and are recorded separately in the snapshot and `../native-build.json`. I independently inspected their ELF program headers: every LOAD has alignment `0x4000` (16K). The component verifier records only `native_init` and `Java_com_example_wheelprobe_LogiNativeBridge_status` as exports and only libdl/liblog/libc dependencies. No libc++ runtime or new Gradle dependency is introduced.

## Scope preservation

Independent comparison with `baseline.json` found only these existing source files changed: E05, ModuleMain, and proguard rules. The complete original E05 bytes remain an exact prefix of the current file. Removing precisely the added saved-process field and one install call restores ModuleMain to its exact original bytes. Gradle and manifest remain byte-identical. Thus old D2 and Java acceptance code are preserved by byte comparison, rather than merely by source inspection.

No installed-app query, module hiding, native authentication path, SET UI, publication or app server request was added in the reviewed source changes.

## Remaining validation boundary

The parent build log records a successful full Debug/Release build with lint and R8 in 66 seconds. Its release report records metadata/native entry/JNI retention and all four packaged helpers. I independently rechecked the current unsigned release APK ZIP: CRC integrity passed, modern native metadata matched, all four helpers were STORED, and every native ZIP data offset was divisible by 16384. These are APK ZIP alignment checks in addition to source ELF LOAD alignment. The inspected unsigned Gradle artifact SHA256 is `665fc3fc972597b57755f81173086c2c71052c6469d925eaf731132db76d466b`; final selected artifact hashes/signature checks remain with the parent.

The parent’s integration report also passes all 11 payload files against both prior Java-fix and prior cleanup baselines, including exact backups and an unchanged second run. This was actual PowerShell 7.5.4 on Linux; it does not establish execution on Windows.

The design intentionally reports late load, ABI/API mismatch, candidate rejection, rollback failure and reload as unsupported/error states. The callback still runs after ELF constructors, and callbacks are not retroactive. No device/runtime hook outcome, server report outcome, installed framework-fork compatibility or server decision is established by these host/static checks.
