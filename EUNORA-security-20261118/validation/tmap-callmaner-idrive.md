# E03 / E04 / E06 security changes

Changed source files are the latest uploaded project's E03.kt, E04.kt and E06.kt only. Nonsecurity sections remain byte-identical, including CRLF line endings. No build-type/debug flags or separate Android source helpers were added.

## Behavior

- All three `File.exists` callbacks require a successful Boolean `true`, preserve the original throwable, require an actual `File` receiver and compare the five pre-existing approved paths by exact path equality. Similar paths, child paths and unrelated files remain unchanged.
- E03 uses its own path callback. Existing `lb.g.h()Z`, `lb.g.i()Z` and `qh.n.a(String,String)Z` targets are checked for exact primitive Boolean prototypes and concrete Java bodies. Every target is attempted independently. The two-argument callback only changes known `su` directory/binary combinations.
- E03's existing `Runtime.exec` behavior is narrowed to exact `which su` commands, including `/system/bin/which` and `/system/xbin/which`. Both String and String[] overloads retain the original executable, environment and working directory. The `su` argument is replaced with an absent path below `/dev/null`; arbitrary commands and additional arguments remain unchanged. Each of the six known Java exec overloads is checked separately.
- E03 retains existing Build.TAGS handling, but replaces complete `test-keys` tokens only and verifies the field value after writing.
- E04 adds the actual root diagnostic `es.x(android.content.Context):boolean`. Callmaner2 raw DEX confirms public static `(Landroid/content/Context;)Z` with `/system/app/Superuser.apk`, `/system/xbin/su` and `test-keys`. Both available Callmaner1 decompilations show the same method. This method belongs to Crashlytics diagnostics.
- E06 adds the actual IDrive root diagnostic `K1.g.g():boolean`. Raw DEX confirms public static `()Z` with the same root literals. This method belongs to Crashlytics diagnostics.
- SDK Boolean callbacks change successful `true` to `false`, preserving false, non-Boolean results and original errors. Actual changes are logged separately from installation and unsupported-target messages. Registration is deduplicated by Method, with failed hook calls excluded from the installed set.

## Evidence and validation

- `apk-root-evidence.json`: APK hashes and exact method metadata from the actual DEX tables, plus decoded root literals/invokes.
- `preservation.json`: CRLF and nonsecurity section preservation results.
- `run_harness.py`: extracts the production security sections, compiles them against the actual libxposed API100 jar, and runs realistic callback fixtures. `setResult` clears the throwable, so tests detect accidental exception suppression.
- `harness-results.json`: Java/Kotlin compilation and **167 passing assertions**, including exact/similar paths, original errors, type guards, command overload argument preservation, native/abstract rejection, failed registration logging, duplicate registration and Build.TAGS readback.

## Limits

No Tmap APK was available, so existing Tmap obfuscated class names are runtime-prototype checks, not APK static verification. The precise semantics of qh.n.a have not been independently verified; therefore only known root path argument pairs are changed. Missing/changed declarations are reported unsupported.

Callmaner1 has supplied Java source evidence but no available raw APK for independent DEX verification. Callmaner2 and IDrive raw APK evidence is recorded in JSON. Diagnostic root fields are not proof of a service-blocking security gate. IDrive Flutter/native checks, native memory/stack checks, server decisions and attestation are outside these edits. No device runtime success is claimed from JVM tests or Android compilation alone.
