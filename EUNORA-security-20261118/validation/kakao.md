# Kakao E02 verification

The final run passed **73 cases / 99 assertions**. `harness-results.json`
records the compiler commands, source and API100 hashes, exit codes, and complete
test output. The test runner extracts the security declarations directly from the
current project E02.kt each time; it does not implement another copy of the hook
logic. The hook callbacks implement the actual libxposed API100 interfaces.

Coverage includes:

- Hook registration failures do not log successful registration; a later retry
  works, and already registered members are not hooked twice.
- qf8 construction changes only the rooted Boolean; check mode and constructor
  arguments remain intact. Original exceptions, wrong instances, missing data,
  extra fields, and changed semantic identities remain untouched.
- il4 hook reports use a fresh assessment and fresh report. The five hook-signal
  lists are normalized, the constructor recomputes the derived signal set, and
  original objects remain intact. Missing framework APIs, original probe
  errors/statuses, timestamps, duration, and individual probe objects survive.
  ERROR/PARTIAL probes produce unknown; a framework API mismatch stays detected.
- Sentry root diagnostics require the expected root-path and manager-package
  fields. Crashlytics ar1.I requires the exact supplied target package/version.
  SDK exceptions, package lookup failures, and unsupported values are preserved.
- All 15 exact root paths are exercised through the registered Kakao path hook;
  near matches, substrings, malformed results, and original exceptions survive.
- A child-first class loader simulates an updated APK that reuses the old class
  names with different field/signature contracts. These targets are unavailable
  and are not falsely registered.
- Sentry option hooks remain independent across class loaders. Failed installs
  roll back only their own configuration, can retry, and do not invalidate an
  already installed loader. Setter failures and callback execution remain intact.
- Diagnostics contain no fake raw session token or original probe-error content;
  logger failure does not prevent a successful callback result update.

The Sentry multi-loader case failed before the focused fix. That result is
retained in `sentry-multiloader-before-fix.json`. The fix replaces the single
global setter/getter pair with a constructor-Member-keyed map, rolls back the
failed member, and avoids duplicate constructor registration. An independent
source review accepted this correction.

Target DTOs and Android package services in this harness are external contract
fixtures based on the supplied decompiled sources; they are not the actual
Android APK running on a phone. A passing JVM run establishes callback and
reflection behavior for those contracts. It does not establish LSPosed device
execution, server acceptance, Play Integrity, native/Flutter behavior, or
cross-version compatibility. The parent task performs full Android Debug and
Release compilation separately.

Run from any directory:

```
python /workspace/analysis/eunora-security-20261118/kakao-tests/run_harness.py
```
