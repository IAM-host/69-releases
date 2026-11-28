# TMAP177 final source review

The two-file change passes the scoped static/JVM/build/package review. Native last-location symbols were independently checked against both rawDEX indexes. No new source issue requiring a change remained after review.

The connected fixture initially expected no later candidate after a definitive401 rejection. Its list also contained a different valid candidate; production correctly released the failed attempt and selected that later candidate. The fixture now isolates a same-ID replay and separately verifies a different candidate is permitted. No production change was made to satisfy that incorrect expectation. The fixture also supplies package metadata added by the final exact-version gate.

Tests execute verbatim extracted production regions; Android/Xposed/native-location/backend boundaries are named fixtures. The real releaseAPK was built and inspected. No phone or backend was contacted. Unknown network outcomes retain a process-local reservation across OFF/ON; a process restart is outside that in-memory guarantee. Existing unchanged E02 compiler warnings remain.
