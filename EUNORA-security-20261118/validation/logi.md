# Logi E05 verification

The current E05 security section passed **564 JVM assertions** compiled against the real libxposed API 100 JAR and Android framework type declarations. The harness extracts the security section from the modified E05 file on every run; it does not maintain a second implementation of the callbacks.

Verified behavior:

- D1 and D2 APK DEX files contain the exact static `t.run():t.a` and `u.run(Context):u.a` endpoints, DTO fields, no-argument constructors, and seven expected flag constants. `apk-contracts.json` records the evidence and APK hashes.
- Root evidence selected by the confirmed probe is removed using a new DTO. Unknown positive evidence remains positive. The original DTO and lists remain unchanged.
- The selected Xposed flag bits are cleared across 512 combinations. Frida, debugger, unknown bits and diagnostic order remain unchanged. Unrelated stack evidence keeps its shared stack flag.
- Exact root-file targets change an existing true result. Similar path names, unrelated files, wrong result types, unknown members, malformed list values, nulls and original exceptions are preserved.
- Changed flag contracts refuse report registration. D1/D2 duplicate installation retains one registration per reflected member. Unattached package routes are rejected.
- Concurrent installation with the first registration failing still leaves one successful registration and a working callback layout, for both report endpoints.
- A logger that throws on every message cannot invalidate successful registration, callback DTO changes, file changes, or original values when the callback setter rejects a write.

The concurrent fixture uses a constructor barrier so both installers reach the report registration stage before one deliberately fails. A negative control substitutes the former unsynchronized cache publication only in the extracted test source. It fails the root callback-layout assertion as expected; it never edits E05.

Two verified implementation defects were corrected during this follow-up: report cache publication and failed-registration rollback now share the registry lock, and diagnostic logger failures cannot roll back successful hooks or escape security callbacks.

The scope verifier passed after these changes: only E02–E06 differ from the uploaded baseline, 69 other files are unchanged, and all 106 protected declarations remain byte-for-byte identical. ModuleMain, call matching, acceptance and GPS code were preserved.

These are JVM and static APK contract checks. They do not claim execution on an Android device, universal root concealment, native/Flutter coverage or server attestation behavior. Final Android compilation is tracked by the parent task.

Reproduce:

```sh
python /workspace/analysis/eunora-security-20261118/logi-tests/verify_apk_contracts.py
python /workspace/analysis/eunora-security-20261118/logi-tests/run.py
LOGI_UNSAFE_REGISTRATION=1 python /workspace/analysis/eunora-security-20261118/logi-tests/run.py
python /workspace/analysis/eunora-security-20261118/verify_security_scope.py
```

`validation.json` records the exact frozen E05 source hash and assertion count; `negative-control/validation.json` records the rejected earlier registration behavior.
