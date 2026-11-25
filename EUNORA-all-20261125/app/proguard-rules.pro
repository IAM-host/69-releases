# Xposed/LSPosed
-keep class de.robv.android.xposed.** { *; }
-keep class io.github.libxposed.** { *; }

# 모듈 진입점
-keep class com.example.wheelprobe.ModuleMain {
    <init>(io.github.libxposed.api.XposedInterface, io.github.libxposed.api.XposedModuleInterface$ModuleLoadedParam);
    *;
}

# Hooker 클래스 전체 유지
-keep class com.example.wheelprobe.*Hooker { *; }
-keepclassmembers class com.example.wheelprobe.*Hooker {
    @io.github.libxposed.api.annotations.BeforeInvocation *;
    @io.github.libxposed.api.annotations.AfterInvocation *;
    @io.github.libxposed.api.annotations.XposedHooker *;
}

# Companion object 메서드 유지
-keepclassmembers class com.example.wheelprobe.*Hooker$Companion {
    *;
}

# Kotlin
-keep class kotlin.** { *; }
-keep class kotlin.Metadata { *; }
-dontwarn kotlin.**

# AndroidX
-keep class androidx.** { *; }
-dontwarn androidx.**

# 로그 유지 (디버그용)
#-assumenosideeffects class android.util.Log {
#    public static *** d(...);
#    public static *** i(...);
#    public static *** v(...);
#}

# Keep the exact JNI export class and native method name.
-keep class com.example.wheelprobe.LogiNativeBridge { *; }
