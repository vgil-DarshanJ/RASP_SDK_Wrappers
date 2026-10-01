# The TurboModule / bridge module is looked up by React Native at runtime.
-keep class com.shieldsdk.rasp.reactnative.** { *; }
# android_core ships its own consumer rules (hook-detection reflection
# targets) inside its AAR; nothing extra is needed for it here.
