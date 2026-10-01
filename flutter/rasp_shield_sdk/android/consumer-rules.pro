# Play Integrity's response models are deserialized reflectively by
# Google's own client library — see RaspPlayIntegrityBridge.kt.
-keep class com.google.android.play.core.integrity.** { *; }
