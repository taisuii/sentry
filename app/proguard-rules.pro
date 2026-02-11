# AntiFrida ProGuard Rules

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep MainActivity and detector classes
-keep class anti.rusda.MainActivity { *; }
-keep class anti.rusda.detector.** { *; }
-keep class anti.rusda.ui.adapter.** { *; }

# Keep JNI-related classes
-keep class * {
    native <methods>;
}

# Preserve line numbers for debugging
-keepattributes SourceFile,LineNumberTable

# Keep BuildConfig
-keep class **.BuildConfig { *; }

# Material Design components
-keep class com.google.android.material.** { *; }
-dontwarn com.google.android.material.**

# RecyclerView
-keep class androidx.recyclerview.widget.** { *; }

# CardView
-keep class androidx.cardview.widget.** { *; }

# CoordinatorLayout
-keep class androidx.coordinatorlayout.widget.** { *; }

# AppCompat
-keep class androidx.appcompat.widget.** { *; }