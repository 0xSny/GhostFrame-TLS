import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.kestrel.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.kestrel.android"
        minSdk = 24
        targetSdk = 35
        versionCode = 427
        versionName = "4.2.7"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    val keystorePath = System.getenv("KESTREL_KEYSTORE_PATH")?.takeIf { it.isNotBlank() }
    val keystorePass = System.getenv("KESTREL_KEYSTORE_PASS")?.takeIf { it.isNotBlank() }
    val keyAliasEnv = System.getenv("KESTREL_KEY_ALIAS")?.takeIf { it.isNotBlank() }
    val keyPassEnv = System.getenv("KESTREL_KEY_PASS")?.takeIf { it.isNotBlank() }
    val hasReleaseSigning = keystorePath != null && File(keystorePath).isFile &&
        keystorePass != null && keyAliasEnv != null && keyPassEnv != null

    signingConfigs {
        create("release") {
            if (hasReleaseSigning) {
                storeFile = File(keystorePath!!)
                storePassword = keystorePass
                keyAlias = keyAliasEnv
                keyPassword = keyPassEnv
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        create("ciPreview") {
            initWith(getByName("debug"))
            applicationIdSuffix = ".ci"
            versionNameSuffix = "-ci"
            matchingFallbacks += listOf("debug")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    gradle.taskGraph.whenReady {
        val buildingRelease = allTasks.any { it.name.contains("Release", ignoreCase = true) }
        if (buildingRelease && !hasReleaseSigning) {
            throw GradleException(
                "Missing official Android release signing credentials (KESTREL_KEYSTORE_PATH, KESTREL_KEYSTORE_PASS, KESTREL_KEY_ALIAS, KESTREL_KEY_PASS). " +
                    "Refusing to fall back to debug/ephemeral keystore for production release."
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar", "*.jar"))))

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")

    val composeBom = platform("androidx.compose:compose-bom:2024.11.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.3")
}
