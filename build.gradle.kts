buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("com.guardsquare:proguard-gradle:7.6.1")
    }
}

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.intellij.platform)
    alias(libs.plugins.detekt)
}

group = providers.gradleProperty("pluginGroup").get()
version = providers.gradleProperty("pluginVersion").get()

kotlin {
    jvmToolchain(providers.gradleProperty("javaVersion").get().toInt())
}

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        create(
            providers.gradleProperty("platformType"),
            providers.gradleProperty("platformVersion"),
        )
        instrumentationTools()
        pluginVerifier()
        zipSigner()
    }

    testImplementation(libs.junit.api)
    testRuntimeOnly(libs.junit.engine)
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.code.gson:gson:2.10.1")
}

// Exclude IDE-provided libraries from plugin distribution
configurations {
    runtimeClasspath {
        exclude(group = "org.jetbrains.kotlin")
        exclude(group = "org.jetbrains", module = "annotations")
    }
}

intellijPlatform {
    pluginConfiguration {
        id = providers.gradleProperty("pluginGroup")
        name = providers.gradleProperty("pluginName")
        version = providers.gradleProperty("pluginVersion")

        ideaVersion {
            sinceBuild = providers.gradleProperty("pluginSinceBuild")
        }

        vendor {
            name = "Jakub Jirák"
            url = "https://github.com/jakubjirak"
        }
    }

    pluginVerification {
        ides {
            ide("IC", "2025.1.7", useInstaller = false)
            ide("IC", "2025.2.6.1", useInstaller = false)
            ide("IC", "2025.3.2", useInstaller = false)
            ide("IC", "2026.1", useInstaller = false)
        }
    }

    signing {
        // Configure via environment variables:
        // ORG_GRADLE_PROJECT_signCertificateChain
        // ORG_GRADLE_PROJECT_signPrivateKey
        // ORG_GRADLE_PROJECT_signPassword
    }

    publishing {
        token.set(System.getenv("PLUGIN_TOKEN"))
    }
}

tasks {
    test {
        useJUnitPlatform()
    }

    wrapper {
        gradleVersion = "8.12"
    }
}

detekt {
    config.setFrom(files("detekt.yml"))
    buildUponDefaultConfig = true
}

tasks.register<proguard.gradle.ProGuardTask>("obfuscate") {
    dependsOn("jar")

    val jarFile = tasks.named<Jar>("jar").flatMap { it.archiveFile }
    val obfuscatedJar = layout.buildDirectory.file("obfuscated/${project.name}-${project.version}-obfuscated.jar")

    injars(jarFile)
    outjars(obfuscatedJar)

    val platformClasspath = configurations.getByName("compileClasspath").files
    libraryjars(platformClasspath)

    val javaHome = System.getProperty("java.home")
    libraryjars(mapOf("jarfilter" to "!**.jar", "filter" to "!module-info.class"), "$javaHome/jmods/java.base.jmod")
    libraryjars(mapOf("jarfilter" to "!**.jar", "filter" to "!module-info.class"), "$javaHome/jmods/java.desktop.jmod")
    libraryjars(mapOf("jarfilter" to "!**.jar", "filter" to "!module-info.class"), "$javaHome/jmods/java.xml.jmod")

    keepattributes("SourceFile,LineNumberTable")
    keepattributes("*Annotation*")
    keepattributes("Signature")
    keepattributes("InnerClasses")
    keepattributes("Exceptions")

    optimizationpasses(3)
    allowaccessmodification()
    repackageclasses("")
    overloadaggressively()

    keep("public class * extends com.intellij.openapi.actionSystem.AnAction { *; }")
    keep("public class * implements com.intellij.openapi.components.PersistentStateComponent { *; }")
    keep("public class * implements com.intellij.openapi.options.Configurable { *; }")
    keep("public class * extends com.intellij.openapi.startup.ProjectActivity { *; }")
    keep("public class * implements com.intellij.openapi.wm.ToolWindowFactory { *; }")
    keep("public class * implements com.intellij.codeInsight.daemon.LineMarkerProvider { *; }")
    keep("public class * extends com.intellij.lang.annotation.Annotator { *; }")
    keep("public class * implements com.intellij.codeInspection.GlobalInspectionTool { *; }")

    keep("public class * { public static * getInstance(com.intellij.openapi.project.Project); }")
    keep("public class * { public static * getInstance(); }")

    keepclassmembers("class * { ** INSTANCE; }")
    keepclassmembers("class * extends com.intellij.openapi.components.PersistentStateComponent { *; }")

    keepattributes("RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations")
    keep("class kotlin.Metadata { *; }")

    dontwarn("com.intellij.**")
    dontwarn("org.jetbrains.**")
    dontwarn("kotlin.**")
    dontwarn("kotlinx.**")

    printmapping(layout.buildDirectory.file("proguard/mapping.txt"))
    printseeds(layout.buildDirectory.file("proguard/seeds.txt"))
    printusage(layout.buildDirectory.file("proguard/usage.txt"))
}

