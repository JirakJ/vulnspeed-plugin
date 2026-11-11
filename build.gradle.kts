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
            url = "https://github.com/JirakJ/vulnspeed-plugin"
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
    baseline = file("detekt-baseline.xml")
}
