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

// Runtime classpath of the standalone CLI jar (the IDE provides these to the plugin).
val cliRuntime: Configuration by configurations.creating

dependencies {
    cliRuntime("org.jetbrains.kotlin:kotlin-stdlib:${libs.versions.kotlin.get()}")
    cliRuntime(libs.gson)

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
    testImplementation(libs.gson)
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

// Standalone CLI: platform-free classes + Kotlin stdlib + Gson, `java -jar vulnspeed-cli-<version>.jar`.
val cliJar by tasks.registering(Jar::class) {
    group = "build"
    description = "Builds the self-contained VulnSpeed CLI jar (scan | baseline | enrich)."
    archiveBaseName.set("vulnspeed-cli")
    archiveVersion.set(project.version.toString())
    destinationDirectory.set(layout.buildDirectory.dir("cli"))
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    from(sourceSets.main.get().output.classesDirs) {
        include("com/jakubjirak/vulnspeed/cli/**")
        include("com/jakubjirak/vulnspeed/model/**")
        include("com/jakubjirak/vulnspeed/core/**")
        include("com/jakubjirak/vulnspeed/baseline/**")
        include("com/jakubjirak/vulnspeed/enrichment/**")
        include("com/jakubjirak/vulnspeed/report/SarifReportExporter*")
        // IntelliJ-bound classes stay in the plugin only.
        exclude("com/jakubjirak/vulnspeed/core/VulnSpeedEngine*")
        exclude("**/*Action.class", "**/*Action$*.class", "**/*ActionKt*.class", "**/*Dialog*.class")
    }
    from(cliRuntime.map { if (it.isDirectory) it else zipTree(it) }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.kotlin_module")
        exclude("module-info.class", "META-INF/versions/*/module-info.class", "META-INF/maven/**")
        // Compile-time-only annotations pulled in by kotlin-stdlib.
        exclude("org/intellij/**", "org/jetbrains/annotations/**")
    }
    from(files("LICENSE", "NOTICE")) { into("META-INF") }
    manifest {
        attributes(
            "Main-Class" to "com.jakubjirak.vulnspeed.cli.VulnSpeedCli",
            "Implementation-Title" to "VulnSpeed CLI",
            "Implementation-Version" to project.version.toString(),
        )
    }
}

tasks {
    test {
        useJUnitPlatform()
        dependsOn(cliJar)
        systemProperty("vulnspeed.cliJar", cliJar.get().archiveFile.get().asFile.absolutePath)
    }

    assemble {
        dependsOn(cliJar)
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
