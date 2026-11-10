/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.sbom

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class ManifestDependencyCollectorTest {

    private val collector = ManifestDependencyCollector()

    @Test
    fun `returns empty list for missing directory`(@TempDir tmp: Path) {
        val ghost = tmp.resolve("does-not-exist")
        assertTrue(collector.collect(ghost).isEmpty())
    }

    @Test
    fun `parses maven pom with scoped + runtime deps, skips dependencyManagement`(@TempDir tmp: Path) {
        Files.writeString(
            tmp.resolve("pom.xml"),
            """
            <project>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.ignored</groupId>
                    <artifactId>ignored-bom</artifactId>
                    <version>1.0.0</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
              <dependencies>
                <dependency>
                  <groupId>org.junit.jupiter</groupId>
                  <artifactId>junit-jupiter-api</artifactId>
                  <version>5.10.0</version>
                  <scope>test</scope>
                </dependency>
                <dependency>
                  <groupId>com.google.code.gson</groupId>
                  <artifactId>gson</artifactId>
                  <version>2.10.1</version>
                  <scope>runtime</scope>
                </dependency>
              </dependencies>
            </project>
            """.trimIndent()
        )

        val comps = collector.collect(tmp)
        assertEquals(2, comps.size)
        assertTrue(comps.none { it.name.contains("ignored-bom") })
        assertTrue(comps.any { it.purl == "pkg:maven/com.google.code.gson/gson@2.10.1" })
        assertTrue(comps.any { it.purl == "pkg:maven/org.junit.jupiter/junit-jupiter-api@5.10.0" })
    }

    @Test
    fun `parses package json + lock, scoped names are encoded`(@TempDir tmp: Path) {
        Files.writeString(
            tmp.resolve("package.json"),
            """
            {
              "name": "demo",
              "dependencies": { "lodash": "^4.17.21", "@scope/utils": "1.0.0" },
              "devDependencies": { "jest": "^29.0.0" }
            }
            """.trimIndent()
        )
        Files.writeString(
            tmp.resolve("package-lock.json"),
            """
            {
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "demo" },
                "node_modules/lodash": { "version": "4.17.21" },
                "node_modules/@scope/utils": { "version": "1.0.0" },
                "node_modules/transitive-dep": { "version": "2.0.0" }
              }
            }
            """.trimIndent()
        )

        val comps = collector.collect(tmp)
        // expect dedup: lodash appears once, @scope/utils once, jest once, transitive-dep once
        val purls = comps.mapNotNull { it.purl }.toSet()
        assertTrue(purls.contains("pkg:npm/lodash@4.17.21"))
        assertTrue(purls.contains("pkg:npm/%40scope/utils@1.0.0"))
        assertTrue(purls.contains("pkg:npm/jest@29.0.0"))
        assertTrue(purls.contains("pkg:npm/transitive-dep@2.0.0"))
        assertEquals(purls.size, comps.size, "no duplicates expected")
    }

    @Test
    fun `parses requirements txt with comments, pins, and env markers`(@TempDir tmp: Path) {
        Files.writeString(
            tmp.resolve("requirements.txt"),
            """
            # top comment
            requests==2.31.0
            flask==3.0.0  # inline comment
            numpy>=1.25   ; python_version >= '3.10'
            -e git+https://example.com/foo.git
            # empty below

            urllib3==2.2.1
            """.trimIndent()
        )

        val comps = collector.collect(tmp)
        val names = comps.map { it.name }
        assertTrue(names.contains("requests"))
        assertTrue(names.contains("flask"))
        assertTrue(names.contains("numpy"))
        assertTrue(names.contains("urllib3"))
        val requests = comps.first { it.name == "requests" }
        assertEquals("2.31.0", requests.version)
        assertEquals("pkg:pypi/requests@2.31.0", requests.purl)
        // unpinned entry keeps null version
        val numpy = comps.first { it.name == "numpy" }
        assertNull(numpy.version)
        assertEquals("pkg:pypi/numpy", numpy.purl)
    }

    @Test
    fun `parses gradle kts literal implementation strings`(@TempDir tmp: Path) {
        Files.writeString(
            tmp.resolve("build.gradle.kts"),
            """
            dependencies {
                implementation("com.squareup.okhttp3:okhttp:4.12.0")
                api('com.google.guava:guava:33.0.0-jre')
                testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.0")
                implementation(project(":core")) // non-literal - must be ignored
            }
            """.trimIndent()
        )

        val comps = collector.collect(tmp)
        val purls = comps.mapNotNull { it.purl }
        assertTrue(purls.contains("pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"))
        assertTrue(purls.contains("pkg:maven/com.google.guava/guava@33.0.0-jre"))
        assertTrue(purls.contains("pkg:maven/org.junit.jupiter/junit-jupiter-api@5.10.0"))
        assertEquals(3, comps.size)
    }

    @Test
    fun `deduplicates by purl and is deterministically ordered`(@TempDir tmp: Path) {
        // Same coord appears in pom.xml and build.gradle.kts
        Files.writeString(
            tmp.resolve("pom.xml"),
            """
            <project><dependencies>
              <dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.10.1</version></dependency>
              <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency>
            </dependencies></project>
            """.trimIndent()
        )
        Files.writeString(
            tmp.resolve("build.gradle.kts"),
            """implementation("com.google.code.gson:gson:2.10.1")"""
        )

        val first = collector.collect(tmp)
        val second = collector.collect(tmp)
        assertEquals(first, second, "order must be deterministic")
        assertEquals(2, first.size, "duplicates must collapse")
        // sorted by (type, name lowercase)
        assertEquals("com.google.code.gson:gson", first[0].name)
        assertEquals("org.apache.commons:commons-lang3", first[1].name)
    }
}
