/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.sbom

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.ByteArrayInputStream
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.w3c.dom.Node

/**
 * Collects direct (and, when a lock file is present, transitive) dependencies
 * from common manifest files located at the root of a project:
 *
 *  - `pom.xml`            — Maven `<dependencies>` (groupId/artifactId/version).
 *  - `package.json`       — npm `dependencies` + `devDependencies` (direct).
 *  - `package-lock.json`  — npm lock file (adds transitive deps when present).
 *  - `requirements.txt`   — Python `name==version`, honoring comments and
 *                            PEP 508 environment markers.
 *  - `build.gradle.kts` / `build.gradle` — best-effort literal
 *    `implementation("g:a:v")` / `api("g:a:v")` strings only.
 *
 * Pure Kotlin, no IDE APIs, therefore fully unit-testable. Output is
 * deterministic: sorted by (type, name, version) and deduplicated by Package URL.
 */
class ManifestDependencyCollector {

    /**
     * Scan [projectRoot] for supported manifests and return a deterministic,
     * deduplicated list of [Component]s.
     *
     * @param projectRoot directory to scan. Non-directory / missing paths
     *                    yield an empty list.
     */
    fun collect(projectRoot: Path): List<Component> {
        if (!Files.isDirectory(projectRoot)) return emptyList()
        val components = mutableListOf<Component>()

        runCatching { parseMaven(projectRoot.resolve("pom.xml"), components) }
        runCatching { parseNpm(projectRoot, components) }
        runCatching { parsePythonRequirements(projectRoot.resolve("requirements.txt"), components) }
        runCatching { parseGradle(projectRoot.resolve("build.gradle.kts"), components) }
        runCatching { parseGradle(projectRoot.resolve("build.gradle"), components) }

        val seen = HashSet<String>()
        return components
            .filter { seen.add(it.purl ?: "${it.type.wireValue}|${it.name}|${it.version}") }
            .sortedWith(
                compareBy({ it.type.name }, { it.name.lowercase() }, { it.version ?: "" })
            )
    }

    // ---------- Maven ----------

    private fun parseMaven(pomPath: Path, out: MutableList<Component>) {
        if (!Files.isRegularFile(pomPath)) return
        val bytes = Files.readAllBytes(pomPath)
        val factory = DocumentBuilderFactory.newInstance().apply {
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            isNamespaceAware = false
            isXIncludeAware = false
            isExpandEntityReferences = false
        }
        val doc = factory.newDocumentBuilder().parse(ByteArrayInputStream(bytes))
        val deps = doc.getElementsByTagName("dependency")
        for (i in 0 until deps.length) {
            val dep = deps.item(i) as? Element ?: continue
            if (isInsideDependencyManagement(dep)) continue
            val group = dep.child("groupId") ?: continue
            val artifact = dep.child("artifactId") ?: continue
            val version = dep.child("version")
            val purl = "pkg:maven/$group/$artifact" + (version?.let { "@$it" } ?: "")
            out += Component(
                bomRef = purl,
                type = Component.Type.LIBRARY,
                name = "$group:$artifact",
                version = version,
                purl = purl
            )
        }
    }

    private fun Element.child(name: String): String? {
        val nodes = getElementsByTagName(name)
        for (i in 0 until nodes.length) {
            val n = nodes.item(i)
            if (n.parentNode === this) {
                val t = n.textContent?.trim().orEmpty()
                if (t.isNotEmpty()) return t
            }
        }
        return null
    }

    private fun isInsideDependencyManagement(node: Node): Boolean {
        var p: Node? = node.parentNode
        while (p != null) {
            if (p.nodeName == "dependencyManagement") return true
            p = p.parentNode
        }
        return false
    }

    // ---------- npm ----------

    private fun parseNpm(projectRoot: Path, out: MutableList<Component>) {
        val pkgJson = projectRoot.resolve("package.json")
        val lock = projectRoot.resolve("package-lock.json")

        if (Files.isRegularFile(pkgJson)) {
            val root = JsonParser.parseString(Files.readString(pkgJson)).asJsonObject
            addNpmMap(root, "dependencies", out)
            addNpmMap(root, "devDependencies", out)
            addNpmMap(root, "peerDependencies", out)
            addNpmMap(root, "optionalDependencies", out)
        }

        if (Files.isRegularFile(lock)) {
            val root = JsonParser.parseString(Files.readString(lock)).asJsonObject
            if (root.has("packages")) {
                val pkgs = root.getAsJsonObject("packages")
                for (key in pkgs.keySet()) {
                    if (key.isEmpty()) continue // root project itself
                    val name = key.substringAfterLast("node_modules/")
                    val entry = pkgs.getAsJsonObject(key)
                    val version = entry.takeIf { it.has("version") }?.get("version")?.asString
                    if (name.isNotEmpty()) {
                        out += npmComponent(name, version)
                    }
                }
            } else if (root.has("dependencies")) {
                addNpmMap(root, "dependencies", out)
            }
        }
    }

    private fun addNpmMap(root: JsonObject, key: String, out: MutableList<Component>) {
        if (!root.has(key) || !root.get(key).isJsonObject) return
        val map = root.getAsJsonObject(key)
        for (name in map.keySet()) {
            val raw = map.get(name)
            val version = when {
                raw.isJsonPrimitive -> raw.asString
                raw.isJsonObject && raw.asJsonObject.has("version") -> raw.asJsonObject.get("version").asString
                else -> null
            }
            out += npmComponent(name, version?.trimStart('^', '~', '=', ' '))
        }
    }

    private fun npmComponent(name: String, version: String?): Component {
        val purl = buildNpmPurl(name, version)
        return Component(
            bomRef = purl,
            type = Component.Type.LIBRARY,
            name = name,
            version = version,
            purl = purl
        )
    }

    private fun buildNpmPurl(name: String, version: String?): String {
        val encoded = if (name.startsWith("@")) {
            val slash = name.indexOf('/')
            if (slash > 0) {
                val scope = URLEncoder.encode(name.substring(0, slash), StandardCharsets.UTF_8)
                val pkg = name.substring(slash + 1)
                "$scope/$pkg"
            } else name
        } else name
        return "pkg:npm/$encoded" + (version?.let { "@$it" } ?: "")
    }

    // ---------- Python ----------

    private fun parsePythonRequirements(req: Path, out: MutableList<Component>) {
        if (!Files.isRegularFile(req)) return
        Files.readAllLines(req, StandardCharsets.UTF_8).forEach { raw ->
            var line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("-")) return@forEach
            val hash = line.indexOf('#')
            if (hash >= 0) line = line.substring(0, hash).trim()
            val semi = line.indexOf(';')
            if (semi >= 0) line = line.substring(0, semi).trim()
            if (line.isEmpty()) return@forEach

            val eq = line.indexOf("==")
            val (name, version) = if (eq > 0) {
                line.substring(0, eq).trim() to line.substring(eq + 2).trim()
            } else {
                val cut = line.indexOfAny(charArrayOf('>', '<', '~', '!', '=', ' ', '['))
                val n = if (cut > 0) line.substring(0, cut).trim() else line
                n to null
            }
            if (name.isEmpty()) return@forEach
            val purl = "pkg:pypi/${name.lowercase()}" + (version?.let { "@$it" } ?: "")
            out += Component(
                bomRef = purl,
                type = Component.Type.LIBRARY,
                name = name,
                version = version,
                purl = purl
            )
        }
    }

    // ---------- Gradle (best-effort literal string deps) ----------

    private fun parseGradle(buildScript: Path, out: MutableList<Component>) {
        if (!Files.isRegularFile(buildScript)) return
        val text = Files.readString(buildScript)
        GRADLE_DEP_REGEX.findAll(text).forEach { m ->
            val coord = m.groupValues[2]
            val parts = coord.split(':')
            if (parts.size >= 2) {
                val group = parts[0]
                val artifact = parts[1]
                val version = parts.getOrNull(2)
                val purl = "pkg:maven/$group/$artifact" + (version?.let { "@$it" } ?: "")
                out += Component(
                    bomRef = purl,
                    type = Component.Type.LIBRARY,
                    name = "$group:$artifact",
                    version = version,
                    purl = purl
                )
            }
        }
    }

    private companion object {
        private val GRADLE_DEP_REGEX = Regex(
            """\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor)\s*\(\s*["']([^"']+)["']\s*\)"""
        )
    }
}
