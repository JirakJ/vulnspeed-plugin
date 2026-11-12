package com.jakubjirak.vulnspeed.core

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Computable
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VirtualFile
import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.settings.VulnSpeedAppSettings
import java.nio.file.Paths
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * IDE-side scanning service. The rules themselves live in the platform-free
 * [RuleScanner], shared with the headless CLI; this service adds the IntelliJ
 * bits: reading the (possibly unsaved) document text, the "Max file size"
 * setting and the project file walk.
 */
@Service
class VulnSpeedEngine : AutoCloseable {
    private val scanResults = ConcurrentHashMap<String, ScanResult>()
    internal val scanner = RuleScanner { LOG.warn(it) }

    fun scanFile(file: VirtualFile, project: Project): ScanResult {
        val startTime = System.currentTimeMillis()
        val maxFileSizeKb = configuredMaxFileSizeKb()
        // Cheap pre-check on the on-disk size before loading the document text.
        if (ScanPolicy.isTooLarge(file.length, maxFileSizeKb)) {
            return emptyScanResult(startTime)
        }
        val content = ApplicationManager.getApplication().runReadAction(Computable {
            FileDocumentManager.getInstance().getDocument(file)?.text
        }) ?: return emptyScanResult(startTime)

        return scanContent(content, file.path, RuleScanner.languageFor(file.name), maxFileSizeKb)
    }

    /**
     * Scans [content] with every enabled rule. Content larger than [maxFileSizeKb]
     * (the "Max file size" setting) is skipped and reported as 0 files scanned.
     */
    internal fun scanContent(content: String, filePath: String, language: String, maxFileSizeKb: Int): ScanResult {
        val result = scanner.scanContent(content, filePath, language, maxFileSizeKb)
        if (result.stats.filesScanned > 0) scanResults[result.scanId] = result
        return result
    }

    private fun configuredMaxFileSizeKb(): Int =
        runCatching { VulnSpeedAppSettings.getInstance().maxFileSizeKb }
            .getOrDefault(ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB)

    fun scanProject(project: Project): ScanResult {
        val startTime = System.currentTimeMillis()
        val allVulnerabilities = mutableListOf<Vulnerability>()
        var totalLoc = 0L
        var filesScanned = 0

        val files = collectProjectFiles(project).take(ScanPolicy.MAX_FILES_PER_SCAN)

        files.parallelStream().forEach { file ->
            try {
                val result = scanFile(file, project)
                synchronized(allVulnerabilities) {
                    allVulnerabilities.addAll(result.vulnerabilities)
                    totalLoc += result.stats.linesOfCode
                    filesScanned += result.stats.filesScanned
                }
            } catch (e: Exception) {
                LOG.warn("VulnSpeed failed to scan ${file.path}: ${e.message}")
            }
        }

        allVulnerabilities.sortWith(compareBy({ it.severity.ordinal }, { it.line }))

        val endTime = System.currentTimeMillis()
        val result = ScanResult(
            scanId = UUID.randomUUID().toString(),
            timestamp = endTime,
            durationMs = endTime - startTime,
            vulnerabilities = allVulnerabilities,
            stats = statsFor(allVulnerabilities, filesScanned, totalLoc),
        )

        scanResults[result.scanId] = result
        return result
    }

    fun getScanResult(scanId: String): ScanResult? = scanResults[scanId]

    private fun collectProjectFiles(project: Project): List<VirtualFile> {
        val basePath = project.basePath ?: return emptyList()
        val fs = LocalFileSystem.getInstance()
        return ProjectFileWalker.collect(Paths.get(basePath)).mapNotNull { fs.findFileByNioFile(it) }
    }

    override fun close() {
        scanResults.clear()
    }

    companion object {
        private val LOG = com.intellij.openapi.diagnostic.Logger.getInstance(VulnSpeedEngine::class.java)

        fun getInstance(project: Project): VulnSpeedEngine {
            return ApplicationManager.getApplication().getService(VulnSpeedEngine::class.java)
        }
    }
}
