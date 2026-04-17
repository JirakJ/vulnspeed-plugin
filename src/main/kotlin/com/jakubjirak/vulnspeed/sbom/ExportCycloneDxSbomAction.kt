/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.sbom

import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileChooser.FileChooserFactory
import com.intellij.openapi.fileChooser.FileSaverDescriptor
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.util.SystemInfo
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VfsUtil
import com.jakubjirak.vulnspeed.core.VulnSpeedEngine
import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.report.LastScanResultHolder
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/**
 * Action that exports a CycloneDX 1.5 JSON SBOM (Software Bill of Materials)
 * for the current project. Components are discovered by
 * [ManifestDependencyCollector] and cross-referenced with the latest
 * [ScanResult] cached in [LastScanResultHolder].
 *
 * All file I/O and scanning runs on a background progress task — the EDT is
 * never blocked.
 */
class ExportCycloneDxSbomAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: System.getProperty("user.dir") ?: "."

        val cached = LastScanResultHolder.getInstance(project).get()
        val runScan = if (cached == null) {
            Messages.showYesNoDialog(
                project,
                "No cached VulnSpeed scan is available. Run a project scan now to include vulnerability data in the SBOM?",
                "Export CycloneDX SBOM",
                "Run Scan",
                "Skip (components only)",
                Messages.getQuestionIcon()
            ) == Messages.YES
        } else false

        val descriptor = FileSaverDescriptor(
            "Export CycloneDX SBOM",
            "Choose a location to save the CycloneDX 1.5 SBOM JSON",
            "json"
        )
        val dialog = FileChooserFactory.getInstance().createSaveFileDialog(descriptor, project)
        val baseVf = LocalFileSystem.getInstance().findFileByIoFile(File(basePath))
        val wrapper = dialog.save(baseVf, DEFAULT_FILE_NAME) ?: return
        val targetFile = wrapper.file

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Exporting CycloneDX SBOM…", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        indicator.text = "Collecting dependencies…"
                        val components = ManifestDependencyCollector().collect(Path.of(basePath))

                        indicator.text = "Resolving vulnerabilities…"
                        val scan = resolveScan(project, indicator, runScan, cached)

                        indicator.text = "Serializing CycloneDX 1.5 JSON…"
                        val appName = project.name
                        val toolVersion = pluginVersion()
                        val app = AppMetadata(
                            name = appName,
                            version = null,
                            bomRef = "app:$appName",
                            toolVersion = toolVersion
                        )
                        val json = CycloneDxSbomExporter().export(
                            components = components,
                            vulnerabilities = scan?.vulnerabilities.orEmpty(),
                            appMetadata = app
                        )
                        writeAtomic(targetFile, json)
                        refreshVfs(targetFile)
                        notifySuccess(project, targetFile, components.size, scan?.vulnerabilities?.size ?: 0)
                    } catch (ex: IOException) {
                        notifyError(project, "Failed to write SBOM: ${ex.message}")
                    } catch (ex: RuntimeException) {
                        notifyError(project, "CycloneDX SBOM export failed: ${ex.message}")
                    }
                }
            }
        )
    }

    private fun resolveScan(
        project: Project,
        indicator: ProgressIndicator,
        runScan: Boolean,
        cached: ScanResult?
    ): ScanResult? {
        if (cached != null) return cached
        if (!runScan) return null
        indicator.text = "Running VulnSpeed project scan…"
        val engine = VulnSpeedEngine.getInstance(project)
        val result = engine.scanProject(project)
        LastScanResultHolder.getInstance(project).set(result)
        return result
    }

    private fun writeAtomic(target: File, content: String) {
        val parent = target.parentFile
        if (parent != null && !parent.exists()) {
            if (!parent.mkdirs() && !parent.exists()) {
                throw IOException("Cannot create directory: ${parent.absolutePath}")
            }
        }
        val tmp = File.createTempFile(".vulnspeed-sbom", ".tmp", parent ?: File("."))
        try {
            Files.write(tmp.toPath(), content.toByteArray(StandardCharsets.UTF_8))
            if (target.exists() && !target.delete()) {
                throw IOException("Cannot overwrite existing file: ${target.absolutePath}")
            }
            if (!tmp.renameTo(target)) {
                Files.copy(tmp.toPath(), target.toPath())
                tmp.delete()
            }
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    private fun refreshVfs(file: File) {
        ApplicationManager.getApplication().invokeLater {
            VfsUtil.markDirtyAndRefresh(true, false, false, file)
        }
    }

    private fun notifySuccess(project: Project, file: File, componentCount: Int, vulnCount: Int) {
        val group = NotificationGroupManager.getInstance().getNotificationGroup("VulnSpeed Feedback")
        val n = group.createNotification(
            "CycloneDX SBOM exported",
            "Wrote $componentCount component(s) and $vulnCount vulnerability entry(ies) to ${file.name}",
            NotificationType.INFORMATION
        )
        n.addAction(NotificationAction.createSimple("Reveal in " + revealLabel()) {
            com.intellij.ide.actions.RevealFileAction.openFile(file)
        })
        n.notify(project)
    }

    private fun notifyError(project: Project, message: String) {
        val group = NotificationGroupManager.getInstance().getNotificationGroup("VulnSpeed Feedback")
        group.createNotification("VulnSpeed SBOM export", message, NotificationType.ERROR).notify(project)
    }

    private fun revealLabel(): String = when {
        SystemInfo.isMac -> "Finder"
        SystemInfo.isWindows -> "Explorer"
        else -> "File Manager"
    }

    private fun pluginVersion(): String {
        val id = com.intellij.openapi.extensions.PluginId.findId("com.jakubjirak.vulnspeed")
        val descriptor = id?.let { com.intellij.ide.plugins.PluginManagerCore.getPlugin(it) }
        return descriptor?.version ?: "unknown"
    }

    companion object {
        private const val DEFAULT_FILE_NAME = "vulnspeed-sbom.cdx.json"
    }
}
