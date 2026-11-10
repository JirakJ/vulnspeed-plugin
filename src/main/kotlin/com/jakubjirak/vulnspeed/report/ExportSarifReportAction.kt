/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.report

import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileChooser.FileChooserFactory
import com.intellij.openapi.fileChooser.FileSaverDescriptor
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.SystemInfo
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VfsUtil
import com.jakubjirak.vulnspeed.core.VulnSpeedEngine
import com.jakubjirak.vulnspeed.model.ScanResult
import java.awt.datatransfer.StringSelection
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files

/**
 * Action that exports the latest VulnSpeed scan results as a SARIF 2.1.0 report.
 *
 * If no cached scan is present, the action triggers a fresh project scan on a
 * background thread. All file IO and scanning happens off the EDT.
 */
class ExportSarifReportAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: System.getProperty("user.dir") ?: "."

        val descriptor = FileSaverDescriptor(
            "Export SARIF Report",
            "Choose a location to save the VulnSpeed SARIF 2.1.0 report",
            "sarif"
        )
        val dialog = FileChooserFactory.getInstance().createSaveFileDialog(descriptor, project)
        val baseVf = LocalFileSystem.getInstance().findFileByIoFile(File(basePath))
        val wrapper = dialog.save(baseVf, DEFAULT_FILE_NAME) ?: return
        val targetFile = wrapper.file

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Exporting VulnSpeed SARIF report…", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        val result = resolveOrScan(project, indicator)
                        indicator.text = "Serializing ${result.vulnerabilities.size} findings to SARIF…"
                        val sarif = SarifReportExporter().export(
                            findings = result.vulnerabilities,
                            toolVersion = pluginVersion(),
                            projectRoot = basePath
                        )
                        writeAtomic(targetFile, sarif)
                        refreshVfs(targetFile)
                        notifySuccess(project, targetFile, result.vulnerabilities.size)
                    } catch (ex: IOException) {
                        notifyError(project, "Failed to write SARIF report: ${ex.message}")
                    } catch (ex: RuntimeException) {
                        notifyError(project, "SARIF export failed: ${ex.message}")
                    }
                }
            }
        )
    }

    private fun resolveOrScan(project: Project, indicator: ProgressIndicator): ScanResult {
        val cached = LastScanResultHolder.getInstance(project).get()
        if (cached != null) return cached
        indicator.text = "No cached scan found — running project scan…"
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
        val tmp = File.createTempFile(".vulnspeed-sarif", ".tmp", parent ?: File("."))
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

    private fun notifySuccess(project: Project, file: File, count: Int) {
        val group = NotificationGroupManager.getInstance().getNotificationGroup("VulnSpeed Feedback")
        val n = group.createNotification(
            "SARIF report exported",
            "Wrote $count finding(s) to ${file.name}",
            NotificationType.INFORMATION
        )
        n.addAction(NotificationAction.createSimple("Reveal in " + revealLabel()) {
            com.intellij.ide.actions.RevealFileAction.openFile(file)
        })
        n.addAction(NotificationAction.createSimple("Copy path") {
            CopyPasteManager.getInstance().setContents(StringSelection(file.absolutePath))
        })
        n.notify(project)
    }

    private fun notifyError(project: Project, message: String) {
        val group = NotificationGroupManager.getInstance().getNotificationGroup("VulnSpeed Feedback")
        group.createNotification("VulnSpeed SARIF export", message, NotificationType.ERROR).notify(project)
    }

    private fun revealLabel(): String = when {
        SystemInfo.isMac -> "Finder"
        SystemInfo.isWindows -> "Explorer"
        else -> "File Manager"
    }

    private fun pluginVersion(): String {
        return com.intellij.ide.plugins.PluginManager.getPluginByClass(javaClass)?.version ?: "unknown"
    }

    companion object {
        private const val DEFAULT_FILE_NAME = "vulnspeed-report.sarif"
    }
}
