/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.report

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
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VfsUtil
import com.jakubjirak.vulnspeed.baseline.VulnFindingsJson
import com.jakubjirak.vulnspeed.core.VulnSpeedEngine
import com.jakubjirak.vulnspeed.model.ScanResult
import java.io.File
import java.io.IOException

/**
 * Exports the latest VulnSpeed scan findings as findings JSON — the input format of
 * the `baseline` and `enrich` commands of the VulnSpeed CLI. Runs a project scan
 * first when no scan result is cached. All file IO and scanning happens off the EDT.
 */
class ExportFindingsJsonAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: return

        val descriptor = FileSaverDescriptor(
            "Export Findings JSON",
            "Choose where to save the VulnSpeed findings JSON",
            "json"
        )
        val dialog = FileChooserFactory.getInstance().createSaveFileDialog(descriptor, project)
        val baseVf = LocalFileSystem.getInstance().findFileByIoFile(File(basePath))
        val targetFile = dialog.save(baseVf, DEFAULT_FILE_NAME)?.file ?: return

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Exporting VulnSpeed findings…", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        val result = resolveOrScan(project, indicator)
                        VulnFindingsJson.write(result.vulnerabilities, targetFile.toPath())
                        ApplicationManager.getApplication().invokeLater {
                            VfsUtil.markDirtyAndRefresh(true, false, false, targetFile)
                        }
                        notify(
                            project,
                            "Wrote ${result.vulnerabilities.size} finding(s) to ${targetFile.name}",
                            NotificationType.INFORMATION
                        )
                    } catch (ex: IOException) {
                        notify(project, "Failed to write findings JSON: ${ex.message}", NotificationType.ERROR)
                    }
                }
            }
        )
    }

    private fun resolveOrScan(project: Project, indicator: ProgressIndicator): ScanResult {
        val holder = LastScanResultHolder.getInstance(project)
        holder.get()?.let { return it }
        indicator.text = "No cached scan found — running project scan…"
        val result = VulnSpeedEngine.getInstance(project).scanProject(project)
        holder.set(result)
        return result
    }

    private fun notify(project: Project, message: String, type: NotificationType) {
        NotificationGroupManager.getInstance().getNotificationGroup("VulnSpeed Feedback")
            .createNotification("VulnSpeed findings export", message, type)
            .notify(project)
    }

    companion object {
        /** Default file name, relative to the project root. */
        const val DEFAULT_FILE_NAME = "vulnspeed-findings.json"
    }
}
