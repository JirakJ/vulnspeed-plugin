/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.VfsUtil
import com.jakubjirak.vulnspeed.core.VulnSpeedEngine
import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.report.LastScanResultHolder
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Creates (or overwrites) the project-local `.vulnspeed-baseline.json` from
 * the most recent scan cached in [LastScanResultHolder]. If no scan has run
 * yet, the user is offered the option to start one.
 *
 * All I/O executes on a background task — the EDT is never blocked.
 */
class CreateVulnBaselineAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: System.getProperty("user.dir") ?: "."
        val root: Path = Paths.get(basePath)

        val cached = LastScanResultHolder.getInstance(project).get()
        if (cached == null) {
            val choice = Messages.showYesNoDialog(
                project,
                "No cached scan results are available. Run a full project scan now to create the baseline?",
                "VulnSpeed — Create Security Baseline",
                Messages.getQuestionIcon()
            )
            if (choice != Messages.YES) return
        }

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Creating VulnSpeed security baseline…", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        val result = resolveOrScan(project, indicator)
                        indicator.text = "Hashing ${result.vulnerabilities.size} finding(s)…"
                        val baseline = VulnBaseline.fromFindings(
                            findings = result.vulnerabilities,
                            projectRoot = root,
                            toolVersion = pluginVersion(),
                        )
                        val target = VulnBaselineStore.saveDefault(baseline, root)
                        VfsUtil.markDirtyAndRefresh(true, false, false, target.toFile())
                        notify(
                            project,
                            "Security baseline written",
                            "Captured ${baseline.entries.size} finding(s) to ${target.fileName}",
                            NotificationType.INFORMATION,
                        )
                    } catch (ex: RuntimeException) {
                        notify(
                            project,
                            "VulnSpeed baseline",
                            "Failed to create baseline: ${ex.message}",
                            NotificationType.ERROR,
                        )
                    }
                }
            }
        )
    }

    private fun resolveOrScan(project: Project, indicator: ProgressIndicator): ScanResult {
        val holder = LastScanResultHolder.getInstance(project)
        val cached = holder.get()
        if (cached != null) return cached
        indicator.text = "No cached scan found — running project scan…"
        val engine = VulnSpeedEngine.getInstance(project)
        val result = engine.scanProject(project)
        holder.set(result)
        return result
    }

    private fun notify(project: Project, title: String, message: String, type: NotificationType) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("VulnSpeed Feedback")
            .createNotification(title, message, type)
            .notify(project)
    }

    private fun pluginVersion(): String {
        return com.intellij.ide.plugins.PluginManager.getPluginByClass(javaClass)?.version ?: "unknown"
    }
}
