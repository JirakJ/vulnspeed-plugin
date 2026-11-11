/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.editor

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.editor.Document
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.fileEditor.FileDocumentManagerListener
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.ProjectLocator
import com.jakubjirak.vulnspeed.actions.showResultInToolWindow
import com.jakubjirak.vulnspeed.core.ScanPolicy
import com.jakubjirak.vulnspeed.core.VulnSpeedEngine
import com.jakubjirak.vulnspeed.report.LastScanResultHolder
import com.jakubjirak.vulnspeed.settings.VulnSpeedProjectSettings

/**
 * Runs the regular single-file scan when a document is saved and the project's
 * "Scan changed file on save" setting is enabled. Results go to the VulnSpeed tool
 * window (without stealing focus) and become the input for report exports.
 */
class ScanOnSaveListener : FileDocumentManagerListener {

    override fun beforeDocumentSaving(document: Document) {
        val file = FileDocumentManager.getInstance().getFile(document) ?: return
        if (!ScanPolicy.isSupportedFile(file.name)) return
        val project = ProjectLocator.getInstance().guessProjectForFile(file) ?: return
        if (project.isDisposed) return
        val scanOnSave = VulnSpeedProjectSettings.getInstance(project).scanOnSave
        if (!ScanPolicy.shouldScanOnSave(scanOnSave, file.name)) return

        // Saving happens inside a write action; schedule the scan for afterwards.
        ApplicationManager.getApplication().invokeLater {
            if (project.isDisposed || !file.isValid) return@invokeLater
            ProgressManager.getInstance().run(
                object : Task.Backgroundable(project, "VulnSpeed: scanning saved file", true) {
                    override fun run(indicator: ProgressIndicator) {
                        val result = VulnSpeedEngine.getInstance(project).scanFile(file, project)
                        LastScanResultHolder.getInstance(project).set(result)
                        showResultInToolWindow(project, result, activate = false)
                    }
                }
            )
        }
    }
}
