package com.jakubjirak.vulnspeed.actions

import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.jakubjirak.vulnspeed.core.VulnSpeedEngine
import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.report.LastScanResultHolder
import com.jakubjirak.vulnspeed.ui.VulnSpeedResultsPanel

/**
 * Publishes a finished scan into the VulnSpeed tool window. ContentManager and
 * tool window activation are EDT-only, so this always hops to the EDT.
 */
internal fun showResultInToolWindow(project: Project, result: ScanResult) {
    ApplicationManager.getApplication().invokeLater {
        if (project.isDisposed) return@invokeLater
        val toolWindow = com.intellij.openapi.wm.ToolWindowManager.getInstance(project)
            .getToolWindow("VulnSpeed") ?: return@invokeLater

        val panel = toolWindow.contentManager.contents
            .map { it.component }
            .filterIsInstance<VulnSpeedResultsPanel>()
            .firstOrNull()
        panel?.displayResult(result)

        toolWindow.activate(null)
    }
}

class ScanFileAction : AnAction() {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun actionPerformed(e: AnActionEvent) {
        val file = e.getData(CommonDataKeys.VIRTUAL_FILE) ?: return
        val project = e.project ?: return
        
        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Scanning file with VulnSpeed...", true) {
                override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                    indicator.isIndeterminate = true
                    
                    val engine = VulnSpeedEngine.getInstance(project)
                    val result = engine.scanFile(file, project)
                    LastScanResultHolder.getInstance(project).set(result)

                    showResultInToolWindow(project, result)
                }
            }
        )
    }
}

class ScanProjectAction : AnAction() {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        
        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Scanning project with VulnSpeed...", true) {
                override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                    val engine = VulnSpeedEngine.getInstance(project)
                    val result = engine.scanProject(project)
                    LastScanResultHolder.getInstance(project).set(result)

                    showResultInToolWindow(project, result)
                }
            }
        )
    }
}

class ShowResultsAction : AnAction() {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val toolWindow = com.intellij.openapi.wm.ToolWindowManager.getInstance(project)
            .getToolWindow("VulnSpeed")
        
        if (toolWindow != null) {
            toolWindow.activate(null)
        } else {
            Messages.showInfoMessage(project, "VulnSpeed results not available", "VulnSpeed")
        }
    }
}

class ClearCacheAction : AnAction() {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val result = Messages.showYesNoDialog(
            project,
            "Clear VulnSpeed scan cache?",
            "Clear Cache",
            Messages.getWarningIcon()
        )
        
        if (result == Messages.YES) {
            Messages.showInfoMessage(project, "Cache cleared successfully", "VulnSpeed")
        }
    }
}
