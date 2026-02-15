package com.jakubjirak.vulnspeed.actions

import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.options.ShowSettingsUtil
import com.jakubjirak.vulnspeed.licensing.LicenseManager
import com.jakubjirak.vulnspeed.settings.VulnSpeedConfigurable
import com.jakubjirak.vulnspeed.ui.dialogs.LicenseActivationDialog
import com.jakubjirak.vulnspeed.ui.dialogs.TrialActivationDialog

/**
 * Action to activate a license
 */
class ActivateLicenseAction : AnAction("Activate License", "Activate your VulnSpeed license", null) {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun actionPerformed(e: AnActionEvent) {
        val dialog = LicenseActivationDialog()
        if (dialog.showAndGet()) {
            // License activated successfully
        }
    }
}

/**
 * Action to start a free trial
 */
class StartTrialAction : AnAction("Start Free Trial", "Start 14-day free trial", null) {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun actionPerformed(e: AnActionEvent) {
        val dialog = TrialActivationDialog()
        if (dialog.showAndGet()) {
            // Trial started
        }
    }
}

/**
 * Action to open license settings
 */
class LicenseSettingsAction : AnAction("License Settings", "View and manage your license", null) {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project
        if (project != null) {
            ShowSettingsUtil.getInstance().showSettingsDialog(
                project,
                VulnSpeedConfigurable::class.java
            )
        }
    }
}

/**
 * Action to manage subscription in JetBrains Store
 */
class ManageSubscriptionAction : AnAction("Manage Subscription", "Manage your VulnSpeed subscription", null) {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun actionPerformed(e: AnActionEvent) {
        val subscriptionManager = com.jakubjirak.vulnspeed.licensing.SubscriptionManager.getInstance()
        subscriptionManager.openSubscriptionPage()
    }
}
