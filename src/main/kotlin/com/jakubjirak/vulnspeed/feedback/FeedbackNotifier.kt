/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.feedback

import com.intellij.ide.BrowserUtil
import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.components.*
import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity

/**
 * Non-intrusive feedback prompt shown once after 7 days of plugin usage.
 * Tracks first activation timestamp and shows a dismissible balloon notification.
 */
@Service(Service.Level.APP)
@State(name = "com.jakubjirak.vulnspeed.FeedbackState", storages = [Storage("com-jakubjirak-vulnspeed-feedback.xml")])
class FeedbackState : PersistentStateComponent<FeedbackState.State> {
    data class State(
        var firstActivation: Long = 0L,
        var feedbackShown: Boolean = false,
        var dismissed: Boolean = false
    )

    private var myState = State()
    override fun getState(): State = myState
    override fun loadState(state: State) { myState = state }

    companion object {
        fun getInstance(): FeedbackState = service()
    }
}

class FeedbackNotifier : ProjectActivity {
    override suspend fun execute(project: Project) {
        val state = FeedbackState.getInstance().state
        val now = System.currentTimeMillis()

        if (state.firstActivation == 0L) {
            state.firstActivation = now
            return
        }

        if (state.feedbackShown || state.dismissed) return

        val daysSinceFirst = (now - state.firstActivation) / (1000 * 60 * 60 * 24)
        if (daysSinceFirst < 7) return

        state.feedbackShown = true

        val notification = NotificationGroupManager.getInstance()
            .getNotificationGroup("VulnSpeed Feedback")
            .createNotification(
                "VulnSpeed",
                "You've been using this plugin for over a week — thank you! 🎉\nWe'd love your feedback to help us improve.",
                NotificationType.INFORMATION
            )
            .addAction(NotificationAction.createSimpleExpiring("📧 Send Feedback") {
                BrowserUtil.browse("mailto:feedback@jakubjirak.com?subject=Feedback: VulnSpeed")
            })
            .addAction(NotificationAction.createSimpleExpiring("⭐ Rate on Marketplace") {
                BrowserUtil.browse("https://plugins.jetbrains.com/plugin/29001/reviews")
            })
            .addAction(NotificationAction.createSimpleExpiring("Later") {
                state.feedbackShown = false
            })
            .addAction(NotificationAction.createSimpleExpiring("Don't show again") {
                state.dismissed = true
            })

        notification.notify(project)
    }
}
