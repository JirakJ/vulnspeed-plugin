package com.jakubjirak.vulnspeed.ui.dialogs

import com.intellij.openapi.ui.DialogWrapper
import com.jakubjirak.vulnspeed.licensing.LicenseManager
import com.jakubjirak.vulnspeed.licensing.LicenseTier
import javax.swing.*
import java.awt.BorderLayout
import java.awt.Dimension

class LicenseActivationDialog : DialogWrapper(true) {
    private val licenseKeyField = JTextField()
    private val emailField = JTextField()
    private val messageLabel = JLabel()

    init {
        title = "Activate VulnSpeed License"
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(BorderLayout(10, 10))
        panel.preferredSize = Dimension(400, 200)

        // Title
        val titleLabel = JLabel("Enter your VulnSpeed license key")
        titleLabel.font = titleLabel.font.deriveFont(14f)
        panel.add(titleLabel, BorderLayout.NORTH)

        // Form
        val formPanel = JPanel()
        formPanel.layout = BoxLayout(formPanel, BoxLayout.Y_AXIS)

        // License key
        val licensePanel = JPanel(BorderLayout(5, 5))
        licensePanel.add(JLabel("License Key:"), BorderLayout.WEST)
        licensePanel.add(licenseKeyField, BorderLayout.CENTER)
        formPanel.add(licensePanel)

        // Email
        val emailPanel = JPanel(BorderLayout(5, 5))
        emailPanel.add(JLabel("Email:"), BorderLayout.WEST)
        emailPanel.add(emailField, BorderLayout.CENTER)
        formPanel.add(emailPanel)

        // Message
        formPanel.add(Box.createVerticalStrut(10))
        messageLabel.foreground = java.awt.Color.RED
        formPanel.add(messageLabel)

        // Info
        formPanel.add(Box.createVerticalStrut(10))
        val infoLabel = JLabel("""
            <html>
            <body>
            Don't have a license? Get one at: <b>https://plugins.jetbrains.com/plugin/vulnspeed</b><br><br>
            License format: VULNSPEED-XXXX-XXXX-XXXX-XXXX
            </body>
            </html>
        """.trimIndent())
        infoLabel.font = infoLabel.font.deriveFont(10f)
        formPanel.add(infoLabel)

        panel.add(formPanel, BorderLayout.CENTER)
        return panel
    }

    override fun doOKAction() {
        val licenseKey = licenseKeyField.text.trim()
        val email = emailField.text.trim()

        if (licenseKey.isEmpty()) {
            messageLabel.text = "Please enter a license key"
            return
        }

        if (email.isEmpty()) {
            messageLabel.text = "Please enter your email"
            return
        }

        val result = LicenseManager.getInstance().activateLicense(licenseKey)
        if (result.isSuccess) {
            LicenseManager.getInstance().state.licensedEmail = email
            messageLabel.text = result.getOrNull() ?: "License activated"
            messageLabel.foreground = java.awt.Color.GREEN
            super.doOKAction()
        } else {
            messageLabel.text = result.exceptionOrNull()?.message ?: "Invalid license key"
        }
    }

    override fun getHelpId(): String? = null
}

class TrialActivationDialog : DialogWrapper(true) {
    init {
        title = "Start Free Trial"
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(BorderLayout(10, 10))
        panel.preferredSize = Dimension(400, 200)

        // Title
        val titleLabel = JLabel("Unlock Premium Features")
        titleLabel.font = titleLabel.font.deriveFont(16f)
        panel.add(titleLabel, BorderLayout.NORTH)

        // Content
        val contentPanel = JPanel()
        contentPanel.layout = BoxLayout(contentPanel, BoxLayout.Y_AXIS)

        // Trial info
        val infoLabel = JLabel("""
            <html>
            <body>
            Start a 14-day free trial of VulnSpeed Professional<br><br>
            <b>Includes:</b><br>
            ✓ GPU-accelerated scanning<br>
            ✓ Advanced vulnerability patterns<br>
            ✓ Real-time code analysis<br>
            ✓ Auto-fix suggestions<br>
            ✓ OWASP Top 10 detection<br><br>
            No credit card required. Trial starts immediately.
            </body>
            </html>
        """.trimIndent())
        infoLabel.font = infoLabel.font.deriveFont(11f)
        contentPanel.add(infoLabel)

        panel.add(contentPanel, BorderLayout.CENTER)
        return panel
    }

    override fun doOKAction() {
        LicenseManager.getInstance().startTrial()
        super.doOKAction()
    }

    override fun getHelpId(): String? = null
}

class LicenseUpgradeDialog(private val feature: String) : DialogWrapper(true) {
    init {
        title = "Upgrade to Professional"
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(BorderLayout(10, 10))
        panel.preferredSize = Dimension(450, 250)

        // Title
        val titleLabel = JLabel("$feature is only available in Professional plan")
        titleLabel.font = titleLabel.font.deriveFont(14f)
        panel.add(titleLabel, BorderLayout.NORTH)

        // Content
        val contentPanel = JPanel()
        contentPanel.layout = BoxLayout(contentPanel, BoxLayout.Y_AXIS)

        // Current plan
        val manager = LicenseManager.getInstance()
        val currentTier = manager.getCurrentTier()

        val planLabel = JLabel("Current Plan: ${currentTier.displayName}")
        planLabel.font = planLabel.font.deriveFont(12f)
        contentPanel.add(planLabel)

        contentPanel.add(Box.createVerticalStrut(15))

        // Features comparison
        val featuresLabel = JLabel("Professional Plan ($29/month):")
        featuresLabel.font = featuresLabel.font.deriveFont(12f)
        contentPanel.add(featuresLabel)

        val featuresList = arrayOf(
            "GPU-accelerated scanning",
            "Advanced vulnerability patterns",
            "1000+ scans per day",
            "1M+ LOC project support",
            "Real-time code analysis",
            "Auto-fix suggestions",
            "OWASP Top 10 detection"
        )

        for (f in featuresList) {
            val item = JLabel("✓ $f")
            item.font = item.font.deriveFont(10f)
            contentPanel.add(item)
        }

        contentPanel.add(Box.createVerticalStrut(15))

        val noteLabel = JLabel("Upgrade now or start a 14-day free trial")
        noteLabel.font = noteLabel.font.deriveFont(10f)
        contentPanel.add(noteLabel)

        panel.add(contentPanel, BorderLayout.CENTER)

        // Buttons
        val buttonPanel = JPanel()
        val upgradeButton = JButton("Buy License")
        upgradeButton.addActionListener {
            // Open JetBrains marketplace plugin page
            com.intellij.ide.BrowserUtil.browse(
                "https://plugins.jetbrains.com/plugin/vulnspeed"
            )
        }
        buttonPanel.add(upgradeButton)

        val trialButton = JButton("Start Free Trial")
        trialButton.addActionListener {
            LicenseManager.getInstance().startTrial()
            doOKAction()
        }
        buttonPanel.add(trialButton)

        panel.add(buttonPanel, BorderLayout.SOUTH)

        return panel
    }

    override fun doOKAction() {
        super.doOKAction()
    }

    override fun getHelpId(): String? = null
}

class LicenseExpiredDialog : DialogWrapper(true) {
    init {
        title = "License Expired"
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(BorderLayout(10, 10))
        panel.preferredSize = Dimension(400, 200)

        val titleLabel = JLabel("Your VulnSpeed license has expired")
        titleLabel.font = titleLabel.font.deriveFont(14f)
        panel.add(titleLabel, BorderLayout.NORTH)

        val messageLabel = JLabel("""
            <html>
            <body>
            Your Professional license has expired.<br><br>
            Please renew your subscription to continue using GPU-accelerated scanning
            and advanced features.<br><br>
            You can still use the Free tier with limited scans per day.
            </body>
            </html>
        """.trimIndent())
        panel.add(messageLabel, BorderLayout.CENTER)

        val buttonPanel = JPanel()
        val renewButton = JButton("Renew License")
        renewButton.addActionListener {
            com.intellij.ide.BrowserUtil.browse(
                "https://plugins.jetbrains.com/plugin/vulnspeed"
            )
            doOKAction()
        }
        buttonPanel.add(renewButton)

        panel.add(buttonPanel, BorderLayout.SOUTH)

        return panel
    }

    override fun doOKAction() {
        super.doOKAction()
    }

    override fun getHelpId(): String? = null
}
