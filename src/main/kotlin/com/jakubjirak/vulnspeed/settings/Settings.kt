package com.jakubjirak.vulnspeed.settings

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.project.Project
import com.intellij.openapi.options.Configurable
import javax.swing.JCheckBox
import javax.swing.JPanel
import javax.swing.JLabel
import com.intellij.ui.components.JBTextField
import java.awt.BorderLayout
import java.awt.GridLayout

@State(
    name = "VulnSpeedAppSettings",
    storages = [Storage("vulnspeed.xml")]
)
@Service
class VulnSpeedAppSettings : PersistentStateComponent<VulnSpeedAppSettings> {
    var enableRealTimeScanning = true
    var enableAutoFix = true
    var maxFileSizeKb = 1000
    var enableTelemetry = false
    
    override fun getState(): VulnSpeedAppSettings = this
    
    override fun loadState(state: VulnSpeedAppSettings) {
        this.enableRealTimeScanning = state.enableRealTimeScanning
        this.enableAutoFix = state.enableAutoFix
        this.maxFileSizeKb = state.maxFileSizeKb
        this.enableTelemetry = state.enableTelemetry
    }
    
    companion object {
        fun getInstance(): VulnSpeedAppSettings {
            return ApplicationManager.getApplication().getService(VulnSpeedAppSettings::class.java)
        }
    }
}

class VulnSpeedAppConfigurable : Configurable {
    private lateinit var realTimeScanningCheckbox: JCheckBox
    private lateinit var autoFixCheckbox: JCheckBox
    private lateinit var telemetryCheckbox: JCheckBox
    private lateinit var maxFileSizeField: JBTextField
    
    override fun getDisplayName(): String = "VulnSpeed"
    
    override fun getPreferredFocusedComponent(): javax.swing.JComponent = realTimeScanningCheckbox
    
    override fun createComponent(): JPanel {
        val panel = JPanel(GridLayout(5, 1, 0, 10))
        
        realTimeScanningCheckbox = JCheckBox("Enable real-time scanning")
        realTimeScanningCheckbox.isSelected = VulnSpeedAppSettings.getInstance().enableRealTimeScanning
        panel.add(realTimeScanningCheckbox)
        
        autoFixCheckbox = JCheckBox("Enable auto-fix suggestions")
        autoFixCheckbox.isSelected = VulnSpeedAppSettings.getInstance().enableAutoFix
        panel.add(autoFixCheckbox)
        
        telemetryCheckbox = JCheckBox("Send anonymous telemetry")
        telemetryCheckbox.isSelected = VulnSpeedAppSettings.getInstance().enableTelemetry
        panel.add(telemetryCheckbox)
        
        val maxFilePanel = JPanel(BorderLayout(10, 0))
        maxFilePanel.add(JLabel("Max file size (KB):"), BorderLayout.WEST)
        maxFileSizeField = JBTextField(VulnSpeedAppSettings.getInstance().maxFileSizeKb.toString())
        maxFilePanel.add(maxFileSizeField, BorderLayout.EAST)
        panel.add(maxFilePanel)
        
        return panel
    }
    
    override fun isModified(): Boolean {
        val settings = VulnSpeedAppSettings.getInstance()
        return realTimeScanningCheckbox.isSelected != settings.enableRealTimeScanning ||
                autoFixCheckbox.isSelected != settings.enableAutoFix ||
                telemetryCheckbox.isSelected != settings.enableTelemetry ||
                maxFileSizeField.text != settings.maxFileSizeKb.toString()
    }
    
    override fun apply() {
        val settings = VulnSpeedAppSettings.getInstance()
        settings.enableRealTimeScanning = realTimeScanningCheckbox.isSelected
        settings.enableAutoFix = autoFixCheckbox.isSelected
        settings.enableTelemetry = telemetryCheckbox.isSelected
        settings.maxFileSizeKb = maxFileSizeField.text.toIntOrNull() ?: 1000
    }
}

@State(
    name = "VulnSpeedProjectSettings",
    storages = [Storage("vulnspeed.xml")]
)
@Service(Service.Level.PROJECT)
class VulnSpeedProjectSettings : PersistentStateComponent<VulnSpeedProjectSettings> {
    var excludePatterns = listOf("**/node_modules/**", "**/build/**", "**/.git/**")
    var scanOnSave = false
    var autoFixOnSave = false
    
    override fun getState(): VulnSpeedProjectSettings = this
    
    override fun loadState(state: VulnSpeedProjectSettings) {
        this.excludePatterns = state.excludePatterns
        this.scanOnSave = state.scanOnSave
        this.autoFixOnSave = state.autoFixOnSave
    }
    
    companion object {
        fun getInstance(project: Project): VulnSpeedProjectSettings {
            return project.getService(VulnSpeedProjectSettings::class.java)
        }
    }
}

open class VulnSpeedProjectConfigurable(val project: Project) : Configurable {
    private lateinit var scanOnSaveCheckbox: JCheckBox
    private lateinit var autoFixCheckbox: JCheckBox
    
    override fun getDisplayName(): String = "VulnSpeed"
    
    override fun createComponent(): JPanel {
        val panel = JPanel(GridLayout(3, 1, 0, 10))
        
        val settings = VulnSpeedProjectSettings.getInstance(project)
        
        scanOnSaveCheckbox = JCheckBox("Scan on file save")
        scanOnSaveCheckbox.isSelected = settings.scanOnSave
        panel.add(scanOnSaveCheckbox)
        
        autoFixCheckbox = JCheckBox("Auto-fix on save")
        autoFixCheckbox.isSelected = settings.autoFixOnSave
        panel.add(autoFixCheckbox)
        
        return panel
    }
    
    override fun isModified(): Boolean = true
    
    override fun apply() {}
}

// Alias for backward compatibility
class VulnSpeedConfigurable(project: Project) : VulnSpeedProjectConfigurable(project)
