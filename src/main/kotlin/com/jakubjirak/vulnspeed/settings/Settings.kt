package com.jakubjirak.vulnspeed.settings

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.options.BoundConfigurable
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogPanel
import com.intellij.ui.dsl.builder.bindIntText
import com.intellij.ui.dsl.builder.bindSelected
import com.intellij.ui.dsl.builder.columns
import com.intellij.ui.dsl.builder.panel
import com.jakubjirak.vulnspeed.core.ScanPolicy

@State(
    name = "VulnSpeedAppSettings",
    storages = [Storage("vulnspeed.xml")]
)
@Service
class VulnSpeedAppSettings : PersistentStateComponent<VulnSpeedAppSettings> {
    var enableRealTimeScanning = true
    var maxFileSizeKb = ScanPolicy.DEFAULT_MAX_FILE_SIZE_KB

    override fun getState(): VulnSpeedAppSettings = this

    override fun loadState(state: VulnSpeedAppSettings) {
        this.enableRealTimeScanning = state.enableRealTimeScanning
        this.maxFileSizeKb = state.maxFileSizeKb
    }

    companion object {
        fun getInstance(): VulnSpeedAppSettings {
            return ApplicationManager.getApplication().getService(VulnSpeedAppSettings::class.java)
        }
    }
}

/**
 * Application-level VulnSpeed settings, built with the IntelliJ Kotlin UI DSL so
 * the layout matches native settings pages (aligned labels, section groups,
 * comments, and a properly sized numeric field).
 */
class VulnSpeedAppConfigurable : BoundConfigurable("VulnSpeed") {

    override fun createPanel(): DialogPanel {
        val settings = VulnSpeedAppSettings.getInstance()
        return panel {
            group("Real-Time Analysis") {
                row {
                    checkBox("Enable real-time scanning")
                        .bindSelected(settings::enableRealTimeScanning)
                        .comment("Highlight vulnerabilities in the editor as you type")
                }
            }
            group("Performance") {
                row("Max file size:") {
                    intTextField(range = 1..1_048_576)
                        .bindIntText(settings::maxFileSizeKb)
                        .columns(8)
                        .gap(com.intellij.ui.dsl.builder.RightGap.SMALL)
                    @Suppress("DialogTitleCapitalization")
                    label("KB")
                }.rowComment("Files larger than this are skipped by editor highlighting, file, project and on-save scans")
            }
        }
    }
}

@State(
    name = "VulnSpeedProjectSettings",
    storages = [Storage("vulnspeed.xml")]
)
@Service(Service.Level.PROJECT)
class VulnSpeedProjectSettings : PersistentStateComponent<VulnSpeedProjectSettings> {
    var scanOnSave = false

    override fun getState(): VulnSpeedProjectSettings = this

    override fun loadState(state: VulnSpeedProjectSettings) {
        this.scanOnSave = state.scanOnSave
    }

    companion object {
        fun getInstance(project: Project): VulnSpeedProjectSettings {
            return project.getService(VulnSpeedProjectSettings::class.java)
        }
    }
}

/**
 * Project-level VulnSpeed settings. Uses the bound UI DSL so isModified/apply/
 * reset are handled by the platform — the previous hand-rolled implementation
 * always reported modified and never persisted changes.
 */
open class VulnSpeedProjectConfigurable(val project: Project) : BoundConfigurable("VulnSpeed") {

    override fun createPanel(): DialogPanel {
        val settings = VulnSpeedProjectSettings.getInstance(project)
        return panel {
            group("On Save") {
                row {
                    checkBox("Scan changed file on save")
                        .bindSelected(settings::scanOnSave)
                        .comment("Run a VulnSpeed scan automatically when a file is saved; results appear in the VulnSpeed tool window")
                }
            }
        }
    }
}

// Alias for backward compatibility
class VulnSpeedConfigurable(project: Project) : VulnSpeedProjectConfigurable(project)
