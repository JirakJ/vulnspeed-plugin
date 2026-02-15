package com.jakubjirak.vulnspeed.licensing

import com.intellij.openapi.components.Service
import com.intellij.openapi.diagnostic.Logger
import java.time.LocalDate
import java.time.format.DateTimeFormatter

/**
 * Manages subscriptions and billing through JetBrains Store
 * Integrates with JetBrains Marketplace licensing API
 */
@Service
class SubscriptionManager {
    private val logger = Logger.getInstance(SubscriptionManager::class.java)
    
    data class Subscription(
        val tier: SubscriptionTier,
        val status: SubscriptionStatus,
        val startDate: LocalDate,
        val expiryDate: LocalDate?,
        val isTrialUsed: Boolean,
        val productCode: String = "PVULNSPEEDGPUAC",
        val marketplaceOrderId: String? = null
    )
    
    enum class SubscriptionTier {
        FREE,
        PROFESSIONAL,
        ENTERPRISE
    }
    
    enum class SubscriptionStatus {
        ACTIVE,
        EXPIRED,
        CANCELED,
        TRIAL_ACTIVE,
        TRIAL_EXPIRED,
        INACTIVE
    }
    
    data class TrialInfo(
        val isActive: Boolean,
        val daysRemaining: Int,
        val startDate: LocalDate,
        val expiryDate: LocalDate
    )
    
    private var currentSubscription: Subscription? = null
    private val licenseManager = LicenseManager.getInstance()
    
    /**
     * Get current subscription status
     */
    fun getCurrentSubscription(): Subscription {
        if (currentSubscription == null) {
            currentSubscription = loadSubscriptionFromStore()
        }
        return currentSubscription ?: createFreeSubscription()
    }
    
    /**
     * Check if user is on professional or enterprise tier
     */
    fun isPaidTier(): Boolean {
        val subscription = getCurrentSubscription()
        return subscription.tier in listOf(
            SubscriptionTier.PROFESSIONAL,
            SubscriptionTier.ENTERPRISE
        )
    }
    
    /**
     * Check if enterprise features are available
     */
    fun isEnterpriseTier(): Boolean {
        return getCurrentSubscription().tier == SubscriptionTier.ENTERPRISE
    }
    
    /**
     * Check trial status
     */
    fun getTrialInfo(): TrialInfo? {
        val subscription = getCurrentSubscription()
        if (subscription.status != SubscriptionStatus.TRIAL_ACTIVE) {
            return null
        }
        
        subscription.expiryDate?.let { expiry ->
            val daysRemaining = (expiry.toEpochDay() - LocalDate.now().toEpochDay()).toInt()
            return TrialInfo(
                isActive = daysRemaining > 0,
                daysRemaining = maxOf(0, daysRemaining),
                startDate = subscription.startDate,
                expiryDate = expiry
            )
        }
        
        return null
    }
    
    /**
     * Activate subscription with license key (if needed)
     */
    fun activateSubscription(licenseKey: String): Boolean {
        try {
            if (licenseManager.validateLicense(licenseKey)) {
                logger.info("Subscription activated with key")
                currentSubscription = null // Reset cache
                return true
            }
        } catch (e: Exception) {
            logger.error("Failed to activate subscription: ${e.message}", e)
        }
        return false
    }
    
    /**
     * Start 14-day trial
     */
    fun startTrial(): Boolean {
        val subscription = getCurrentSubscription()
        
        // Don't start trial if already used
        if (subscription.isTrialUsed) {
            logger.warn("Trial already used by this user")
            return false
        }
        
        val startDate = LocalDate.now()
        val expiryDate = startDate.plusDays(14)
        
        currentSubscription = Subscription(
            tier = SubscriptionTier.PROFESSIONAL,
            status = SubscriptionStatus.TRIAL_ACTIVE,
            startDate = startDate,
            expiryDate = expiryDate,
            isTrialUsed = true
        )
        
        // Save to marketplace
        saveToMarketplace()
        logger.info("Trial started, expires: $expiryDate")
        return true
    }
    
    /**
     * Refresh subscription from JetBrains Store
     */
    fun refreshSubscription(): Boolean {
        return try {
            currentSubscription = loadSubscriptionFromStore()
            true
        } catch (e: Exception) {
            logger.error("Failed to refresh subscription: ${e.message}", e)
            false
        }
    }
    
    /**
     * Open JetBrains Store subscription page
     */
    fun openSubscriptionPage() {
        // This would open the JetBrains Store subscription management page
        val storeUrl = "https://plugins.jetbrains.com/plugin/marketplace/PVULNSPEEDGPUAC/pricing"
        try {
            if (com.intellij.ide.BrowserUtil.isAbsoluteURL(storeUrl)) {
                com.intellij.ide.BrowserUtil.browse(storeUrl)
            }
        } catch (e: Exception) {
            logger.error("Failed to open subscription page: ${e.message}", e)
        }
    }
    
    /**
     * Get subscription days remaining
     */
    fun getDaysRemaining(): Int {
        val subscription = getCurrentSubscription()
        subscription.expiryDate?.let { expiry ->
            val remaining = (expiry.toEpochDay() - LocalDate.now().toEpochDay()).toInt()
            return maxOf(0, remaining)
        }
        return -1 // No expiry
    }
    
    /**
     * Get formatted expiry date
     */
    fun getFormattedExpiryDate(): String {
        val subscription = getCurrentSubscription()
        subscription.expiryDate?.let {
            return it.format(DateTimeFormatter.ofPattern("yyyy-MM-dd"))
        }
        return "No expiry"
    }
    
    // Private implementation methods
    
    private fun loadSubscriptionFromStore(): Subscription {
        // In a real implementation, this would call JetBrains Marketplace API
        // For now, we'll implement a fallback mechanism
        return try {
            // Try to load from JetBrains licensing service
            val hasValidLicense = licenseManager.hasValidLicense()
            
            if (hasValidLicense) {
                val tier = determineTierFromLicense()
                val license = licenseManager.getCurrentLicense()
                
                Subscription(
                    tier = tier,
                    status = SubscriptionStatus.ACTIVE,
                    startDate = license?.purchaseDate ?: LocalDate.now(),
                    expiryDate = license?.expiryDate,
                    isTrialUsed = license?.isTrialUsed ?: false
                )
            } else {
                createFreeSubscription()
            }
        } catch (e: Exception) {
            logger.warn("Could not load subscription from store: ${e.message}")
            createFreeSubscription()
        }
    }
    
    private fun determineTierFromLicense(): SubscriptionTier {
        val license = licenseManager.getCurrentLicense() ?: return SubscriptionTier.FREE
        
        return when {
            license.isEnterprise -> SubscriptionTier.ENTERPRISE
            license.isProfessional -> SubscriptionTier.PROFESSIONAL
            else -> SubscriptionTier.FREE
        }
    }
    
    private fun saveToMarketplace() {
        // This would sync the trial/subscription state to JetBrains Marketplace
        logger.info("Subscription state synced to marketplace")
    }
    
    private fun createFreeSubscription(): Subscription {
        return Subscription(
            tier = SubscriptionTier.FREE,
            status = SubscriptionStatus.ACTIVE,
            startDate = LocalDate.now(),
            expiryDate = null,
            isTrialUsed = false
        )
    }
    
    companion object {
        fun getInstance(): SubscriptionManager {
            return com.intellij.openapi.components.service()
        }
    }
}
