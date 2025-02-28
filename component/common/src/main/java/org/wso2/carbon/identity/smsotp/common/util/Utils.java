/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.smsotp.common.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.smsotp.common.constant.Constants;
import org.wso2.carbon.identity.smsotp.common.dto.ConfigsDTO;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPClientException;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPException;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPServerException;
import org.wso2.carbon.identity.smsotp.common.internal.SMSOTPServiceDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;

import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ACCOUNT_DISABLED_CLAIM_URI;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_LOCKED_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY;

/**
 * Util functions for SMS OTP service.
 */
public class Utils {

    private static final Log log = LogFactory.getLog(Utils.class);

    /**
     * Read configurations and populate ConfigDTO object.
     *
     * @throws SMSOTPServerException Throws upon an issue on while reading configs.
     */
    public static void readConfigurations() throws SMSOTPServerException {

        Properties properties;
        try {
            ModuleConfiguration configs = IdentityEventConfigBuilder.getInstance()
                    .getModuleConfigurations(Constants.SMS_OTP_IDENTITY_EVENT_MODULE_NAME);
            if (configs != null) {
                properties = configs.getModuleProperties();
            } else {
                properties = new Properties();
                log.debug("Couldn't find SMS OTP handler configurations.");
            }
            sanitizeAndPopulateConfigs(properties);
        } catch (IdentityEventException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_EVENT_CONFIG_LOADING_ERROR,
                    Constants.SMS_OTP_IDENTITY_EVENT_MODULE_NAME, e);
        }
        log.debug(String.format("SMS OTP service configurations : %s.",
                SMSOTPServiceDataHolder.getConfigs().toString()));
    }

    /**
     *
     * @param user
     * @return
     * @throws SMSOTPException
     */
    public static boolean isUserDisabled(User user) throws SMSOTPException {

        try {
            if (!isAccountDisablingEnabled(user.getTenantDomain())) {
                return false;
            }
            String accountDisabledClaimValue = getClaimValue(
                    user.getUserID(), ACCOUNT_DISABLED_CLAIM_URI, user.getTenantDomain());
            return Boolean.parseBoolean(accountDisabledClaimValue);
        } catch (FrameworkException e) {
            throw new SMSOTPException(e.getErrorCode(), e.getMessage(), e);
        }
    }

    private static boolean isAccountDisablingEnabled(String tenantDomain) throws FrameworkException {

        Property accountDisableConfigProperty = FrameworkUtils.getResidentIdpConfiguration(
                ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY, tenantDomain);

        return accountDisableConfigProperty != null && Boolean.parseBoolean(accountDisableConfigProperty.getValue());
    }

    private static String getClaimValue(String userId, String claimURI, String tenantDomain) throws
            FrameworkException {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) SMSOTPServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();

            Map<String, String> values = userStoreManager.getUserClaimValuesWithID(userId, new String[]{claimURI},
                    UserCoreConstants.DEFAULT_PROFILE);
            if (log.isDebugEnabled()) {
                log.debug(String.format("%s claim value of user %s is set to: " + values.get(claimURI),
                        claimURI, userId));
            }
            return values.get(claimURI);

        } catch (UserStoreException e) {
            throw new FrameworkException("Error occurred while retrieving claim: " + claimURI, e);
        }
    }

    /**
     * This method returns the SHA-256 hash of a given string.
     *
     * @param text plain text.
     * @return SHA-256 hash value of the given plain text.
     */
    public static String getHash(String text) {

        return DigestUtils.sha256Hex(text);
    }

    private static void sanitizeAndPopulateConfigs(Properties properties) throws SMSOTPServerException {

        ConfigsDTO configs = SMSOTPServiceDataHolder.getConfigs();

        boolean isEnabled = Boolean.parseBoolean(StringUtils.trim(
                properties.getProperty(Constants.SMS_OTP_ENABLED)));
        configs.setEnabled(isEnabled);

        // Defaults to 'false'.
        boolean triggerNotification = Boolean.parseBoolean(StringUtils.trim(
                properties.getProperty(Constants.SMS_OTP_TRIGGER_NOTIFICATION)));
        configs.setTriggerNotification(triggerNotification);

        boolean showFailureReason = Boolean.parseBoolean(StringUtils.trim(
                properties.getProperty(Constants.SMS_OTP_SHOW_FAILURE_REASON)));
        configs.setShowFailureReason(showFailureReason);

        boolean isAlphaNumericOtp = Boolean.parseBoolean(StringUtils.trim(
                properties.getProperty(Constants.SMS_OTP_ALPHANUMERIC_TOKEN)));
        configs.setAlphaNumericOTP(isAlphaNumericOtp);

        String otpLengthValue = StringUtils.trim(properties.getProperty(Constants.SMS_OTP_TOKEN_LENGTH));
        int otpLength = StringUtils.isNumeric(otpLengthValue) ?
                Integer.parseInt(otpLengthValue) : Constants.DEFAULT_OTP_LENGTH;
        configs.setOtpLength(otpLength);

        String otpValidityPeriodValue =
                StringUtils.trim(properties.getProperty(Constants.SMS_OTP_TOKEN_VALIDITY_PERIOD));
        int otpValidityPeriod = StringUtils.isNumeric(otpValidityPeriodValue) ?
                Integer.parseInt(otpValidityPeriodValue) * 1000 : Constants.DEFAULT_SMS_OTP_VALIDITY_PERIOD;
        configs.setOtpValidityPeriod(otpValidityPeriod);

        // If not defined, defaults to 'zero' to renew always.
        String otpRenewIntervalValue = StringUtils.trim(
                properties.getProperty(Constants.SMS_OTP_TOKEN_RENEWAL_INTERVAL));
        int otpRenewalInterval = StringUtils.isNumeric(otpRenewIntervalValue) ?
                Integer.parseInt(otpRenewIntervalValue) * 1000 : 0;
        configs.setOtpRenewalInterval(otpRenewalInterval);

        if (otpRenewalInterval >= otpValidityPeriod) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_INVALID_RENEWAL_INTERVAL_ERROR,
                    String.valueOf(otpRenewalInterval));
        }

        String otpResendThrottleIntervalValue = StringUtils.trim(
                properties.getProperty(Constants.SMS_OTP_RESEND_THROTTLE_INTERVAL));
        int resendThrottleInterval = StringUtils.isNumeric(otpResendThrottleIntervalValue) ?
                Integer.parseInt(otpResendThrottleIntervalValue) * 1000 : Constants.DEFAULT_RESEND_THROTTLE_INTERVAL;
        configs.setResendThrottleInterval(resendThrottleInterval);

        // Maximum allowed validation attempts defaults to 5 if its not specified as a property in deployment.toml file.
        String otpMaxValidationAttemptsAllowedValue = StringUtils.trim(
                properties.getProperty(Constants.SMS_OTP_MAX_VALIDATION_ATTEMPTS_ALLOWED));
        int maxValidationAttemptsAllowed = StringUtils.isNumeric(otpMaxValidationAttemptsAllowedValue) ?
                Integer.parseInt(otpMaxValidationAttemptsAllowedValue) :
                Constants.DEFAULT_MAX_VALIDATION_ATTEMPTS_ALLOWED;
        configs.setMaxValidationAttemptsAllowed(maxValidationAttemptsAllowed);

        boolean lockAccountOnFailedAttempts = Boolean.parseBoolean(org.apache.commons.lang.StringUtils.trim(
                properties.getProperty(Constants.SMS_OTP_LOCK_ACCOUNT_ON_FAILED_ATTEMPTS)));
        configs.setLockAccountOnFailedAttempts(lockAccountOnFailedAttempts);

        // Should we send the same OTP upon the next generation request. Defaults to 'false'.
        boolean resendSameOtp = (otpRenewalInterval > 0) && (otpRenewalInterval < otpValidityPeriod);
        configs.setResendSameOtp(resendSameOtp);

        // Defaults to 'true' with an interval of 30 seconds.
        boolean resendThrottlingEnabled = resendThrottleInterval > 0;
        configs.setResendThrottlingEnabled(resendThrottlingEnabled);
    }

    public static String createTransactionId() {

        String transactionId = UUID.randomUUID().toString();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Transaction Id hash: %s.", Utils.getHash(transactionId)));
        }
        return transactionId;
    }

    public static SMSOTPClientException handleClientException(Constants.ErrorMessage error, String data) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new SMSOTPClientException(error.getCode(), error.getMessage(), description);
    }

    public static SMSOTPClientException handleClientException(Constants.ErrorMessage error, String data,
                                                              Throwable e) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new SMSOTPClientException(error.getCode(), error.getMessage(), description, e);
    }

    public static SMSOTPServerException handleServerException(Constants.ErrorMessage error, String data,
                                                              Throwable e) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new SMSOTPServerException(error.getCode(), error.getMessage(), description, e);
    }

    public static SMSOTPServerException handleServerException(Constants.ErrorMessage error, String data) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new SMSOTPServerException(error.getCode(), error.getMessage(), description);
    }

    /**
     * Check whether a given user is locked.
     *
     * @param user The user.
     * @return True if user account is locked.
     */
    public static boolean isAccountLocked(User user) throws SMSOTPServerException {

        try {
            return SMSOTPServiceDataHolder.getInstance().getAccountLockService().isAccountLocked(user.getUsername(),
                    user.getTenantDomain(), user.getUserStoreDomain());
        } catch (AccountLockServiceException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_ERROR_VALIDATING_ACCOUNT_LOCK_STATUS,
                    user.getUserID(), e);
        }
    }

    /**
     * Get the account lock connector configurations.
     *
     * @param tenantDomain Tenant domain.
     * @return Account lock connector configurations.
     * @throws SMSOTPServerException Server exception while retrieving account lock configurations.
     */
    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws SMSOTPServerException {

        try {
            return SMSOTPServiceDataHolder.getInstance().getIdentityGovernanceService().getConfiguration
                    (new String[]{ACCOUNT_LOCKED_PROPERTY, FAILED_LOGIN_ATTEMPTS_PROPERTY, ACCOUNT_UNLOCK_TIME_PROPERTY,
                            LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY}, tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_ERROR_RETRIEVING_ACCOUNT_LOCK_CONFIGS, null,
                    e);
        }
    }
}
