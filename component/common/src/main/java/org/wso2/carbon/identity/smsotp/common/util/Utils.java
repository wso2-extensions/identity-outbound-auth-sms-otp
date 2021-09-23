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
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.smsotp.common.constant.Constants;
import org.wso2.carbon.identity.smsotp.common.dto.ConfigsDTO;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPClientException;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPServerException;
import org.wso2.carbon.identity.smsotp.common.internal.SMSOTPServiceDataHolder;

import java.util.Properties;
import java.util.UUID;

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
}
