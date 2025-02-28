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

package org.wso2.carbon.identity.smsotp.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.internal.IdentityRecoveryServiceDataHolder;
import org.wso2.carbon.identity.smsotp.common.constant.Constants;
import org.wso2.carbon.identity.smsotp.common.dto.FailureReasonDTO;
import org.wso2.carbon.identity.smsotp.common.dto.GenerationResponseDTO;
import org.wso2.carbon.identity.smsotp.common.dto.SessionDTO;
import org.wso2.carbon.identity.smsotp.common.dto.ValidationResponseDTO;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPException;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPServerException;
import org.wso2.carbon.identity.smsotp.common.internal.SMSOTPServiceDataHolder;
import org.wso2.carbon.identity.smsotp.common.util.OneTimePasswordUtils;
import org.wso2.carbon.identity.smsotp.common.util.Utils;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.FailureReason;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.constants.UserCoreErrorConstants;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_LOCKED_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY;

/**
 * This class implements the SMSOTPService interface.
 */
public class SMSOTPServiceImpl implements SMSOTPService {

    private static final Log log = LogFactory.getLog(SMSOTPService.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public GenerationResponseDTO generateSMSOTP(String userId) throws SMSOTPException {

        if (StringUtils.isBlank(userId)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_EMPTY_USER_ID, null);
        }

        // Retrieve mobile number only if notifications the are managed internally.
        boolean sendNotification = SMSOTPServiceDataHolder.getConfigs().isTriggerNotification();
        String[] requestedClaims =
                sendNotification ? new String[]{NotificationChannels.SMS_CHANNEL.getClaimUri()} : null;

        // Retrieve user by ID.
        AbstractUserStoreManager userStoreManager;
        User user;
        try {
            userStoreManager = (AbstractUserStoreManager) SMSOTPServiceDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            user = userStoreManager.getUserWithID(userId, requestedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            // Handle user not found.
            String errorCode = ((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode();
            if (UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode().equals(errorCode)) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
            }
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    String.format("Error while retrieving user for the Id : %s.", userId), e);
        }

        boolean showFailureReason = SMSOTPServiceDataHolder.getConfigs().isShowFailureReason();
        // Check if the user is locked.
        if (Utils.isAccountLocked(user)) {
            if (!showFailureReason) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_FORBIDDEN, user.getUserID());
            }
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_FORBIDDEN, user.getUserID());
        }

        // Check if the user is disabled.
        if (Utils.isUserDisabled(user)) {
            if (!showFailureReason) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_FORBIDDEN, user.getUserID());
            }
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_ACCOUNT_DISABLED, user.getUserID());
        }

        // If throttling is enabled, check if the resend request has sent too early.
        boolean resendThrottlingEnabled = SMSOTPServiceDataHolder.getConfigs().isResendThrottlingEnabled();
        if (resendThrottlingEnabled) {
            shouldThrottle(userId);
        }

        String mobileNumber = sendNotification ? getMobileNumber(user) : null;
        if (sendNotification && StringUtils.isBlank(mobileNumber)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_BLANK_MOBILE_NUMBER, user.getUserID());
        }

        SessionDTO sessionDTO = issueOTP(user);

        GenerationResponseDTO responseDTO = new GenerationResponseDTO();
        // If WSO2IS is handling the notifications, don't send the OTP in the response.
        if (!sendNotification) {
            responseDTO.setSmsOTP(sessionDTO.getOtp());
        }
        responseDTO.setTransactionId(sessionDTO.getTransactionId());
        return responseDTO;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ValidationResponseDTO validateSMSOTP(String transactionId, String userId, String smsOTP)
            throws SMSOTPException {

        // Sanitize inputs.
        if (StringUtils.isBlank(transactionId) || StringUtils.isBlank(userId) || StringUtils.isBlank(smsOTP)) {
            String missingParam = StringUtils.isBlank(transactionId) ? "transactionId"
                    : StringUtils.isBlank(userId) ? "userId"
                    : "smsOTP";
            throw Utils.handleClientException(
                    Constants.ErrorMessage.CLIENT_MANDATORY_VALIDATION_PARAMETERS_EMPTY, missingParam);
        }

        boolean showFailureReason = SMSOTPServiceDataHolder.getConfigs().isShowFailureReason();

        // Retrieve session from the database.
        String sessionId = Utils.getHash(userId);
        String jsonString = (String) SessionDataStore.getInstance()
                .getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        if (StringUtils.isBlank(jsonString)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No OTP session found for the user : %s.", userId));
            }
            FailureReasonDTO error = showFailureReason
                    ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_NO_OTP_FOR_USER, userId)
                    : null;
            return new ValidationResponseDTO(userId, false, error);
        }

        User user = getUserById(userId);

        // Check if user account is locked.
        if (Utils.isAccountLocked(user)) {
            return createAccountLockedResponse(userId, showFailureReason);
        }

        // Check if user account is disabled.
        if (Utils.isUserDisabled(user)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User account is disabled for the user : %s.", userId));
            }
            FailureReasonDTO error = showFailureReason
                    ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_ACCOUNT_DISABLED, userId)
                    : null;
            return new ValidationResponseDTO(userId, false, error);
        }

        SessionDTO sessionDTO;
        int validateAttempt;
        try {
            sessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
            validateAttempt = sessionDTO.getValidationAttempts();
            FailureReasonDTO error;
            if (validateAttempt >= SMSOTPServiceDataHolder.getConfigs().getMaxValidationAttemptsAllowed()) {
                SessionDataStore.getInstance().clearSessionData(sessionId, Constants.SESSION_TYPE_OTP);
                error = showFailureReason
                        ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_BLOCKED, userId)
                        : null;
                return new ValidationResponseDTO(userId, false, error);
            } else {
                validateAttempt++;
                sessionDTO.setValidationAttempts(validateAttempt);
                persistOTPSession(sessionDTO, sessionId);
            }
        } catch (IOException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
        }

        ValidationResponseDTO responseDTO = isValid(sessionDTO, smsOTP, userId, transactionId, validateAttempt, showFailureReason);
        if (!responseDTO.isValid()) {
            return responseDTO;
        }
        // Valid OTP. Clear OTP session data.
        SessionDataStore.getInstance().clearSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        resetOtpFailedAttempts(userId);
        return new ValidationResponseDTO(userId, true);
    }

    private ValidationResponseDTO isValid(SessionDTO sessionDTO, String smsOTP, String userId,
                                          String transactionId, int validateAttempt, boolean showFailureReason)
            throws SMSOTPException {

        FailureReasonDTO error;
        // Check if the provided OTP is correct.
        if (!StringUtils.equals(smsOTP, sessionDTO.getOtp())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid OTP provided for the user : %s.", userId));
            }
            ValidationResponseDTO responseDTO = handleAccountLock(userId, showFailureReason);
            if (responseDTO != null) {
                return responseDTO;
            }
            int remainingFailedAttempts =
                    SMSOTPServiceDataHolder.getConfigs().getMaxValidationAttemptsAllowed() - validateAttempt;
            error = showFailureReason
                    ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED, userId,
                    remainingFailedAttempts) : null;
            return new ValidationResponseDTO(userId, false, error);
        }
        // Check for expired OTPs.
        if (System.currentTimeMillis() > sessionDTO.getExpiryTime()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Expired OTP provided for the user : %s.", userId));
            }
            error = showFailureReason ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_EXPIRED_OTP, userId) : null;
            return new ValidationResponseDTO(userId, false, error);
        }
        // Check if the provided transaction Id is correct.
        if (!StringUtils.equals(transactionId, sessionDTO.getTransactionId())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Provided transaction Id doesn't match. User : %s.", userId));
            }
            error = showFailureReason ?
                    new FailureReasonDTO(Constants.ErrorMessage.CLIENT_INVALID_TRANSACTION_ID, transactionId) : null;
            return new ValidationResponseDTO(userId, false, error);
        }
        return new ValidationResponseDTO(userId, true);
    }

    private SessionDTO issueOTP(User user) throws SMSOTPException {

        boolean triggerNotification = SMSOTPServiceDataHolder.getConfigs().isTriggerNotification();
        boolean resendSameOtp = SMSOTPServiceDataHolder.getConfigs().isResendSameOtp();

        // If 'Resend same OTP' is enabled, check if such OTP exists.
        SessionDTO sessionDTO = null;
        if (resendSameOtp) {
            sessionDTO = getPreviousValidOTPSession(user);
            // This is done in order to support 'resend throttling'.
            if (sessionDTO != null) {
                String sessionId = Utils.getHash(user.getUserID());
                // Remove previous OTP session.
                SessionDataStore.getInstance().clearSessionData(sessionId, Constants.SESSION_TYPE_OTP);
                // Re-persisting after changing the 'generated time' of the OTP session.
                sessionDTO.setGeneratedTime(System.currentTimeMillis());
                persistOTPSession(sessionDTO, sessionId);
            }
        }

        // If no such valid OTPs exist, generate a new OTP and proceed.
        if (sessionDTO == null) {
            sessionDTO = generateNewOTP(user);
        }

        // Sending SMS notifications.
        if (triggerNotification) {
            triggerNotification(user, sessionDTO.getOtp());
        }
        return sessionDTO;
    }

    private SessionDTO generateNewOTP(User user) throws SMSOTPServerException {

        boolean isAlphaNumericOtpEnabled = SMSOTPServiceDataHolder.getConfigs().isAlphaNumericOTP();
        int otpLength = SMSOTPServiceDataHolder.getConfigs().getOtpLength();
        int otpValidityPeriod = SMSOTPServiceDataHolder.getConfigs().getOtpValidityPeriod();

        // Generate OTP.
        String transactionId = Utils.createTransactionId();
        String otp = OneTimePasswordUtils.generateOTP(
                transactionId,
                String.valueOf(Constants.NUMBER_BASE),
                otpLength,
                isAlphaNumericOtpEnabled);

        // Save the otp in the 'IDN_AUTH_SESSION_STORE' table.
        SessionDTO sessionDTO = new SessionDTO();
        sessionDTO.setOtp(otp);
        sessionDTO.setGeneratedTime(System.currentTimeMillis());
        sessionDTO.setExpiryTime(sessionDTO.getGeneratedTime() + otpValidityPeriod);
        sessionDTO.setTransactionId(transactionId);
        sessionDTO.setFullQualifiedUserName(user.getFullQualifiedUsername());
        sessionDTO.setUserId(user.getUserID());
        sessionDTO.setValidationAttempts(0);

        String sessionId = Utils.getHash(user.getUserID());
        persistOTPSession(sessionDTO, sessionId);
        return sessionDTO;
    }

    private void persistOTPSession(SessionDTO sessionDTO, String sessionId) throws SMSOTPServerException {

        String jsonString;
        try {
            jsonString = new ObjectMapper().writeValueAsString(sessionDTO);
        } catch (JsonProcessingException e) {
            throw Utils.handleServerException(
                    Constants.ErrorMessage.SERVER_SESSION_JSON_MAPPER_ERROR, e.getMessage(), e);
        }
        SessionDataStore.getInstance().storeSessionData(sessionId, Constants.SESSION_TYPE_OTP, jsonString,
                getTenantId());
        if (log.isDebugEnabled()) {
            log.debug(String.format("Successfully persisted the OTP for the user Id: %s.", sessionDTO.getUserId()));
        }
    }

    private void triggerNotification(User user, String otp) throws SMSOTPException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Sending SMS OTP notification to user Id: %s.", user.getUserID()));
        }

        Map<String, Object> properties = new HashMap<>();
        properties.put(Constants.CORRELATION_ID, getCorrelationId());
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUsername());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        properties.put(IdentityRecoveryConstants.TEMPLATE_TYPE, Constants.SMS_OTP_NOTIFICATION_TEMPLATE);
        properties.put(IdentityRecoveryConstants.SEND_TO, getMobileNumber(user));
        properties.put(IdentityRecoveryConstants.CONFIRMATION_CODE, otp);

        Event event = new Event(IdentityEventConstants.Event.TRIGGER_SMS_NOTIFICATION, properties);
        try {
            IdentityRecoveryServiceDataHolder.getInstance().getIdentityEventService().handleEvent(event);
        } catch (IdentityEventException e) {
            throw Utils.handleServerException(
                    Constants.ErrorMessage.SERVER_NOTIFICATION_SENDING_ERROR, user.getUserID(), e);
        }
    }

    private SessionDTO getPreviousValidOTPSession(User user) throws SMSOTPException {

        // Search previous session object.
        String sessionId = Utils.getHash(user.getUserID());
        String jsonString = (String) SessionDataStore.getInstance().
                getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        if (StringUtils.isBlank(jsonString)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No valid sessions found for the user Id: %s.", user.getUserID()));
            }
            return null;
        }
        SessionDTO previousOTPSessionDTO;
        try {
            previousOTPSessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
        } catch (IOException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
        }
        // If the previous OTP is issued within the interval, return the same.
        int otpRenewalInterval = SMSOTPServiceDataHolder.getConfigs().getOtpRenewalInterval();
        long elapsedTime = System.currentTimeMillis() - previousOTPSessionDTO.getGeneratedTime();
        boolean isValidToResend = elapsedTime < otpRenewalInterval;
        if (isValidToResend) {
            return previousOTPSessionDTO;
        }
        return null;
    }

    private void shouldThrottle(String userId) throws SMSOTPException {

        String sessionId = Utils.getHash(userId);
        String jsonString = (String) SessionDataStore.getInstance().
                getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        if (StringUtils.isBlank(jsonString)) {
            return;
        }

        SessionDTO previousOTPSessionDTO;
        try {
            previousOTPSessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
        } catch (IOException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
        }

        long elapsedTimeSinceLastOtp = System.currentTimeMillis() - previousOTPSessionDTO.getGeneratedTime();
        int resendThrottleInterval = SMSOTPServiceDataHolder.getConfigs().getResendThrottleInterval();
        if (elapsedTimeSinceLastOtp < resendThrottleInterval) {
            long waitingPeriod = (resendThrottleInterval - elapsedTimeSinceLastOtp) / 1000;
            throw Utils.handleClientException(
                    Constants.ErrorMessage.CLIENT_SLOW_DOWN_RESEND, String.valueOf(waitingPeriod));
        }
    }

    private String getMobileNumber(User user) {

        Map<String, String> userAttributes = user.getAttributes();
        return userAttributes.get(NotificationChannels.SMS_CHANNEL.getClaimUri());
    }

    private int getTenantId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    /**
     * Get correlation id of current thread.
     *
     * @return correlation-id.
     */
    public static String getCorrelationId() {

        return StringUtils.isBlank(MDC.get(Constants.CORRELATION_ID_MDC))
                ? UUID.randomUUID().toString() : MDC.get(Constants.CORRELATION_ID_MDC);
    }

    /**
     * Execute account lock flow for OTP verification failures.
     *
     * @param userId            The ID of the user.
     * @param showFailureReason Display the failure reason.
     * @return The response DTO.
     * @throws SMSOTPException If an error occurs while handling the account lock.
     */
    private ValidationResponseDTO handleAccountLock(String userId, boolean showFailureReason)
            throws SMSOTPException {

        boolean lockAccountOnFailedAttempts = SMSOTPServiceDataHolder.getConfigs().isLockAccountOnFailedAttempts();
        if (!lockAccountOnFailedAttempts) {
            return null;
        }

        User user = getUserById(userId);
        if (Utils.isAccountLocked(user)) {
            return createAccountLockedResponse(userId, showFailureReason);
        }

        int maxAttempts = 0;
        long unlockTimePropertyValue = 0;
        double unlockTimeRatio = 1;

        Property[] connectorConfigs = Utils.getAccountLockConnectorConfigs(user.getTenantDomain());
        for (Property connectorConfig : connectorConfigs) {
            switch (connectorConfig.getName()) {
                case ACCOUNT_LOCKED_PROPERTY:
                    if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                        return null;
                    }
                case FAILED_LOGIN_ATTEMPTS_PROPERTY:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        maxAttempts = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case ACCOUNT_UNLOCK_TIME_PROPERTY:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        unlockTimePropertyValue = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        double value = Double.parseDouble(connectorConfig.getValue());
                        if (value > 0) {
                            unlockTimeRatio = value;
                        }
                    }
                    break;
            }
        }
        Map<String, String> claimValues = getUserClaimValues(user, new String[]{
                Constants.SMS_OTP_FAILED_ATTEMPTS_CLAIM, Constants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM});
        if (claimValues == null) {
            claimValues = new HashMap<>();
        }
        int currentAttempts = getCurrentAttempts(claimValues);
        int failedLoginLockoutCountValue = getFailedLoginLockoutCount(claimValues);

        Map<String, String> updatedClaims = new HashMap<>();
        if ((currentAttempts + 1) >= maxAttempts) {
            populateAccountLockClaims(unlockTimePropertyValue, unlockTimeRatio, failedLoginLockoutCountValue, updatedClaims);
            setUserClaimValues(user, updatedClaims);
            return createAccountLockedResponse(userId, showFailureReason);
        } else {
            updatedClaims.put(Constants.SMS_OTP_FAILED_ATTEMPTS_CLAIM, String.valueOf(currentAttempts + 1));
            setUserClaimValues(user, updatedClaims);
            return null;
        }
    }

    private ValidationResponseDTO createAccountLockedResponse(String userId, boolean showFailureReason) {

        FailureReasonDTO error = showFailureReason ?
                new FailureReasonDTO(Constants.ErrorMessage.CLIENT_ACCOUNT_LOCKED, userId) : null;
        return new ValidationResponseDTO(userId, false, error);
    }

    private void populateAccountLockClaims(long unlockTimePropertyValue, double unlockTimeRatio,
                                           int failedLoginLockoutCountValue, Map<String, String> updatedClaims) {

        // Calculate the incremental unlock time interval in milli seconds.
        unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow(unlockTimeRatio,
                failedLoginLockoutCountValue));
        // Calculate unlock time by adding current time and unlock time interval in milli seconds.
        long unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
        updatedClaims.put(Constants.ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString());
        updatedClaims.put(Constants.SMS_OTP_FAILED_ATTEMPTS_CLAIM, "0");
        updatedClaims.put(Constants.ACCOUNT_UNLOCK_TIME_CLAIM, String.valueOf(unlockTime));
        updatedClaims.put(Constants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                String.valueOf(failedLoginLockoutCountValue + 1));
        updatedClaims.put(Constants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                Constants.MAX_SMS_OTP_ATTEMPTS_EXCEEDED);
        IdentityUtil.threadLocalProperties.get().put(Constants.ADMIN_INITIATED, false);
    }

    private int getCurrentAttempts(Map<String, String> claimValues) {

        if (NumberUtils.isNumber(claimValues.get(Constants.SMS_OTP_FAILED_ATTEMPTS_CLAIM))) {
            return Integer.parseInt(claimValues.get(Constants.SMS_OTP_FAILED_ATTEMPTS_CLAIM));
        }
        return 0;
    }

    private int getFailedLoginLockoutCount(Map<String, String> claimValues) {

        if (NumberUtils.isNumber(claimValues.get(Constants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM))) {
            return Integer.parseInt(claimValues.get(Constants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM));
        }
        return 0;
    }

    private User getUserById(String userId) throws SMSOTPException {

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) SMSOTPServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            return userStoreManager.getUser(userId, null);
        } catch (UserStoreException e) {
            // Handle user not found.
            String errorCode = ((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode();
            if (UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode().equals(errorCode)) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
            }
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    String.format("Error while retrieving user for the ID : %s.", userId), e);
        }
    }

    private Map<String, String> getUserClaimValues(User user, String[] claims) throws SMSOTPServerException {

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) SMSOTPServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            return userStoreManager.getUserClaimValues(user.getDomainQualifiedUsername(), claims,
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    String.format("Failed to read user claims for user ID : %s.", user.getUserID()), e);
        }
    }

    private void setUserClaimValues(User user, Map<String, String> updatedClaims) throws SMSOTPServerException {

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) SMSOTPServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            userStoreManager.setUserClaimValues(user.getDomainQualifiedUsername(), updatedClaims,
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    String.format("Failed to update user claims for user ID: %s.", user.getUserID()), e);
        }
    }

    /**
     * Reset OTP Failed Attempts count upon successful completion of the OTP verification.
     *
     * @param userId The ID of the user.
     * @throws SMSOTPException If an error occurred.
     */
    private void resetOtpFailedAttempts(String userId) throws SMSOTPException {

        if (!SMSOTPServiceDataHolder.getConfigs().isLockAccountOnFailedAttempts()) {
            return;
        }

        User user = getUserById(userId);
        Property[] connectorConfigs = Utils.getAccountLockConnectorConfigs(user.getTenantDomain());
        // Return if account lock handler is not enabled.
        for (Property connectorConfig : connectorConfigs) {
            if ((ACCOUNT_LOCKED_PROPERTY.equals(connectorConfig.getName())) &&
                    !Boolean.parseBoolean(connectorConfig.getValue())) {
                return;
            }
        }

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) SMSOTPServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();

            String[] claimsToCheck = {Constants.SMS_OTP_FAILED_ATTEMPTS_CLAIM, Constants.ACCOUNT_LOCKED_CLAIM};
            Map<String, String> userClaims = userStoreManager.getUserClaimValues(user.getDomainQualifiedUsername(),
                    claimsToCheck, UserCoreConstants.DEFAULT_PROFILE);
            String failedEmailOtpAttemptsClaimValue = userClaims.get(Constants.SMS_OTP_FAILED_ATTEMPTS_CLAIM);
            String accountLockClaimValue = userClaims.get(Constants.ACCOUNT_LOCKED_CLAIM);

            Map<String, String> updatedClaims = new HashMap<>();
            if (NumberUtils.isNumber(failedEmailOtpAttemptsClaimValue) &&
                    Integer.parseInt(failedEmailOtpAttemptsClaimValue) > 0) {
                updatedClaims.put(Constants.SMS_OTP_FAILED_ATTEMPTS_CLAIM, "0");
            }
            if (Boolean.parseBoolean(accountLockClaimValue)) {
                updatedClaims.put(Constants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                updatedClaims.put(Constants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
            }
            if (!updatedClaims.isEmpty()) {
                userStoreManager.setUserClaimValues(user.getDomainQualifiedUsername(), updatedClaims,
                        UserCoreConstants.DEFAULT_PROFILE);
            }
        } catch (UserStoreException e) {
            String errorMessage = String.format("Failed to reset failed attempts count for user ID : %s.",
                    user.getUserID());
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    errorMessage, e);
        }
    }
}
