/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.smsotp.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.smsotp.common.constant.Constants;
import org.wso2.carbon.identity.smsotp.common.dto.GenerationResponseDTO;
import org.wso2.carbon.identity.smsotp.common.dto.SessionDTO;
import org.wso2.carbon.identity.smsotp.common.dto.ValidationResponseDTO;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPException;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPServerException;
import org.wso2.carbon.identity.smsotp.common.internal.SMSOTPServiceDataHolder;
import org.wso2.carbon.identity.smsotp.common.util.OneTimePasswordUtils;
import org.wso2.carbon.identity.smsotp.common.util.Utils;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.internal.IdentityRecoveryServiceDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.common.User;

import java.io.IOException;
import java.util.HashMap;

import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/**
 * This class implements the {@link SMSOTPService} interface.
 */
public class SMSOTPServiceImpl implements SMSOTPService {

    private static final Log log = LogFactory.getLog(SMSOTPService.class);

    @Override
    public GenerationResponseDTO generateSMSOTP(String userId) throws SMSOTPException {

        if (StringUtils.isBlank(userId)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_EMPTY_USER_ID, null);
        }
        // Retrieve user by ID.
        UniqueIDUserStoreManager userStoreManager;
        User user;
        try {
            UserStoreManager manager = SMSOTPServiceDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            if (manager instanceof UniqueIDUserStoreManager) {
                userStoreManager = (UniqueIDUserStoreManager) manager;
            } else {
                throw Utils.handleClientException(
                        Constants.ErrorMessage.SERVER_INCOMPATIBLE_USER_STORE_MANAGER_ERROR, null);
            }
            user = userStoreManager.getUserWithID(userId, null, null);
        } catch (UserStoreException e) {
            // Handle user not found.
            if ("30007".equals(((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode())) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
            }
            throw Utils.handleClientException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    "Error while retrieving user from the Id : " + userId, e);
        }
        // Check if the user exist.
        if (user == null) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
        }

        // Retrieve mobile number if notifications are managed internally.
        boolean sendNotification = Boolean.parseBoolean(
                Utils.readConfigurations().getProperty(Constants.TRIGGER_OTP_NOTIFICATION_PROPERTY));
        String mobileNumber = sendNotification ? getMobileNumber(user.getUsername(), userStoreManager) : null;
        if (StringUtils.isBlank(mobileNumber)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_BLANK_MOBILE_NUMBER,
                    user.getFullQualifiedUsername());
        }

        SessionDTO sessionDTO = proceedWithOTP(mobileNumber, user);

        GenerationResponseDTO otpDto = new GenerationResponseDTO();
        otpDto.setTransactionId(sessionDTO.getTransactionId());
        otpDto.setSmsOTP(sessionDTO.getOtp());
        return otpDto;
    }

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
        // TODO move to the API layer.
//        transactionId = transactionId.trim();
//        userId = userId.trim();
//        smsOTP = smsOTP.trim();

        // Check if resend same valid OTP is enabled.
        Properties properties = Utils.readConfigurations();
        String otpExpiryTimeValue = StringUtils.trim(properties.getProperty(Constants.OTP_EXPIRY_TIME_PROPERTY));
        String otpRenewalIntervalValue = StringUtils.trim(properties.getProperty(Constants.OTP_RENEWAL_INTERVAL));
        // If not defined, use the default values.
        int otpExpiryTime = StringUtils.isNumeric(otpExpiryTimeValue) ?
                Integer.parseInt(otpExpiryTimeValue) : Constants.DEFAULT_SMS_OTP_EXPIRY_TIME;
        // If not defined, defaults to zero to renew always.
        int otpRenewalInterval = StringUtils.isNumeric(otpRenewalIntervalValue) ?
                Integer.parseInt(otpRenewalIntervalValue) : 0;
        boolean resendSameOtpEnabled = otpRenewalInterval > 0 && otpRenewalInterval < otpExpiryTime;

        // Retrieve session from the database.
        String sessionId = resendSameOtpEnabled ? String.valueOf(userId.hashCode()) : transactionId;
        String jsonString = (String) SessionDataStore.getInstance()
                .getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        if (StringUtils.isBlank(jsonString)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid transaction Id provided for the user : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        ObjectMapper mapper = new ObjectMapper();
        SessionDTO sessionDTO;
        try {
            sessionDTO = mapper.readValue(jsonString, SessionDTO.class);
        } catch (IOException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
        }

        ValidationResponseDTO validationResponseDTO = isValid(sessionDTO, smsOTP, userId, transactionId);
        if (!validationResponseDTO.isValid()) {
            return validationResponseDTO;
        }
        // Valid OTP. Clear OTP session data.
        SessionDataStore.getInstance().clearSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        return new ValidationResponseDTO(userId, true);
    }

    private ValidationResponseDTO isValid(SessionDTO sessionDTO, String smsOTP, String userId, String transactionId) {

        // Check if the provided OTP is correct.
        if (!StringUtils.equals(smsOTP, sessionDTO.getOtp())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid OTP provided for the user : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        // Check for expired OTPs.
        if (System.currentTimeMillis() - sessionDTO.getGeneratedTime() >= sessionDTO.getExpiryTime()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Expired OTP provided for the user : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        // Check if the OTP belongs to the provided user.
        if (!StringUtils.equals(userId, sessionDTO.getUserId())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("OTP doesn't belong to the provided user. User : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        // Check if the provided transaction Id is correct.
        if (!StringUtils.equals(transactionId, sessionDTO.getTransactionId())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Provided transaction Id doesn't match. User : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        return new ValidationResponseDTO(userId, true);
    }

    private SessionDTO proceedWithOTP(String mobileNumber, User user) throws SMSOTPException {

        // Read server configurations.
        Properties properties = Utils.readConfigurations();
        String otpLengthValue = StringUtils.trim(properties.getProperty(Constants.OTP_LENGTH_PROPERTY));
        String otpExpiryTimeValue = StringUtils.trim(properties.getProperty(Constants.OTP_EXPIRY_TIME_PROPERTY));
        String otpRenewIntervalValue = StringUtils.trim(properties.getProperty(Constants.OTP_RENEWAL_INTERVAL));
        boolean isAlphaNumericOtpEnabled = Boolean.parseBoolean(
                properties.getProperty(Constants.ALPHA_NUMERIC_OTP_PROPERTY));
        // Notification sending defaults to false.
        boolean triggerNotification =
                StringUtils.isNotBlank(properties.getProperty(Constants.TRIGGER_OTP_NOTIFICATION_PROPERTY)) &&
                        Boolean.parseBoolean(properties.getProperty(Constants.TRIGGER_OTP_NOTIFICATION_PROPERTY));

        // If not defined, use the default values.
        int otpExpiryTime = StringUtils.isNumeric(otpExpiryTimeValue) ?
                Integer.parseInt(otpExpiryTimeValue) : Constants.DEFAULT_SMS_OTP_EXPIRY_TIME;
        int otpLength = StringUtils.isNumeric(otpLengthValue) ?
                Integer.parseInt(otpLengthValue) : Constants.DEFAULT_OTP_LENGTH;
        // If not defined, defaults to zero to renew always.
        int otpRenewalInterval = StringUtils.isNumeric(otpRenewIntervalValue) ?
                Integer.parseInt(otpRenewIntervalValue) : 0;
        // Should we send the same OTP when asked to resend.
        boolean resendSameOtpEnabled = otpRenewalInterval > 0 && otpRenewalInterval < otpExpiryTime;

        // If 'resending same OTP' is enabled, check if such exists.
        SessionDTO sessionDTO = resendSameOtpEnabled ?
                getPreviousValidSession(user.getUserID(), otpRenewalInterval) : null;

        // Otherwise generate a new OTP and proceed.
        if (sessionDTO == null) {
            // Generate OTP.
            String transactionId = createTransactionId();
            String otp = OneTimePasswordUtils.generateOTP(
                    transactionId,
                    String.valueOf(Constants.NUMBER_BASE),
                    otpLength,
                    isAlphaNumericOtpEnabled);
            // Save the otp in the IDN_AUTH_SESSION_STORE table.
            sessionDTO = new SessionDTO();
            sessionDTO.setOtp(otp);
            sessionDTO.setGeneratedTime(System.currentTimeMillis());
            sessionDTO.setExpiryTime(otpExpiryTime);
            sessionDTO.setTransactionId(transactionId);
            sessionDTO.setFullQualifiedUserName(user.getFullQualifiedUsername());
            sessionDTO.setUserId(user.getUserID());
            String jsonString;
            try {
                jsonString = new ObjectMapper().writeValueAsString(sessionDTO);
            } catch (JsonProcessingException e) {
                throw Utils.handleServerException(
                        Constants.ErrorMessage.SERVER_SESSION_JSON_MAPPER_ERROR, e.getMessage(), e);
            }
            String sessionId = resendSameOtpEnabled ? String.valueOf(user.getUserID().hashCode()) : transactionId;
            SessionDataStore.getInstance().storeSessionData(sessionId, Constants.SESSION_TYPE_OTP, jsonString,
                    getTenantId());
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully persisted the OTP for the user : %s.",
                        sessionDTO.getFullQualifiedUserName()));
            }
        }

        // Sending SMS notifications.
        if (triggerNotification) {
            triggerNotification(user, mobileNumber, sessionDTO.getOtp());
        }
        return sessionDTO;
    }

    private void triggerNotification(User user, String mobileNumber, String otp) throws SMSOTPException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Sending SMS OTP notification to : %s using the template : %s.",
                    user.getFullQualifiedUsername(),
                    Constants.SMS_OTP_NOTIFICATION_TEMPLATE));
        }

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUsername());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        properties.put(IdentityRecoveryConstants.TEMPLATE_TYPE, Constants.SMS_OTP_NOTIFICATION_TEMPLATE);
        properties.put(IdentityRecoveryConstants.SEND_TO, mobileNumber);
        properties.put(IdentityRecoveryConstants.CONFIRMATION_CODE, otp);

        Event event = new Event(IdentityEventConstants.Event.TRIGGER_SMS_NOTIFICATION, properties);
        try {
            IdentityRecoveryServiceDataHolder.getInstance().getIdentityEventService().handleEvent(event);
        } catch (IdentityEventException e) {
            throw Utils.handleServerException(
                    Constants.ErrorMessage.SERVER_NOTIFICATION_SENDING_ERROR, user.getFullQualifiedUsername(), e);
        }
    }

    private String getMobileNumber(String username, UserStoreManager userStoreManager)
            throws SMSOTPServerException {

        Map<String, String> mobileNumbersMap;
        try {
            mobileNumbersMap = userStoreManager.getUserClaimValues(
                    username,
                    new String[] { IdentityRecoveryConstants.MOBILE_NUMBER_CLAIM },
                    null);
        } catch (UserStoreException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_RETRIEVING_MOBILE_ERROR, username, e);
        }
        if (MapUtils.isEmpty(mobileNumbersMap)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No mobile numbers found for the user : %s.", username));
            }
            return null;
        }
        return mobileNumbersMap.get(IdentityRecoveryConstants.MOBILE_NUMBER_CLAIM);
    }

    private SessionDTO getPreviousValidSession(String userId, int otpRenewalInterval) throws SMSOTPException {

        // Search previous session object.
        String jsonString = (String) SessionDataStore.getInstance().
                getSessionData(String.valueOf(userId.hashCode()), Constants.SESSION_TYPE_OTP);
        if (StringUtils.isBlank(jsonString)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No valid sessions found for the user : %s.", userId));
            }
            return null;
        }
        ObjectMapper mapper = new ObjectMapper();
        SessionDTO previousSessionDTO;
        try {
            previousSessionDTO = mapper.readValue(jsonString, SessionDTO.class);
        } catch (IOException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
        }
        // If the previous OTP is issued within the interval, return the same.
        return (System.currentTimeMillis() - previousSessionDTO.getGeneratedTime() < otpRenewalInterval) ?
                previousSessionDTO : null;
    }

    private String createTransactionId() {

        String transactionId = UUID.randomUUID().toString();
        if (log.isDebugEnabled()) {
            log.debug("Transaction Id: " + transactionId);
        }
        return transactionId;
    }

    private int getTenantId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }
}
