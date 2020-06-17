/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.smsotp;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.smsotp.exception.SMSOTPException;
import org.wso2.carbon.identity.authenticator.smsotp.internal.SMSOTPServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Collections;
import java.util.Map;

public class SMSOTPUtils {

    private static final Log log = LogFactory.getLog(SMSOTPUtils.class);
    private static boolean useInternalErrorCodes = false;

    /**
     * Get parameter values from application-authentication.xml local file.
     */
    public static Map<String, String> getSMSParameters() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(SMSOTPConstants.AUTHENTICATOR_NAME);
        if (authConfig != null) {
            return authConfig.getParameterMap();
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator configs not found. Hence returning an empty map");
        }
        return Collections.emptyMap();
    }

    /**
     * Check whether SMSOTP is disable by user.
     *
     * @param username the Username
     * @param context  the AuthenticationContext
     * @return true or false
     * @throws SMSOTPException
     */
    public static boolean isSMSOTPDisableForLocalUser(String username, AuthenticationContext context)
            throws SMSOTPException {

        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            boolean isEnablingControlledByUser = isSMSOTPEnableOrDisableByUser(context);
            if (userRealm != null) {
                if (isEnablingControlledByUser) {
                    Map<String, String> claimValues = userRealm.getUserStoreManager().getUserClaimValues(username,
                            new String[]{SMSOTPConstants.USER_SMSOTP_DISABLED_CLAIM_URI}, null);
                    return Boolean.parseBoolean(claimValues.get(SMSOTPConstants.USER_SMSOTP_DISABLED_CLAIM_URI));
                }
            } else {
                throw new SMSOTPException("Cannot find the user realm for the given tenant domain : " + CarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new SMSOTPException("Failed while trying to access userRealm of the user : " + username, e);
        }
        return false;
    }

    /**
     * Update the mobile number (user attribute) in user's profile.
     *
     * @param username  the Username
     * @param attribute the Attribute
     * @throws SMSOTPException
     */
    public static void updateUserAttribute(String username, Map<String, String> attribute, String tenantDomain)
            throws SMSOTPException {

        try {
            // updating user attributes is independent from tenant association.not tenant association check needed here.
            UserRealm userRealm;
            // user is always in the super tenant.
            userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
            if (userRealm == null) {
                throw new SMSOTPException("The specified tenant domain " + tenantDomain + " does not exist.");
            }
            // check whether user already exists in the system.
            SMSOTPUtils.verifyUserExists(username, tenantDomain);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(username, attribute, null);
        } catch (UserStoreException | AuthenticationFailedException e) {
            throw new SMSOTPException("Exception occurred while connecting to User Store: Authentication is failed. ", e);
        }
    }

    /**
     * Verify whether user Exist in the user store or not.
     *
     * @param username the Username
     * @throws SMSOTPException
     */
    public static void verifyUserExists(String username, String tenantDomain) throws SMSOTPException,
            AuthenticationFailedException {

        UserRealm userRealm;
        boolean isUserExist = false;
        try {
            userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
            if (userRealm == null) {
                throw new SMSOTPException("Super tenant realm not loaded.");
            }
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager.isExistingUser(username)) {
                isUserExist = true;
            }
        } catch (UserStoreException e) {
            throw new SMSOTPException("Error while validating the user.", e);
        }
        if (!isUserExist) {
            if (log.isDebugEnabled()) {
                log.debug("User does not exist in the User Store");
            }
            throw new SMSOTPException("User does not exist in the User Store.");
        }
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param tenantDomain the tenantDomain
     * @return th user realm
     * @throws AuthenticationFailedException
     */
    public static UserRealm getUserRealm(String tenantDomain) throws AuthenticationFailedException {

        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Cannot find the user realm for the tenant domain "
                    + tenantDomain, e);
        }
        return userRealm;
    }

    /**
     * Get the mobile number for Username.
     *
     * @param username the username
     * @return mobile number
     * @throws SMSOTPException
     */
    public static String getMobileNumberForUsername(String username) throws SMSOTPException,
            AuthenticationFailedException {

        UserRealm userRealm;
        String mobile;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            userRealm = getUserRealm(tenantDomain);
            if (userRealm != null) {
                mobile = userRealm.getUserStoreManager()
                        .getUserClaimValue(tenantAwareUsername, SMSOTPConstants.MOBILE_CLAIM, null);
            } else {
                throw new SMSOTPException("Cannot find the user realm for the given tenant domain : " + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new SMSOTPException("Cannot find the user " + username + " to get the mobile number ", e);
        }
        return mobile;
    }

    /**
     * Check whether SMSOTP is mandatory or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isSMSOTPMandatory(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_SMSOTP_MANDATORY));
    }

    /**
     * Check whether admin enable to send otp directly to mobile number or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isSendOTPDirectlyToMobile(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE));
    }

    /**
     * Check whether admin enable to send otp directly to mobile number which gets from federated idp claims.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean sendOtpToFederatedMobile(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_SEND_OTP_TO_FEDERATED_MOBILE));
    }

    /**
     * Check whether user enable the second factor or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isSMSOTPEnableOrDisableByUser(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER));
    }

    /**
     * Check whether admin enable to enter and update a mobile number in user profile when user forgets to register
     * the mobile number or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isEnableMobileNoUpdate(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE));
    }

    /**
     * Check whether resend functionality enable or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isEnableResendCode(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_ENABLED_RESEND));
    }

    /**
     * Get the error page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return errorPage
     */
    public static String getErrorPageFromXMLFile(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL);
    }

    /**
     * Get the login page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return loginPage
     */
    public static String getLoginPageFromXMLFile(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL);
    }

    /**
     * Check whether retry functionality enable or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isRetryEnabled(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_ENABLED_RETRY));
    }

    /**
     * Get the mobile number request page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return mobile number request page
     */
    public static String getMobileNumberRequestPage(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE);
    }

    /**
     * Get the screen user attribute.
     *
     * @param context the AuthenticationContext
     * @return screenUserAttribute
     */
    public static String getScreenUserAttribute(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.SCREEN_USER_ATTRIBUTE);
    }

    /**
     * Check the number of digits of claim value to show in UI.
     *
     * @param context the AuthenticationContext
     * @return noOfDigits
     */
    public static String getNoOfDigits(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.NO_DIGITS);
    }

    /**
     * Check the order whether first number or last of n digits.
     *
     * @param context the AuthenticationContext
     * @return digitsOrder
     */
    public static String getDigitsOrder(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.ORDER);
    }

    /**
     * Check whether admin allows to use the backup codes or not
     *
     * @param context the AuthenticationContext
     * @return backupCode
     */
    public static String getBackupCode(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.BACKUP_CODE);

    }

    /**
     * Return whether internal errorcodes support is configured.
     *
     * @param context Authentication Context.
     * @return Ture if UseInternalError codes is enabled, else return false.
     */
    public static boolean useInternalErrorCodes(AuthenticationContext context) {

        String useSMSProviderCodesConfig = getConfiguration(context, SMSOTPConstants.USE_INTERNAL_ERROR_CODES);
        if (StringUtils.isNotEmpty(useSMSProviderCodesConfig)) {
            useInternalErrorCodes = Boolean.parseBoolean(useSMSProviderCodesConfig);
            if (log.isDebugEnabled()) {
                log.debug("useInternalErrorCodes is enabled in SMS-OTP Authenticator configuration");
            }
        }
        return useInternalErrorCodes;
    }

    /**
     * Return the value for useInternalErrorCodes.
     *
     * @return useInternalErrorCodes.
     */
    public static boolean useInternalErrorCodes() {

        return useInternalErrorCodes;
    }
    /**
     * Check whether admin allows to generate the alphanumeric token or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isEnableAlphanumericToken(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_ENABLE_ALPHANUMERIC_TOKEN));
    }

    /**
     * Get the token expiry time.
     *
     * @param context the AuthenticationContext
     * @return tokenExpiryTime
     */
    public static String getTokenExpiryTime(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.TOKEN_EXPIRY_TIME);
    }

    /**
     * Get the token length.
     *
     * @param context the AuthenticationContext
     * @return tokenLength
     */
    public static String getTokenLength(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.TOKEN_LENGTH);
    }

    /**
     * Read configurations from application-authentication.xml for given authenticator.
     *
     * @param context    Authentication Context.
     * @param configName Name of the config.
     * @return Config value.
     */
    public static String getConfiguration(AuthenticationContext context, String configName) {

        String configValue = null;
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        String tenantDomain = context.getTenantDomain();
        if ((propertiesFromLocal != null || MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) &&
                getSMSParameters().containsKey(configName)) {
            configValue = getSMSParameters().get(configName);
        } else if ((context.getProperty(configName)) != null) {
            configValue = String.valueOf(context.getProperty(configName));
        }
        if (log.isDebugEnabled()) {
            log.debug("Config value for key " + configName + " for tenant " + tenantDomain + " : " +
                    configValue);
        }
        return configValue;
    }

    /**
     * Check whether ShowAuthFailureReason is enabled or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isShowAuthFailureReason(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.SHOW_AUTH_FAILURE_REASON));
    }

    /**
     * Check whether account locking is enabled for SMS OTP
     *
     * @param context
     * @return
     */
    public static boolean isAccountLockingEnabledForSmsOtp(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context,
                SMSOTPConstants.ENABLE_ACCOUNT_LOCKING_FOR_FAILED_ATTEMPTS));
    }

    /**
     * Check whether a given user is locked
     *
     * @param authenticatedUser
     * @return true or false
     * @throws AuthenticationFailedException
     */
    public static boolean isAccountLocked(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        try {
            return SMSOTPServiceDataHolder.getInstance().getAccountLockService()
                    .isAccountLocked(authenticatedUser.getUserName(), authenticatedUser.getTenantDomain(),
                            authenticatedUser.getUserStoreDomain());
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error while validating account lock status of user: " +
                    authenticatedUser.getUserName(), e);
        }
    }

    /**
     * Get Account Lock Connector Configs
     *
     * @param tenantDomain
     * @return AccountLockConnectorConfigs
     * @throws AuthenticationFailedException
     */
    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws AuthenticationFailedException {

        Property[] connectorConfigs;
        try {
            connectorConfigs = SMSOTPServiceDataHolder.getInstance()
                    .getIdentityGovernanceService()
                    .getConfiguration(
                            new String[]{
                                    SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE,
                                    SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX,
                                    SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_TIME,
                                    SMSOTPConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO
                            }, tenantDomain);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while retrieving account lock connector " +
                    "configuration", e);
        }

        return connectorConfigs;
    }

    /**
     * Check whether the user being authenticated via a local authenticator or not.
     *
     * @param context Authentication context.
     * @return Whether the user being authenticated via a local authenticator.
     */
    public static boolean isLocalUser(AuthenticationContext context) {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        if (stepConfigMap != null) {
            for (StepConfig stepConfig : stepConfigMap.values()) {
                if (stepConfig.getAuthenticatedUser() != null && stepConfig.isSubjectAttributeStep() &&
                        StringUtils.equals(SMSOTPConstants.LOCAL_AUTHENTICATOR, stepConfig.getAuthenticatedIdP())) {
                    return true;
                }
            }
        }
        return false;
    }
}