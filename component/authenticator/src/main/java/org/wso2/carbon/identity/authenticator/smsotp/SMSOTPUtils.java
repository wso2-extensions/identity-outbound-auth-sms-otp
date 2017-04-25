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


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.authenticator.smsotp.exception.SMSOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

public class SMSOTPUtils {

    private static Log log = LogFactory.getLog(SMSOTPUtils.class);

    /**
     * Get parameter values from application-authentication.xml local file.
     */
    public static Map<String, String> getSMSParameters() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(SMSOTPConstants.AUTHENTICATOR_NAME);
        return authConfig.getParameterMap();
    }

    /**
     * Check whether SMSOTP is disable by user.
     *
     * @param username the Username
     * @param context  the AuthenticationContext
     * @return true or false
     * @throws SMSOTPException
     */
    public static boolean isSMSOTPDisableForLocalUser(String username, AuthenticationContext context,
                                                      String authenticatorName) throws SMSOTPException,
            AuthenticationFailedException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            boolean isEnableORDisableLocalUserClaim = isSMSOTPEnableOrDisableByUser(context, authenticatorName);
            if (userRealm != null) {
                if (isEnableORDisableLocalUserClaim) {
                    String isSMSOTPEnabledByUser = userRealm.getUserStoreManager().getUserClaimValue(username,
                            SMSOTPConstants.USER_SMSOTP_DISABLED_CLAIM_URI, null);
                    return Boolean.parseBoolean(isSMSOTPEnabledByUser);
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
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return true or false
     * @throws AuthenticationFailedException
     */
    public static boolean isSMSOTPMandatory(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        boolean isSMSOTPMandatory = false;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.IS_SMSOTP_MANDATORY)) {
            isSMSOTPMandatory = Boolean.parseBoolean(getSMSParameters().get(SMSOTPConstants.IS_SMSOTP_MANDATORY));
        } else if ((context.getProperty(SMSOTPConstants.IS_SMSOTP_MANDATORY)) != null) {
            isSMSOTPMandatory = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(SMSOTPConstants.IS_SMSOTP_MANDATORY)));
        }
        return isSMSOTPMandatory;
    }

    /**
     * Check whether admin enable to send otp directly to mobile number or not.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return true or false
     * @throws AuthenticationFailedException
     */
    public static boolean isSendOTPDirectlyToMobile(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        boolean sendOTPDirectlyToMobile = false;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE)) {
            sendOTPDirectlyToMobile = Boolean.parseBoolean(getSMSParameters().get
                    (SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE));
        } else if ((context.getProperty(SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE)) != null) {
            sendOTPDirectlyToMobile = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE)));
        }
        return sendOTPDirectlyToMobile;
    }

    /**
     * Check whether user enable the second factor or not.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return true or false
     * @throws AuthenticationFailedException
     */
    public static boolean isSMSOTPEnableOrDisableByUser(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        boolean isSMSOTPEnableByUser = false;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER)) {
            isSMSOTPEnableByUser = Boolean.parseBoolean(getSMSParameters().get(SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER));
        } else if ((context.getProperty(SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER)) != null) {
            isSMSOTPEnableByUser = Boolean.parseBoolean(String.valueOf(context.getProperty
                    (SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER)));
        }
        return isSMSOTPEnableByUser;
    }

    /**
     * Check whether admin enable to enter and update a mobile number in user profile when user forgets to register
     * the mobile number or not.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return true or false
     * @throws AuthenticationFailedException
     */
    public static boolean isEnableMobileNoUpdate(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        boolean enableMobileNoUpdate = false;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE)) {
            enableMobileNoUpdate = Boolean.parseBoolean(getSMSParameters().get
                    (SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE));
        } else if ((context.getProperty(SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE)) != null) {
            enableMobileNoUpdate = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE)));
        }
        return enableMobileNoUpdate;
    }

    /**
     * Check whether resend functionality enable or not.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return true or false
     * @throws AuthenticationFailedException
     */
    public static boolean isEnableResendCode(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        boolean enableResendCode = false;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.IS_ENABLED_RESEND)) {
            enableResendCode = Boolean.parseBoolean(getSMSParameters().get(SMSOTPConstants.IS_ENABLED_RESEND));
        } else if ((context.getProperty(SMSOTPConstants.IS_ENABLED_RESEND)) != null) {
            enableResendCode = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(SMSOTPConstants.IS_ENABLED_RESEND)));
        }
        return enableResendCode;
    }

    /**
     * Get the error page url from the application-authentication.xml file.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return errorPage
     * @throws AuthenticationFailedException
     */
    public static String getErrorPageFromXMLFile(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String errorPage = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL)) {
            errorPage = getSMSParameters().get(SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL);
        } else if ((context.getProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL)) != null) {
            errorPage = String.valueOf(context.getProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL));
        }
        return errorPage;
    }

    /**
     * Get the login page url from the application-authentication.xml file.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return loginPage
     * @throws AuthenticationFailedException
     */
    public static String getLoginPageFromXMLFile(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String loginPage = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL)) {
            loginPage = getSMSParameters().get(SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL);
        } else if ((context.getProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL)) != null) {
            loginPage = String.valueOf(context.getProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL));
        }
        return loginPage;
    }

    /**
     * Check whether retry functionality enable or not.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return true or false
     * @throws AuthenticationFailedException
     */
    public static boolean isRetryEnabled(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        boolean isRetryEnabled = false;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.IS_ENABLED_RETRY)) {
            isRetryEnabled = Boolean.parseBoolean(getSMSParameters().get(SMSOTPConstants.IS_ENABLED_RETRY));
        } else if ((context.getProperty(SMSOTPConstants.IS_ENABLED_RETRY)) != null) {
            isRetryEnabled = Boolean.parseBoolean(String.valueOf(context.getProperty(SMSOTPConstants.IS_ENABLED_RETRY)));
        }
        return isRetryEnabled;
    }

    /**
     * Get the mobile number request page url from the application-authentication.xml file.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return mobile number request page
     * @throws AuthenticationFailedException
     */
    public static String getMobileNumberRequestPage(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String mobileNoReqPage = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE)) {
            mobileNoReqPage = getSMSParameters().get(SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE);
        } else if ((context.getProperty(SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE)) != null) {
            mobileNoReqPage = String.valueOf(context.getProperty(SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE));
        }
        return mobileNoReqPage;
    }

    /**
     * Get the screen user attribute.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return screenUserAttribute
     * @throws AuthenticationFailedException
     */
    public static String getScreenUserAttribute(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String screenUserAttribute = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.SCREEN_USER_ATTRIBUTE)) {
            screenUserAttribute = getSMSParameters().get(SMSOTPConstants.SCREEN_USER_ATTRIBUTE);
        } else if ((context.getProperty(SMSOTPConstants.SCREEN_USER_ATTRIBUTE)) != null) {
            screenUserAttribute = String.valueOf(context.getProperty(SMSOTPConstants.SCREEN_USER_ATTRIBUTE));
        }
        return screenUserAttribute;
    }

    /**
     * Check the number of digits of claim value to show in UI.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return noOfDigits
     * @throws AuthenticationFailedException
     */
    public static String getNoOfDigits(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String noOfDigits = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.NO_DIGITS)) {
            noOfDigits = getSMSParameters().get(SMSOTPConstants.NO_DIGITS);
        } else if ((context.getProperty(SMSOTPConstants.NO_DIGITS)) != null) {
            noOfDigits = String.valueOf(context.getProperty(SMSOTPConstants.NO_DIGITS));
        }
        return noOfDigits;
    }

    /**
     * Check the order whether first number or last of n digits.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return digitsOrder
     * @throws AuthenticationFailedException
     */
    public static String getDigitsOrder(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String digitsOrder = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.ORDER)) {
            digitsOrder = getSMSParameters().get(SMSOTPConstants.ORDER);
        } else if ((context.getProperty(SMSOTPConstants.ORDER)) != null) {
            digitsOrder = String.valueOf(context.getProperty(SMSOTPConstants.ORDER));
        }
        return digitsOrder;
    }

    /**
     * Check whether admin allows to use the backup codes or not
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return backupCode
     * @throws AuthenticationFailedException
     */
    public static String getBackupCode(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        Object propertiesFromLocal = null;
        String backupCode = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) &&
                getSMSParameters().containsKey(SMSOTPConstants.BACKUP_CODE)) {
            backupCode = getSMSParameters().get(SMSOTPConstants.BACKUP_CODE);
        } else if ((context.getProperty(SMSOTPConstants.BACKUP_CODE)) != null) {
            backupCode = String.valueOf(context.getProperty(SMSOTPConstants.BACKUP_CODE));
        }
        return backupCode;
    }
}