/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.smsotp;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.smsotp.exception.SMSOTPException;
import org.wso2.carbon.identity.authenticator.smsotp.internal.SMSOTPServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.CHAR_SET_UTF_8;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.MASKING_VALUE_SEPARATOR;

import static java.util.Base64.getEncoder;

/**
 * Authenticator of SMS OTP
 */
public class SMSOTPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(SMSOTPAuthenticator.class);
    private static final String TRIGGER_SMS_NOTIFICATION = "TRIGGER_SMS_NOTIFICATION";

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside SMSOTPAuthenticator canHandle method and check the existence of mobile number and otp code");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(SMSOTPConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.CODE))
                || StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.MOBILE_NUMBER)));
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.MOBILE_NUMBER))) {
            // if the request comes with MOBILE_NUMBER, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } else if (StringUtils.isEmpty(request.getParameter(SMSOTPConstants.CODE))) {
            // if the request comes with code, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(SMSOTPConstants.AUTHENTICATION)
                    .equals(SMSOTPConstants.AUTHENTICATOR_NAME)) {
                // if the request comes with authentication is SMSOTP, it will go through this flow.
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // if the request comes with authentication is basic, complete the flow.
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            return super.process(request, response, context);
        }
    }

    /**
     * Initiate the authentication request.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            String username;
            AuthenticatedUser authenticatedUser;
            String mobileNumber;
            String tenantDomain = context.getTenantDomain();
            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.AUTHENTICATOR_NAME);
            if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
            }
            FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty(SMSOTPConstants.USER_NAME));
            authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
            // find the authenticated user.
            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failed: Could not find the authenticated user. ");
                }
                throw new AuthenticationFailedException
                        ("Authentication failed: Cannot proceed further without identifying the user. ");
            }
            boolean isSMSOTPMandatory = SMSOTPUtils.isSMSOTPMandatory(context);
            boolean isUserExists = FederatedAuthenticatorUtil.isUserExistInUserStore(username);
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String errorPage = getErrorPage(context);
            // SMS OTP authentication is mandatory and user doesn't disable SMS OTP claim in user's profile.
            if (isSMSOTPMandatory) {
                if (log.isDebugEnabled()) {
                    log.debug("SMS OTP is mandatory. Hence processing in mandatory path");
                }
                processSMSOTPMandatoryCase(context, request, response, queryParams, username, isUserExists);
            } else if (isUserExists && !SMSOTPUtils.isSMSOTPDisableForLocalUser(username, context)) {
                if (context.isRetrying() && !Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND))) {
                    checkStatusCode(response, context, queryParams, errorPage);
                } else {
                    mobileNumber = getMobileNumber(request, response, context, username, tenantDomain, queryParams);
                    if (StringUtils.isNotEmpty(mobileNumber)) {
                        proceedWithOTP(response, context, errorPage, mobileNumber, queryParams, username);
                    }

                }
            } else {
                processFirstStepOnly(authenticatedUser, context);
            }
        } catch (SMSOTPException e) {
            throw new AuthenticationFailedException("Failed to get the parameters from authentication xml file. ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from User Store. ", e);
        }
    }

    /**
     * Get the mobile number from user's profile to send an otp.
     *
     * @param request      the HttpServletRequest
     * @param response     the HttpServletResponse
     * @param context      the AuthenticationContext
     * @param username     the Username
     * @param tenantDomain the TenantDomain
     * @param queryParams  the queryParams
     * @return the mobile number
     * @throws AuthenticationFailedException
     * @throws SMSOTPException
     */
    private String getMobileNumber(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationContext context, String username, String tenantDomain,
                                   String queryParams) throws AuthenticationFailedException, SMSOTPException {

        String mobileNumber = SMSOTPUtils.getMobileNumberForUsername(username);
        if (StringUtils.isEmpty(mobileNumber)) {
            if (request.getParameter(SMSOTPConstants.MOBILE_NUMBER) == null) {
                if (log.isDebugEnabled()) {
                    log.debug("User has not registered a mobile number: " + username);
                }
                redirectToMobileNoReqPage(response, context, queryParams);
            } else {
                updateMobileNumberForUsername(context, request, username, tenantDomain);
                mobileNumber = SMSOTPUtils.getMobileNumberForUsername(username);
            }
        }
        return mobileNumber;
    }

    /**
     * Get the loginPage from authentication.xml file or use the login page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the loginPage
     * @throws AuthenticationFailedException
     */
    private String getLoginPage(AuthenticationContext context) throws AuthenticationFailedException {

        String loginPage = SMSOTPUtils.getLoginPageFromXMLFile(context);
        if (StringUtils.isEmpty(loginPage)) {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.SMS_LOGIN_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used");
            }
        }
        return loginPage;
    }

    /**
     * Get the errorPage from authentication.xml file or use the error page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the errorPage
     * @throws AuthenticationFailedException
     */
    private String getErrorPage(AuthenticationContext context) throws AuthenticationFailedException {

        String errorPage = SMSOTPUtils.getErrorPageFromXMLFile(context);
        if (StringUtils.isEmpty(errorPage)) {
            errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used");
            }
        }
        return errorPage;
    }

    /**
     * To get the redirection URL.
     *
     * @param baseURI     the base path
     * @param queryParams the queryParams
     * @return url
     */
    private String getURL(String baseURI, String queryParams) {

        String url;
        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + SMSOTPConstants.NAME_OF_AUTHENTICATORS + getName();
        } else {
            url = baseURI + "?" + SMSOTPConstants.NAME_OF_AUTHENTICATORS + getName();
        }
        return url;
    }

    /**
     * Redirect to an error page.
     *
     * @param response    the HttpServletResponse
     * @param queryParams the queryParams
     * @throws AuthenticationFailedException
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context, String queryParams,
                                     String retryParam)
            throws AuthenticationFailedException {
        // that Enable the SMS OTP in user's Profile. Cannot proceed further without SMS OTP authentication.
        try {
            String errorPage = getErrorPage(context);
            String url = getURL(errorPage, queryParams);
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception occurred while redirecting to errorPage. ", e);
        }
    }

    /**
     * In SMSOTP optional case proceed with first step only.It can be basic or federated.
     *
     * @param authenticatedUser the name of authenticatedUser
     * @param context           the AuthenticationContext
     */
    private void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Processing First step only. Skipping SMSOTP");
        }
        //the authentication flow happens with basic authentication.
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {
            if (log.isDebugEnabled()) {
                log.debug("Found local authenticator in previous step. Hence setting a local user");
            }
            FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.BASIC);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Found federated authenticator in previous step. Hence setting a local user");
            }
            FederatedAuthenticatorUtil.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.FEDERETOR);
        }
    }

    /**
     * Update mobile number when user forgets to update the mobile number in user's profile.
     *
     * @param context      the AuthenticationContext
     * @param request      the HttpServletRequest
     * @param username     the Username
     * @param tenantDomain the TenantDomain
     * @throws SMSOTPException
     * @throws AuthenticationFailedException
     */
    private void updateMobileNumberForUsername(AuthenticationContext context, HttpServletRequest request,
                                               String username, String tenantDomain)
            throws SMSOTPException, AuthenticationFailedException {

        if (username != null && !context.isRetrying()) {
            if (log.isDebugEnabled()) {
                log.debug("Updating mobile number for user : " + username);
            }
            Map<String, String> attributes = new HashMap<>();
            attributes.put(SMSOTPConstants.MOBILE_CLAIM, request.getParameter(SMSOTPConstants.MOBILE_NUMBER));
            SMSOTPUtils.updateUserAttribute(MultitenantUtils.getTenantAwareUsername(username), attributes,
                    tenantDomain);
        }
    }

    /**
     * Check with SMSOTP mandatory case with SMSOTP flow.
     *
     * @param context      the AuthenticationContext
     * @param request      the HttpServletRequest
     * @param response     the HttpServletResponse
     * @param queryParams  the queryParams
     * @param username     the Username
     * @param isUserExists check whether user exist or not
     * @throws AuthenticationFailedException
     * @throws SMSOTPException
     */
    private void processSMSOTPMandatoryCase(AuthenticationContext context, HttpServletRequest request,
                                            HttpServletResponse response, String queryParams, String username,
                                            boolean isUserExists) throws AuthenticationFailedException, SMSOTPException {
        //the authentication flow happens with sms otp authentication.
        String tenantDomain = context.getTenantDomain();
        String errorPage = getErrorPage(context);
        if (context.isRetrying() && !Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND))) {
            checkStatusCode(response, context, queryParams, errorPage);
        } else {
            processSMSOTPFlow(context, request, response, isUserExists, username, queryParams, tenantDomain,
                    errorPage);
        }
    }

    private void proceedOTPWithFederatedMobileNumber(AuthenticationContext context, HttpServletResponse response,
                                                     String username, String queryParams,
                                                     boolean sendOtpToFederatedMobile)
            throws AuthenticationFailedException {

        try {
            String federatedMobileAttributeKey;
            String mobile = null;
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
            String previousStepAuthenticator = stepConfig.getAuthenticatedAutenticator().getName();
            StepConfig currentStep = context.getSequenceConfig().getStepMap().get(context.getCurrentStep());
            String currentStepAuthenticator = currentStep.getAuthenticatorList().iterator().next().getName();
            if (sendOtpToFederatedMobile) {
                federatedMobileAttributeKey = getFederatedMobileAttributeKey(context, previousStepAuthenticator);
                if (StringUtils.isEmpty(federatedMobileAttributeKey)) {
                    federatedMobileAttributeKey = getFederatedMobileAttributeKey(context, currentStepAuthenticator);
                }
                Map<ClaimMapping, String> userAttributes = context.getCurrentAuthenticatedIdPs().values().
                        iterator().next().getUser().getUserAttributes();
                for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                    String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
                    String value = entry.getValue();
                    if (key.equals(federatedMobileAttributeKey)) {
                        mobile = String.valueOf(value);
                        proceedWithOTP(response, context, getErrorPage(context), mobile, queryParams, username);
                        break;
                    }
                }
                if (StringUtils.isEmpty(mobile)) {
                    if (log.isDebugEnabled()) {
                        log.debug("There is no mobile claim to send otp ");
                    }
                    throw new AuthenticationFailedException("There is no mobile claim to send otp");
                }
            } else {
                redirectToErrorPage(response, context, queryParams, SMSOTPConstants.SEND_OTP_DIRECTLY_DISABLE);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException(" Failed to process SMSOTP flow ", e);
        }
    }

    private String getFederatedMobileAttributeKey(AuthenticationContext context, String authenticatorName) {

        String federatedSMSAttributeKey = null;
        Map<String, String> parametersMap;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if (propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
            parametersMap = FederatedAuthenticatorUtil.getAuthenticatorConfig(authenticatorName);
            if (parametersMap != null) {
                federatedSMSAttributeKey = parametersMap.get
                        (SMSOTPConstants.FEDERATED_MOBILE_ATTRIBUTE_KEY);
            }
        } else {
            federatedSMSAttributeKey = String.valueOf(context.getProperty
                    (SMSOTPConstants.FEDERATED_MOBILE_ATTRIBUTE_KEY));
        }
        return federatedSMSAttributeKey;
    }

    /**
     * Check with SMSOTP flow with user existence.
     *
     * @param context      the AuthenticationContext
     * @param request      the HttpServletRequest
     * @param response     the HttpServletResponse
     * @param isUserExists check whether user exist or not
     * @param username     the UserName
     * @param queryParams  the queryParams
     * @param tenantDomain the TenantDomain
     * @param errorPage    the errorPage
     * @throws AuthenticationFailedException
     * @throws SMSOTPException
     */
    private void processSMSOTPFlow(AuthenticationContext context, HttpServletRequest request,
                                   HttpServletResponse response, boolean isUserExists, String username,
                                   String queryParams, String tenantDomain, String errorPage)
            throws AuthenticationFailedException, SMSOTPException {

        String mobileNumber = null;
        if (isUserExists) {
            boolean isSMSOTPDisabledByUser = SMSOTPUtils.isSMSOTPDisableForLocalUser(username, context);
            if (log.isDebugEnabled()) {
                log.debug("Has user enabled SMS OTP : " + isSMSOTPDisabledByUser);
            }
            if (isSMSOTPDisabledByUser) {
                // that Enable the SMS OTP in user's Profile. Cannot proceed further without SMS OTP authentication.
                redirectToErrorPage(response, context, queryParams, SMSOTPConstants.ERROR_SMSOTP_DISABLE);
            } else {
                mobileNumber = getMobileNumber(request, response, context, username, tenantDomain, queryParams);
            }
        } else if (SMSOTPUtils.isSendOTPDirectlyToMobile(context)) {
            if (log.isDebugEnabled()) {
                log.debug("User :" + username + " doesn't exist");
            }
            if (request.getParameter(SMSOTPConstants.MOBILE_NUMBER) == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Couldn't find the mobile number in request. Hence redirecting to mobile number input " +
                            "page");
                }
                String loginPage = SMSOTPUtils.getMobileNumberRequestPage(context);
                try {
                    String url = getURL(loginPage, queryParams);
                    response.sendRedirect(url);
                } catch (IOException e) {
                    throw new AuthenticationFailedException("Authentication failed!. An IOException occurred ", e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Mobile number found in request : " + request.getParameter(SMSOTPConstants.MOBILE_NUMBER));
                }
                mobileNumber = request.getParameter(SMSOTPConstants.MOBILE_NUMBER);
            }
        } else if (SMSOTPUtils.sendOtpToFederatedMobile(context)) {
            if (log.isDebugEnabled()) {
                log.debug("SMS OTP is mandatory. But user is not there in active directory. Hence send the otp to the " +
                        "federated mobile claim");
            }
            proceedOTPWithFederatedMobileNumber(context, response, username, queryParams,
                    SMSOTPUtils.sendOtpToFederatedMobile(context));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("SMS OTP is mandatory. But couldn't find a mobile number.");
            }
            redirectToErrorPage(response, context, queryParams, SMSOTPConstants.SEND_OTP_DIRECTLY_DISABLE);
        }
        if (StringUtils.isNotEmpty(mobileNumber)) {
            proceedWithOTP(response, context, errorPage, mobileNumber, queryParams, username);
        }
    }

    /**
     * Proceed with One Time Password.
     *
     * @param response     the HttpServletResponse
     * @param context      the AuthenticationContext
     * @param errorPage    the errorPage
     * @param mobileNumber the mobile number
     * @param queryParams  the queryParams
     * @param username     the Username
     * @throws AuthenticationFailedException
     */
    private void proceedWithOTP(HttpServletResponse response, AuthenticationContext context, String errorPage,
                                String mobileNumber, String queryParams, String username)
            throws AuthenticationFailedException {

        String screenValue;
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        boolean isEnableResendCode = SMSOTPUtils.isEnableResendCode(context);
        String loginPage = getLoginPage(context);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
        int tokenLength = SMSOTPConstants.NUMBER_DIGIT;
        boolean isEnableAlphanumericToken = SMSOTPUtils.isEnableAlphanumericToken(context);
        try {
            // One time password is generated and stored in the context.
            OneTimePassword token = new OneTimePassword();
            String secret = OneTimePassword.getRandomNumber(SMSOTPConstants.SECRET_KEY_LENGTH);
            if ((SMSOTPUtils.getTokenLength(context)) != null) {
                tokenLength = Integer.parseInt(SMSOTPUtils.getTokenLength(context));
            }
            if ((SMSOTPUtils.getTokenExpiryTime(context)) != null) {
                long tokenExpiryTime = Integer.parseInt(SMSOTPUtils.getTokenExpiryTime(context));
                context.setProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME, tokenExpiryTime);
            }
            String otpToken = token.generateToken(secret, String.valueOf(SMSOTPConstants.NUMBER_BASE), tokenLength,
                    isEnableAlphanumericToken);
            context.setProperty(SMSOTPConstants.OTP_TOKEN, otpToken);
            if (log.isDebugEnabled()) {
                log.debug("Generated OTP successfully and set to the context.");
            }
            //Get the values of the sms provider related api parameters.
            String smsUrl = authenticatorProperties.get(SMSOTPConstants.SMS_URL);
            String httpMethod = authenticatorProperties.get(SMSOTPConstants.HTTP_METHOD);
            String headerString = authenticatorProperties.get(SMSOTPConstants.HEADERS);
            String payload = authenticatorProperties.get(SMSOTPConstants.PAYLOAD);
            String httpResponse = authenticatorProperties.get(SMSOTPConstants.HTTP_RESPONSE);
            boolean connectionResult = true;
            //Check the SMS URL configure in UI and give the first priority for that.
            if (StringUtils.isNotEmpty(smsUrl)) {
                connectionResult = sendRESTCall(context, smsUrl, httpMethod, headerString, payload,
                        httpResponse, mobileNumber, otpToken);
            } else {
                //Use the default notification mechanism (CEP) to send SMS.
                AuthenticatedUser authenticatedUser = (AuthenticatedUser)
                        context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
                triggerNotification(authenticatedUser.getUserName(), authenticatedUser.getTenantDomain(),
                        authenticatedUser.getUserStoreDomain(), mobileNumber, otpToken);
            }

            if (!connectionResult) {
                String retryParam;
                if (context.getProperty(SMSOTPConstants.ERROR_CODE) != null) {
                    String errorCode = context.getProperty(SMSOTPConstants.ERROR_CODE).toString();
                    // If useInternalErrorCodes is configured as true, then http response error codes will be mapped
                    // to local error codes and passed as query param value for authfailure msg.
                    if (SMSOTPUtils.useInternalErrorCodes(context)) {
                        String errorResponseCode = getHttpErrorResponseCode(errorCode);
                        if (StringUtils.isNotEmpty(errorResponseCode)) {
                            String internalErrorCode = SMSOTPConstants.ErrorMessage.
                                    getMappedInternalErrorCode(errorResponseCode).getCode();
                            errorCode = URLEncoder.encode(internalErrorCode, CHAR_SET_UTF_8);
                        }
                    }
                    retryParam = SMSOTPConstants.ERROR_MESSAGE + errorCode;
                    String errorInfo = context.getProperty(SMSOTPConstants.ERROR_INFO).toString();
                    if (Boolean.parseBoolean(authenticatorProperties.get(SMSOTPConstants.SHOW_ERROR_INFO)) &&
                            errorInfo != null) {
                        retryParam = retryParam + SMSOTPConstants.ERROR_MESSAGE_DETAILS + getEncoder().encodeToString
                                (errorInfo.getBytes());
                    }
                } else {
                    retryParam = SMSOTPConstants.ERROR_MESSAGE + SMSOTPConstants.UNABLE_SEND_CODE_VALUE;
                }
                String redirectUrl = getURL(errorPage, queryParams);
                response.sendRedirect(redirectUrl + SMSOTPConstants.RESEND_CODE + isEnableResendCode + retryParam);
            } else {
                long sentOTPTokenTime = System.currentTimeMillis();
                context.setProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME, sentOTPTokenTime);
                String url = getURL(loginPage, queryParams);
                boolean isUserExists = FederatedAuthenticatorUtil.isUserExistInUserStore(username);
                if (isUserExists) {
                    screenValue = getScreenAttribute(context, userRealm, tenantAwareUsername);
                    if (screenValue != null) {
                        url = url + SMSOTPConstants.SCREEN_VALUE + screenValue;
                    }
                }
                response.sendRedirect(url);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while sending the HTTP request. ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from user store. ", e);
        }
    }

    /**
     * Check the status codes when resend and retry enabled.
     *
     * @param response    the HttpServletResponse
     * @param context     the AuthenticationContext
     * @param queryParams the queryParams
     * @param errorPage   the errorPage
     * @throws AuthenticationFailedException
     */
    private void checkStatusCode(HttpServletResponse response, AuthenticationContext context,
                                 String queryParams, String errorPage) throws AuthenticationFailedException {

        boolean isRetryEnabled = SMSOTPUtils.isRetryEnabled(context);
        String loginPage = getLoginPage(context);
        String url = getURL(loginPage, queryParams);
        if (StringUtils.isNotEmpty(getScreenValue(context))) {
            url = url + SMSOTPConstants.SCREEN_VALUE + getScreenValue(context);
        }
        try {
            if (isRetryEnabled) {
                if (StringUtils.isNotEmpty((String) context.getProperty(SMSOTPConstants.TOKEN_EXPIRED))) {
                    response.sendRedirect(url + SMSOTPConstants.RESEND_CODE
                            + SMSOTPUtils.isEnableResendCode(context) + SMSOTPConstants.ERROR_MESSAGE +
                            SMSOTPConstants.TOKEN_EXPIRED_VALUE);
                } else {
                    response.sendRedirect(url + SMSOTPConstants.RESEND_CODE
                            + SMSOTPUtils.isEnableResendCode(context) + SMSOTPConstants.RETRY_PARAMS);
                }
            } else {
                url = getURL(errorPage, queryParams);
                if (Boolean.parseBoolean(String.valueOf(context.getProperty(SMSOTPConstants.CODE_MISMATCH)))) {
                    response.sendRedirect(url + SMSOTPConstants.RESEND_CODE
                            + SMSOTPUtils.isEnableResendCode(context) + SMSOTPConstants.ERROR_MESSAGE
                            + SMSOTPConstants.ERROR_CODE_MISMATCH);
                } else if (StringUtils.isNotEmpty((String) context.getProperty(SMSOTPConstants.TOKEN_EXPIRED))) {
                    response.sendRedirect(url + SMSOTPConstants.RESEND_CODE
                            + SMSOTPUtils.isEnableResendCode(context) + SMSOTPConstants.ERROR_MESSAGE + SMSOTPConstants
                            .TOKEN_EXPIRED_VALUE);
                } else {
                    response.sendRedirect(url + SMSOTPConstants.RESEND_CODE
                            + SMSOTPUtils.isEnableResendCode(context) + SMSOTPConstants.RETRY_PARAMS);
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed: An IOException was caught. ", e);
        }
    }

    /**
     * Get the screen value for configured screen attribute.
     *
     * @param context the AuthenticationContext
     * @return screenValue
     * @throws AuthenticationFailedException
     */
    private String getScreenValue(AuthenticationContext context) throws AuthenticationFailedException {

        String screenValue;
        String username = String.valueOf(context.getProperty(SMSOTPConstants.USER_NAME));
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
        try {
            screenValue = getScreenAttribute(context, userRealm, tenantAwareUsername);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the screen attribute for the user " +
                    tenantAwareUsername + " from user store. ", e);
        }
        return screenValue;
    }

    /**
     * Redirect the user to mobile number request page.
     *
     * @param response    the HttpServletResponse
     * @param context     the AuthenticationContext
     * @param queryParams the queryParams
     * @throws AuthenticationFailedException
     */
    private void redirectToMobileNoReqPage(HttpServletResponse response, AuthenticationContext context,
                                           String queryParams) throws AuthenticationFailedException {

        boolean isEnableMobileNoUpdate = SMSOTPUtils.isEnableMobileNoUpdate(context);
        if (isEnableMobileNoUpdate) {
            String loginPage = SMSOTPUtils.getMobileNumberRequestPage(context);
            try {
                String url = getURL(loginPage, queryParams);
                if (log.isDebugEnabled()) {
                    log.debug("Redirecting to mobile number request page : " + url);
                }
                response.sendRedirect(url);
            } catch (IOException e) {
                throw new AuthenticationFailedException("Authentication failed!. An IOException was caught. ", e);
            }
        } else {
            throw new AuthenticationFailedException("Authentication failed!. Update mobile no in your profile.");
        }
    }

    /**
     * Process the response of the SMSOTP end-point.
     *
     * @param request  the HttpServletRequest
     * @param response the HttpServletResponse
     * @param context  the AuthenticationContext
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String userToken = request.getParameter(SMSOTPConstants.CODE);
        String contextToken = (String) context.getProperty(SMSOTPConstants.OTP_TOKEN);
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
        if (StringUtils.isEmpty(request.getParameter(SMSOTPConstants.CODE))) {
            throw new InvalidCredentialsException("Code cannot not be null");
        }
        if (Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND))) {
            if (log.isDebugEnabled()) {
                log.debug("Retrying to resend the OTP");
            }
            throw new InvalidCredentialsException("Retrying to resend the OTP");
        }
        if (userToken.equals(contextToken)) {
            processValidUserToken(context, authenticatedUser);
        } else if (SMSOTPUtils.getBackupCode(context).equals("true")) {
            checkWithBackUpCodes(context, userToken, authenticatedUser);
        } else {
            context.setProperty(SMSOTPConstants.CODE_MISMATCH, true);
            throw new AuthenticationFailedException("Code mismatch");
        }
    }

    private void processValidUserToken(AuthenticationContext context, AuthenticatedUser authenticatedUser) throws
            AuthenticationFailedException {
        Optional<Object> tokenValidityTime = Optional.ofNullable(context.getProperty(SMSOTPConstants.
                TOKEN_VALIDITY_TIME));
        if (!tokenValidityTime.isPresent() || !NumberUtils.isNumber((String) tokenValidityTime.get())) {
            log.error("TokenExpiryTime property is not configured in application-authentication.xml or SMS OTP " +
                    "Authenticator UI");
            context.setSubject(authenticatedUser);
            return;
        }

        Optional<Object> otpTokenSentTime = Optional.ofNullable(context.getProperty(SMSOTPConstants.
                SENT_OTP_TOKEN_TIME));
        if (!otpTokenSentTime.isPresent() || !NumberUtils.isNumber((String) otpTokenSentTime.get())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find OTP sent time");
            }
            throw new AuthenticationFailedException("Internal Error Occurred");
        }

        long elapsedTokenTime = System.currentTimeMillis() - Long.parseLong((String) otpTokenSentTime.get());

        if (elapsedTokenTime <= (Long.parseLong((String) tokenValidityTime.get()) * 1000)) {
            context.setSubject(authenticatedUser);
        } else {
            context.setProperty(SMSOTPConstants.TOKEN_EXPIRED, SMSOTPConstants.TOKEN_EXPIRED_VALUE);
            throw new AuthenticationFailedException("OTP code has expired");
        }
    }

    /**
     * If user forgets the mobile, then user can use the back up codes to authenticate the user.
     *
     * @param context           the AuthenticationContext
     * @param userToken         the userToken
     * @param authenticatedUser the name of authenticatedUser
     * @throws AuthenticationFailedException
     */
    private void checkWithBackUpCodes(AuthenticationContext context, String userToken,
                                      AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        String[] savedOTPs = null;
        String username = context.getProperty(SMSOTPConstants.USER_NAME).toString();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = getUserRealm(username);
        try {
            if (userRealm != null) {
                UserStoreManager userStoreManager = userRealm.getUserStoreManager();
                if (userStoreManager != null) {
                    String savedOTPString = userStoreManager
                            .getUserClaimValue(tenantAwareUsername, SMSOTPConstants.SAVED_OTP_LIST, null);
                    if (StringUtils.isNotEmpty(savedOTPString)) {
                        savedOTPs = savedOTPString.split(",");
                    }
                }
            }
            // Check whether there is any backup OTPs and return.
            if (ArrayUtils.isEmpty(savedOTPs)) {
                if (log.isDebugEnabled()) {
                    log.debug("The claim " + SMSOTPConstants.SAVED_OTP_LIST + " does not contain any values");
                }
                throw new AuthenticationFailedException("The claim " + SMSOTPConstants.SAVED_OTP_LIST +
                        " does not contain any values");
            }
            if (isBackUpCodeValid(savedOTPs, userToken)) {
                if (log.isDebugEnabled()) {
                    log.debug("Found saved backup SMS OTP for user :" + authenticatedUser);
                }
                context.setSubject(authenticatedUser);
                savedOTPs = (String[]) ArrayUtils.removeElement(savedOTPs, userToken);
                userRealm.getUserStoreManager().setUserClaimValue(tenantAwareUsername,
                        SMSOTPConstants.SAVED_OTP_LIST, String.join(",", savedOTPs), null);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User entered OTP :" + userToken + " does not match with any of the saved " +
                            "backup codes");
                }
                context.setProperty(SMSOTPConstants.CODE_MISMATCH, true);
                throw new AuthenticationFailedException("Verification Error due to Code " + userToken + " " +
                        "mismatch.", authenticatedUser);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user claim for OTP list for user : " +
                    authenticatedUser, e);
        }
    }

    private boolean isBackUpCodeValid(String[] savedOTPs, String userToken) {

        if (StringUtils.isEmpty(userToken)) {
            return false;
        }
        // Check whether the usertoken exists in the saved backup OTP list.
        for (String value : savedOTPs) {
            if (value.equals(userToken))
                return true;
        }
        return false;
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param username the Username
     * @return the userRealm
     * @throws AuthenticationFailedException
     */
    private UserRealm getUserRealm(String username) throws AuthenticationFailedException {

        UserRealm userRealm = null;
        try {
            if (StringUtils.isNotEmpty(username)) {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm. ", e);
        }
        return userRealm;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    public String getFriendlyName() {

        return SMSOTPConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    public String getName() {

        return SMSOTPConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property smsUrl = new Property();
        smsUrl.setName(SMSOTPConstants.SMS_URL);
        smsUrl.setDisplayName("SMS URL");
        smsUrl.setRequired(false);
        smsUrl.setDescription("Enter client sms url value. If the phone number and text message are in URL, " +
                "specify them as $ctx.num and $ctx.msg");
        smsUrl.setDisplayOrder(0);
        configProperties.add(smsUrl);

        Property httpMethod = new Property();
        httpMethod.setName(SMSOTPConstants.HTTP_METHOD);
        httpMethod.setDisplayName("HTTP Method");
        httpMethod.setRequired(false);
        httpMethod.setDescription("Enter the HTTP Method used by the SMS API");
        httpMethod.setDisplayOrder(1);
        configProperties.add(httpMethod);

        Property headers = new Property();
        headers.setName(SMSOTPConstants.HEADERS);
        headers.setDisplayName("HTTP Headers");
        headers.setRequired(false);
        headers.setDescription("Enter the headers used by the API separated by comma, with the Header name and value " +
                "separated by \":\". If the phone number and text message are in Headers, specify them as $ctx.num and $ctx.msg");
        headers.setDisplayOrder(2);
        configProperties.add(headers);

        Property payload = new Property();
        payload.setName(SMSOTPConstants.PAYLOAD);
        payload.setDisplayName("HTTP Payload");
        payload.setRequired(false);
        payload.setDescription("Enter the HTTP Payload used by the SMS API. If the phone number and text message are " +
                "in Payload, specify them as $ctx.num and $ctx.msg");
        payload.setDisplayOrder(3);
        configProperties.add(payload);

        Property httpResponse = new Property();
        httpResponse.setName(SMSOTPConstants.HTTP_RESPONSE);
        httpResponse.setDisplayName("HTTP Response Code");
        httpResponse.setRequired(false);
        httpResponse.setDescription("Enter the HTTP response code the API sends upon successful call. Leave empty if unknown");
        httpResponse.setDisplayOrder(4);
        configProperties.add(httpResponse);

        Property showErrorInfo = new Property();
        showErrorInfo.setName(SMSOTPConstants.SHOW_ERROR_INFO);
        showErrorInfo.setDisplayName("Show Detailed Error Information");
        showErrorInfo.setRequired(false);
        showErrorInfo.setDescription("Enter \"true\" if detailed error information from SMS provider needs to be " +
                "displayed in the UI");
        showErrorInfo.setDisplayOrder(5);
        configProperties.add(showErrorInfo);

        Property valuesToBeMasked = new Property();
        valuesToBeMasked.setName(SMSOTPConstants.VALUES_TO_BE_MASKED_IN_ERROR_INFO);
        valuesToBeMasked.setDisplayName("Mask values in Error Info");
        valuesToBeMasked.setRequired(false);
        valuesToBeMasked.setDescription("Enter comma separated Values to be masked by * in the detailed error messages");
        valuesToBeMasked.setDisplayOrder(6);
        configProperties.add(valuesToBeMasked);

        return configProperties;
    }

    /**
     * Get the connection and proceed with SMS API's rest call.
     *
     * @param httpConnection  the connection
     * @param context         the authenticationContext
     * @param headerString    the header string
     * @param payload         the payload
     * @param httpResponse    the http response
     * @param encodedMobileNo the encoded mobileNo
     * @param smsMessage      the sms message
     * @param otpToken        the token
     * @param httpMethod      the http method
     * @return true or false
     * @throws AuthenticationFailedException
     */
    private boolean getConnection(HttpURLConnection httpConnection, AuthenticationContext context, String headerString,
                                  String payload, String httpResponse, String encodedMobileNo, String smsMessage,
                                  String otpToken, String httpMethod) throws AuthenticationFailedException {

        try {
            httpConnection.setDoInput(true);
            httpConnection.setDoOutput(true);
            String[] headerArray;
            if (StringUtils.isNotEmpty(headerString)) {
                if (log.isDebugEnabled()) {
                    log.debug("Processing HTTP headers since header string is available");
                }
                headerString = headerString.trim().replaceAll("\\$ctx.num", encodedMobileNo).replaceAll("\\$ctx.msg",
                        smsMessage + otpToken);
                headerArray = headerString.split(",");
                for (String header : headerArray) {
                    String[] headerElements = header.split(":");
                    if (headerElements.length > 1) {
                        httpConnection.setRequestProperty(headerElements[0], headerElements[1]);
                    } else {
                        log.info("Either header name or value not found. Hence not adding header which contains " +
                                headerElements[0]);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No configured headers found. Header string is empty");
                }
            }

            // Processing HTTP Method
            if (log.isDebugEnabled()) {
                log.debug("Configured http method is " + httpMethod);
            }

            if (SMSOTPConstants.GET_METHOD.equalsIgnoreCase(httpMethod)) {
                httpConnection.setRequestMethod(SMSOTPConstants.GET_METHOD);

            } else if (SMSOTPConstants.POST_METHOD.equalsIgnoreCase(httpMethod)) {
                httpConnection.setRequestMethod(SMSOTPConstants.POST_METHOD);
                if (StringUtils.isNotEmpty(payload)) {
                    payload = payload.replaceAll("\\$ctx.num", encodedMobileNo).replaceAll("\\$ctx.msg", smsMessage +
                            otpToken);

                    OutputStreamWriter writer = null;
                    try {
                        writer = new OutputStreamWriter(httpConnection.getOutputStream(), SMSOTPConstants.CHAR_SET_UTF_8);
                        writer.write(payload);
                    } catch (IOException e) {
                        throw new AuthenticationFailedException("Error while posting payload message ", e);
                    } finally {
                        if (writer != null) {
                            writer.close();
                        }
                    }
                }
            }
            if (StringUtils.isNotEmpty(httpResponse)) {
                if (httpResponse.trim().equals(String.valueOf(httpConnection.getResponseCode()))) {
                    if (log.isDebugEnabled()) {
                        log.debug("Code is successfully sent to the mobile and recieved expected response code : " +
                                httpResponse);
                    }
                    return true;
                }
            } else {
                if (httpConnection.getResponseCode() == 200 || httpConnection.getResponseCode() == 201
                        || httpConnection.getResponseCode() == 202) {
                    if (log.isDebugEnabled()) {
                        log.debug("Code is successfully sent to the mobile. Relieved HTTP response code is : " +
                                httpConnection.getResponseCode());
                    }
                    return true;
                } else {
                    context.setProperty(SMSOTPConstants.ERROR_CODE, httpConnection.getResponseCode() + " : " +
                            httpConnection.getResponseMessage());
                    String content = getSanitizedErrorInfo(httpConnection, context, encodedMobileNo);

                    log.error("Error while sending SMS: error code is " + httpConnection.getResponseCode()
                            + " and error message is " + httpConnection.getResponseMessage());
                    context.setProperty(SMSOTPConstants.ERROR_INFO, content);
                    return false;
                }
            }
        } catch (MalformedURLException e) {
            throw new AuthenticationFailedException("Invalid URL ", e);
        } catch (ProtocolException e) {
            throw new AuthenticationFailedException("Error while setting the HTTP method ", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while setting the HTTP response ", e);
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
        }
        return false;
    }


    private String getSanitizedErrorInfo(HttpURLConnection httpConnection, AuthenticationContext context, String
            encodedMobileNo) throws IOException, AuthenticationFailedException {

        String contentRaw = readContent(httpConnection);

        String screenValue = getScreenValue(context);
        if (StringUtils.isEmpty(screenValue)) {
            int noOfDigits = 0;
            if ((SMSOTPUtils.getNoOfDigits(context)) != null) {
                noOfDigits = Integer.parseInt(SMSOTPUtils.getNoOfDigits(context));
            }
            screenValue = getMaskedValue(context, encodedMobileNo, noOfDigits);
        }
        String content = contentRaw.replace(encodedMobileNo, screenValue);
        URLDecoder decoder = new URLDecoder();
        String decodedMobileNo = decoder.decode(encodedMobileNo);
        content = content.replace(decodedMobileNo, screenValue);
        content = maskConfiguredValues(context, content);
        context.setProperty(SMSOTPConstants.ERROR_INFO, content);

        String errorContent = content;
        if (log.isDebugEnabled()) {
            errorContent = contentRaw;
        }
        log.error(String.format("Following Error occurred while sending SMS for user: %s, %s", String.valueOf(context
                .getProperty(SMSOTPConstants.USER_NAME)), errorContent));

        return content;
    }

    private String maskConfiguredValues(AuthenticationContext context, String content) {

        String valuesToMask = context.getAuthenticatorProperties().get(SMSOTPConstants
                .VALUES_TO_BE_MASKED_IN_ERROR_INFO);
        if (StringUtils.isNotEmpty(valuesToMask)) {
            String[] values = valuesToMask.split(MASKING_VALUE_SEPARATOR);
            for (String val : values) {
                content = content.replaceAll(val, getMaskedValue(context, val, 0));
            }

        }
        return content;
    }

    private String readContent(HttpURLConnection httpConnection) throws IOException {

        BufferedReader br = new BufferedReader(new InputStreamReader(httpConnection.getErrorStream()));
        StringBuilder sb = new StringBuilder();
        String output;
        while ((output = br.readLine()) != null) {
            sb.append(output);
        }
        return sb.toString();
    }

    /**
     * Proceed with SMS API's rest call.
     *
     * @param context      the AuthenticationContext
     * @param smsUrl       the smsUrl
     * @param httpMethod   the httpMethod
     * @param headerString the headerString
     * @param payload      the payload
     * @param httpResponse the httpResponse
     * @param mobile       the mobile number
     * @param otpToken     the OTP token
     * @return true or false
     * @throws IOException
     * @throws AuthenticationFailedException
     */
    public boolean sendRESTCall(AuthenticationContext context, String smsUrl, String httpMethod,
                                String headerString, String payload, String httpResponse, String mobile,
                                String otpToken) throws IOException, AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Preparing message for sending out");
        }
        HttpURLConnection httpConnection;
        boolean connection;
        String smsMessage = SMSOTPConstants.SMS_MESSAGE;
        String encodedMobileNo = URLEncoder.encode(mobile, CHAR_SET_UTF_8);
        smsUrl = smsUrl.replaceAll("\\$ctx.num", encodedMobileNo).replaceAll("\\$ctx.msg",
                smsMessage.replaceAll("\\s", "+") + otpToken);
        URL smsProviderUrl = null;
        try {
            smsProviderUrl = new URL(smsUrl);
        } catch (MalformedURLException e) {
            log.error("Error while parsing SMS provider URL: " + smsUrl, e);
            if (SMSOTPUtils.useInternalErrorCodes(context)) {
                context.setProperty(SMSOTPConstants.ERROR_CODE, SMSOTPConstants.ErrorMessage.MALFORMED_URL.getCode());
            } else {
                context.setProperty(SMSOTPConstants.ERROR_CODE, "The SMS URL does not conform to URL specification");
            }
            return false;
        }
        String subUrl = smsProviderUrl.getProtocol();
        if (subUrl.equals(SMSOTPConstants.HTTPS)) {
            httpConnection = (HttpsURLConnection) smsProviderUrl.openConnection();
            connection = getConnection(httpConnection, context, headerString, payload, httpResponse, encodedMobileNo,
                    smsMessage, otpToken, httpMethod);
        } else {
            httpConnection = (HttpURLConnection) smsProviderUrl.openConnection();
            connection = getConnection(httpConnection, context, headerString, payload, httpResponse, encodedMobileNo,
                    smsMessage, otpToken, httpMethod);
        }
        return connection;
    }

    /**
     * Get a screen value from the user attributes. If you need to show n digits of mobile number or any other user
     * attribute value in the UI.
     *
     * @param userRealm the user Realm
     * @param username  the username
     * @return the screen attribute
     * @throws UserStoreException
     */
    public String getScreenAttribute(AuthenticationContext context, UserRealm userRealm, String username)
            throws UserStoreException, AuthenticationFailedException {

        String screenUserAttributeParam;
        String screenUserAttributeValue = null;
        String screenValue = null;
        int noOfDigits = 0;

        screenUserAttributeParam = SMSOTPUtils.getScreenUserAttribute(context);
        if (screenUserAttributeParam != null) {
            screenUserAttributeValue = userRealm.getUserStoreManager()
                    .getUserClaimValue(username, screenUserAttributeParam, null);
        }

        if (screenUserAttributeValue != null) {
            if ((SMSOTPUtils.getNoOfDigits(context)) != null) {
                noOfDigits = Integer.parseInt(SMSOTPUtils.getNoOfDigits(context));
            }
            screenValue = getMaskedValue(context, screenUserAttributeValue, noOfDigits);
        }
        return screenValue;
    }

    private String getMaskedValue(AuthenticationContext context, String screenUserAttributeValue, int noOfDigits) {

        String screenValue;
        String hiddenScreenValue;

        int screenAttributeLength = screenUserAttributeValue.length();
        if (SMSOTPConstants.BACKWARD.equals(SMSOTPUtils.getDigitsOrder(context))) {
            screenValue = screenUserAttributeValue.substring(screenAttributeLength - noOfDigits,
                    screenAttributeLength);
            hiddenScreenValue = screenUserAttributeValue.substring(0, screenAttributeLength - noOfDigits);
            for (int i = 0; i < hiddenScreenValue.length(); i++) {
                screenValue = ("*").concat(screenValue);
            }
        } else {
            screenValue = screenUserAttributeValue.substring(0, noOfDigits);
            hiddenScreenValue = screenUserAttributeValue.substring(noOfDigits, screenAttributeLength);
            for (int i = 0; i < hiddenScreenValue.length(); i++) {
                screenValue = screenValue.concat("*");
            }
        }
        return screenValue;
    }

    /**
     * We can reuse this method once the improvements done into the eventing and notification handler in IS.
     */
    protected void triggerNotification(String userName, String tenantDomain, String userStoreDomainName, String mobileNumber, String otpCode) {

        String eventName = TRIGGER_SMS_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);

        properties.put(SMSOTPConstants.ATTRIBUTE_SMS_SENT_TO, mobileNumber);
        properties.put(SMSOTPConstants.OTP_TOKEN, otpCode);

        properties.put(SMSOTPConstants.TEMPLATE_TYPE, SMSOTPConstants.EVENT_NAME);
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            SMSOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (Exception e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage();
            //We are not throwing any exception from here, because this event notification should not break the main
            // flow.
            log.warn(errorMsg);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
        }
    }

    private String getHttpErrorResponseCode(String errorMsg) {

        String errorCode = errorMsg;
        if (StringUtils.contains(errorCode, ":")) {
            errorCode = errorCode.split(":")[0];
        }
        return StringUtils.trim(errorCode);
    }
}
