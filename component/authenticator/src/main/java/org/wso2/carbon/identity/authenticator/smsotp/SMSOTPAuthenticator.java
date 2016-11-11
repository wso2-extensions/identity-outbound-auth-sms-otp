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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticator;
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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.smsotp.exception.SMSOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of SMS OTP
 */
public class SMSOTPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(SMSOTPAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside SMSOTPAuthenticator canHandle method");
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
     * initiate the authentication request.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            String username = null;
            AuthenticatedUser authenticatedUser;
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            Map<String, String> smsOTPParameters = getAuthenticatorConfig().getParameterMap();
            String tenantDomain = context.getTenantDomain();
            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.AUTHENTICATOR_NAME);
            if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
            }

            String mobile = null;
            FederatedAuthenticator federatedAuthenticator = new FederatedAuthenticator();
            federatedAuthenticator.getUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty(SMSOTPConstants.USER_NAME));
            authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
            // find the authenticated user.
            if (authenticatedUser == null) {
                throw new AuthenticationFailedException
                        ("Authentication failed!. Cannot proceed further without identifying the user");
            }

            boolean isSMSOTPMandatory = Boolean.parseBoolean(smsOTPParameters
                    .get(SMSOTPConstants.IS_SMSOTP_MANDATORY));
            boolean isSMSOTPDisabledByUser = SMSOTPUtils.isSMSOTPDisableForLocalUser(username, context);
            boolean isEnableMobileNoUpdate = Boolean.parseBoolean(smsOTPParameters
                    .get(SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE));
            boolean isEnableResendCode = Boolean.parseBoolean(smsOTPParameters
                    .get(SMSOTPConstants.IS_ENABLED_RESEND));

            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String retryParam = "";
            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.AUTHENTICATOR_NAME);
            // SMS OTP authentication is mandatory and user doesn't disable SMS OTP claim in user's profile.
            if (isSMSOTPMandatory && isSMSOTPDisabledByUser) {
                // that Enable the SMS OTP in user's Profile. Cannot proceed further without SMS OTP authentication.
                String errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                        .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.ERROR_PAGE);
                response.sendRedirect(response.encodeRedirectURL(errorPage + ("?" + queryParams))
                        + SMSOTPConstants.AUTHENTICATORS + getName() + retryParam);

            } else if (isSMSOTPDisabledByUser) {
                //the authentication flow happens with basic authentication.
                StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
                if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                    federatedAuthenticator.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
                    context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.BASIC);
                } else {
                    federatedAuthenticator.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
                    context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.FEDERETOR);
                }

            } else {
                //the authentication flow happens with sms otp authentication.
                String login = smsOTPParameters.get(SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL);
                String loginPage = "";
                if (StringUtils.isNotEmpty(login)) {
                    loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                            .replace(SMSOTPConstants.LOGIN_PAGE, login);
                } else {
                    loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                            .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.SMS_LOGIN_PAGE);
                }
                boolean isRetryEnabled = Boolean.parseBoolean(smsOTPParameters
                        .get(SMSOTPConstants.IS_ENABLED_RETRY));
                if (context.isRetrying() && !Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND))) {
                    if (isRetryEnabled) {
                        retryParam = SMSOTPConstants.RETRY_PARAMS;
                        response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                + SMSOTPConstants.AUTHENTICATORS + getName() + SMSOTPConstants.RESEND_CODE
                                + isEnableResendCode + retryParam);
                    } else {
                        throw new AuthenticationFailedException("Authentication failed! Code is Mismatch");
                    }
                } else {
                    if (username != null) {
                        UserRealm userRealm = getUserRealm(username);
                        username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
                        if (userRealm != null) {
                            try {
                                if (request.getParameter(SMSOTPConstants.MOBILE_NUMBER) != null) {
                                    if (!context.isRetrying()) {
                                        Map<String, String> attributes = new HashMap<String, String>();
                                        attributes.put(SMSOTPConstants.MOBILE_CLAIM, request
                                                .getParameter(SMSOTPConstants.MOBILE_NUMBER));
                                        SMSOTPUtils.updateUserAttribute(username, attributes);
                                    }
                                }
                                if (Boolean.parseBoolean(smsOTPParameters.get(SMSOTPConstants.IS_MOBILE_CLAIM))) {
                                    mobile = userRealm.getUserStoreManager()
                                            .getUserClaimValue(username, SMSOTPConstants.MOBILE_CLAIM, null);
                                }
                                // User does not have a phone number.
                                if (StringUtils.isEmpty(mobile)) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("User has not previously registered a mobile number: " + username);
                                    }
                                    if (isEnableMobileNoUpdate) {
                                        loginPage = smsOTPParameters.get(SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE);
                                        try {
                                            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?"
                                                    + queryParams)) + SMSOTPConstants.AUTHENTICATORS + getName()
                                                    + retryParam);
                                        } catch (IOException e) {
                                            throw new AuthenticationFailedException("Authentication failed!", e);
                                        }
                                    } else {
                                        throw new AuthenticationFailedException("Authentication failed!. Update mobile "
                                                + "no in your profile");
                                    }
                                } else {
                                    try {
                                        // One time password is generated and stored in the context.
                                        OneTimePassword token = new OneTimePassword();
                                        String secret = OneTimePassword.getRandomNumber(SMSOTPConstants.SECRET_KEY_LENGTH);
                                        String otpToken = token.generateToken(secret, ""
                                                + SMSOTPConstants.NUMBER_BASE, SMSOTPConstants.NUMBER_DIGIT);
                                        context.setProperty(SMSOTPConstants.OTP_TOKEN, otpToken);

                                        //Get the values of the sms provider related api parameters.
                                        String smsUrl = authenticatorProperties.get(SMSOTPConstants.SMS_URL);
                                        String httpMethod = authenticatorProperties.get(SMSOTPConstants.HTTP_METHOD);
                                        String headerString = authenticatorProperties.get(SMSOTPConstants.HEADERS);
                                        String payload = authenticatorProperties.get(SMSOTPConstants.PAYLOAD);
                                        String httpResponse = authenticatorProperties.get(SMSOTPConstants.HTTP_RESPONSE);

                                        response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                                + SMSOTPConstants.AUTHENTICATORS + getName() + retryParam);
                                        if (!sendRESTCall(smsUrl, httpMethod, headerString, payload, httpResponse, mobile,
                                                otpToken)) {
                                            throw new AuthenticationFailedException("Unable to send the code");
                                        }
                                    } catch (IOException e) {
                                        throw new AuthenticationFailedException("Error while sending the HTTP request", e);
                                    }
                                }
                            } catch (UserStoreException e) {
                                throw new AuthenticationFailedException("Cannot find the user claim for mobile "
                                        + e.getMessage(), e);
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication failed!", e);
        } catch (SMSOTPException e) {
            throw new AuthenticationFailedException("Failed to get the parameters from authentication xml fie", e);
        }
    }

    /**
     * Process the response of the SMSOTP end-point.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        Map<String, String> smsOTPParameters = getAuthenticatorConfig().getParameterMap();
        String userToken = request.getParameter(SMSOTPConstants.CODE);
        String contextToken = (String) context.getProperty(SMSOTPConstants.OTP_TOKEN);
        String savedOTPString = null;
        try {
            String username = context.getProperty("username").toString();
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
                context.setSubject(AuthenticatedUser
                        .createLocalAuthenticatedUserFromSubjectIdentifier("an authorised user"));
            } else if (smsOTPParameters.get(SMSOTPConstants.BACKUP_CODE).equals("false")) {
                throw new AuthenticationFailedException("Code mismatch");
            } else {
                if (username != null) {
                    UserRealm userRealm = getUserRealm(username);
                    username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
                    if (userRealm != null) {
                        savedOTPString = userRealm.getUserStoreManager()
                                .getUserClaimValue(username, SMSOTPConstants.SAVED_OTP_LIST, null);
                    }
                }
                if (savedOTPString == null) {
                    throw new AuthenticationFailedException("The claim " + SMSOTPConstants.SAVED_OTP_LIST +
                            " does not contain any values");
                } else {
                    if (savedOTPString.contains(userToken)) {
                        context.setSubject(AuthenticatedUser
                                .createLocalAuthenticatedUserFromSubjectIdentifier("an authorised user"));
                        savedOTPString = savedOTPString.replaceAll(userToken, "").replaceAll(",,", ",");
                        if (username != null) {
                            UserRealm userRealm = getUserRealm(username);
                            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
                            if (userRealm != null) {
                                try {
                                    userRealm.getUserStoreManager().setUserClaimValue(username, SMSOTPConstants.SAVED_OTP_LIST,
                                            savedOTPString, null);
                                } catch (UserStoreException e) {
                                    log.error("Unable to set the user claim for OTP List for user " + username, e);
                                }
                            }
                        }
                    } else {
                        throw new AuthenticationFailedException("Verification Error due to Code Mismatch");
                    }
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user claim for OTP list " + e.getMessage(), e);
        }
    }

    /**
     * Get the user realm of the logged in user
     */
    private UserRealm getUserRealm(String username) throws AuthenticationFailedException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Cannot find the user realm", e);
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
        return null;
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
        smsUrl.setRequired(true);
        smsUrl.setDescription("Enter client sms url value. If the phone number and text message are in URL, " +
                "specify them as $ctx.num and $ctx.msg");
        smsUrl.setDisplayOrder(0);
        configProperties.add(smsUrl);

        Property httpMethod = new Property();
        httpMethod.setName(SMSOTPConstants.HTTP_METHOD);
        httpMethod.setDisplayName("HTTP Method");
        httpMethod.setRequired(true);
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

        return configProperties;
    }

    public boolean sendRESTCall(String smsUrl, String httpMethod, String headerString, String payload,
                                String httpResponse, String mobile, String otpToken) throws IOException,
            AuthenticationFailedException {

        HttpURLConnection httpConnection = null;
        HttpsURLConnection httpsConnection = null;
        String smsMessage = SMSOTPConstants.SMS_MESSAGE;
        try {
            smsUrl = smsUrl.replaceAll("\\$ctx.num", mobile).replaceAll("\\$ctx.msg",
                    smsMessage.replaceAll("\\s", "+") + otpToken);
            URL smsProviderUrl = new URL(smsUrl);
            String subUrl = smsProviderUrl.getProtocol();
            if (subUrl.equals(SMSOTPConstants.HTTPS)) {
                httpsConnection = (HttpsURLConnection) smsProviderUrl.openConnection();
                httpsConnection.setDoInput(true);
                httpsConnection.setDoOutput(true);
                String[] headerList;
                if (!headerString.isEmpty()) {
                    headerString = headerString.trim().replaceAll("\\$ctx.num", mobile).replaceAll("\\$ctx.msg",
                            smsMessage + otpToken);
                    headerList = headerString.split(",");
                    for (String aHeaderList : headerList) {
                        String[] header = aHeaderList.split(":");
                        httpsConnection.setRequestProperty(header[0], header[1]);
                    }
                }
                if (httpMethod.toUpperCase().equals(SMSOTPConstants.GET_METHOD)) {
                    httpsConnection.setRequestMethod(SMSOTPConstants.GET_METHOD);
                } else if (httpMethod.toUpperCase().equals(SMSOTPConstants.POST_METHOD)) {
                    httpsConnection.setRequestMethod(SMSOTPConstants.POST_METHOD);
                    if (!payload.isEmpty()) {
                        payload = payload.replaceAll("\\$ctx.num", mobile).replaceAll("\\$ctx.msg", smsMessage + otpToken);
                    }
                    OutputStreamWriter writer = null;
                    try {
                        writer = new OutputStreamWriter(httpsConnection.getOutputStream(), SMSOTPConstants.CHAR_SET);
                        writer.write(payload);
                    } catch (IOException e) {
                        throw new AuthenticationFailedException("Error while posting payload message", e);
                    } finally {
                        if (writer != null) {
                            writer.close();
                        }
                    }
                }
                if (!httpResponse.isEmpty()) {
                    if (httpResponse.trim().equals(String.valueOf(httpsConnection.getResponseCode()))) {
                        if (log.isDebugEnabled()) {
                            log.debug("Code is successfully sent to the mobile");
                        }
                        return true;
                    }
                } else {
                    if (httpsConnection.getResponseCode() == 200 || httpsConnection.getResponseCode() == 201
                            || httpsConnection.getResponseCode() == 202) {
                        if (log.isDebugEnabled()) {
                            log.debug("Code is successfully sent to the mobile");
                        }
                        return true;
                    }
                }
            } else {
                httpConnection = (HttpURLConnection) smsProviderUrl.openConnection();
                httpConnection.setDoInput(true);
                httpConnection.setDoOutput(true);
                String[] headerList;
                if (!headerString.isEmpty()) {
                    headerString = headerString.trim().replaceAll("\\$ctx.num", mobile).replaceAll("\\$ctx.msg",
                            smsMessage + otpToken);
                    headerList = headerString.split(",");
                    for (String aHeaderList : headerList) {
                        String[] header = aHeaderList.split(":");
                        httpConnection.setRequestProperty(header[0], header[1]);
                    }
                }
                if (httpMethod.toUpperCase().equals(SMSOTPConstants.GET_METHOD)) {
                    httpConnection.setRequestMethod(SMSOTPConstants.GET_METHOD);
                } else if (httpMethod.toUpperCase().equals(SMSOTPConstants.POST_METHOD)) {
                    httpConnection.setRequestMethod(SMSOTPConstants.POST_METHOD);
                    if (!payload.isEmpty()) {
                        payload = payload.replaceAll("\\$ctx.num", mobile).replaceAll("\\$ctx.msg", smsMessage + otpToken);
                    }
                    OutputStreamWriter writer = null;
                    try {
                        writer = new OutputStreamWriter(httpConnection.getOutputStream(), SMSOTPConstants.CHAR_SET);
                        writer.write(payload);
                    } catch (IOException e) {
                        throw new AuthenticationFailedException("Error while posting payload message", e);
                    } finally {
                        if (writer != null) {
                            writer.close();
                        }
                    }
                }
                if (!httpResponse.isEmpty()) {
                    if (httpResponse.trim().equals(String.valueOf(httpConnection.getResponseCode()))) {
                        if (log.isDebugEnabled()) {
                            log.debug("Code is successfully sent to the mobile");
                        }
                        return true;
                    }
                } else {
                    if (httpConnection.getResponseCode() == 200 || httpConnection.getResponseCode() == 201
                            || httpConnection.getResponseCode() == 202) {
                        if (log.isDebugEnabled()) {
                            log.debug("Code is successfully sent to the mobile");
                        }
                        return true;
                    } else {
                        log.error(httpConnection.getErrorStream().toString());
                        return false;
                    }
                }
            }
        } catch (MalformedURLException e) {
            throw new AuthenticationFailedException("Invalid URL", e);
        } catch (ProtocolException e) {
            throw new AuthenticationFailedException("Error while setting the HTTP method", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while setting the HTTP response", e);
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
            if (httpsConnection != null) {
                httpsConnection.disconnect();
            }
        }
        return false;
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    private void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser) {
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        context.setSubject(authenticatedUser);
    }
}
