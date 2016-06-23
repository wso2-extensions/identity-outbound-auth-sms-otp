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
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.net.HttpURLConnection;
import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of SMSOTP
 */
public class SMSOTPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(SMSOTPAuthenticator.class);
    AuthenticationContext authContext = new AuthenticationContext();
    private String otpToken;
    private String mobile;
    private String savedOTPString;

    /**
     * Check whether the authentication or logout request can be handled by the
     * authenticator
     */
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside SMSOTPAuthenticator canHandle method");
        }
        return StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.CODE));
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        OneTimePassword token = new OneTimePassword();
        String secret = OneTimePassword.getRandomNumber(SMSOTPConstants.SECRET_KEY_LENGTH);
        otpToken = token.generateToken(secret, "" + SMSOTPConstants.NUMBER_BASE, SMSOTPConstants.NUMBER_DIGIT);
        Object myToken = otpToken;
        authContext.setProperty(otpToken, myToken);

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String smsUrl = authenticatorProperties.get(SMSOTPConstants.SMS_URL);
        String httpMethod = authenticatorProperties.get(SMSOTPConstants.HTTP_METHOD);
        String headerString = authenticatorProperties.get(SMSOTPConstants.HEADERS);
        String payload = authenticatorProperties.get(SMSOTPConstants.PAYLOAD);
        String httpResponse = authenticatorProperties.get(SMSOTPConstants.HTTP_RESPONSE);

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                .replace("authenticationendpoint/login.do", SMSOTPConstants.LOGIN_PAGE);
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String retryParam = "";
        if (context.isRetrying()) {
            retryParam = SMSOTPConstants.RETRY_PARAMS;
        }
        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) + "&authenticators="
                    + getName() + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication failed!", e);
        }
        String username = getUsername(context);
        if (username != null) {
            UserRealm userRealm = getUserRealm(username);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                try {
                    mobile = userRealm.getUserStoreManager()
                            .getUserClaimValue(username, SMSOTPConstants.MOBILE_CLAIM, null);
                } catch (UserStoreException e) {
                    throw new AuthenticationFailedException("Cannot find the user claim for mobile " + e.getMessage(),
                            e);
                }
            }
        }

        if (StringUtils.isEmpty(mobile)) {
            throw new AuthenticationFailedException("Mobile Number is null");
        }
        if (StringUtils.isEmpty(smsUrl)) {
            throw new AuthenticationFailedException("SMS URL is null");
        } else if (StringUtils.isEmpty(httpMethod)) {
            throw new AuthenticationFailedException("HTTP Method is null");
        } else {
            try {
                if (!sendRESTCall(smsUrl, httpMethod, headerString, payload, httpResponse)) {
                    throw new AuthenticationFailedException("Unable to send the code");
                }
            } catch (IOException e) {
                throw new AuthenticationFailedException("Error while sending the HTTP request", e);
            }
        }
    }

    /**
     * Process the response of the SMSOTP end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String userToken = request.getParameter(SMSOTPConstants.CODE);
        String contextToken = (String) authContext.getProperty(otpToken);
        if (userToken.equals(contextToken)) {
            context.setSubject(AuthenticatedUser
                    .createLocalAuthenticatedUserFromSubjectIdentifier("an authorised user"));
        } else {
            String username = getUsername(context);
            if (username != null) {
                UserRealm userRealm = getUserRealm(username);
                username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
                if (userRealm != null) {
                    try {
                        savedOTPString = userRealm.getUserStoreManager()
                                .getUserClaimValue(username, SMSOTPConstants.SAVED_OTP_LIST, null);
                    } catch (UserStoreException e) {
                        throw new AuthenticationFailedException(
                                "Cannot find the user claim for OTP list " + e.getMessage(), e);
                    }
                }
            }
            if (savedOTPString != null && savedOTPString.contains(userToken)) {
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
            } else if (savedOTPString == null) {
                throw new AuthenticationFailedException("The claim " + SMSOTPConstants.SAVED_OTP_LIST +
                        " does not contain any values");
            } else {
                throw new AuthenticationFailedException("Verification Error due to Code Mismatch");
            }
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
     * Get the username of the logged in User
     */
    private String getUsername(AuthenticationContext context) {
        String username = null;
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet())
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null
                    && context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username = String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                break;
            }
        return username;
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
        headers.setDescription("Enter the headers used by the API seperated by comma, with the Header name and value " +
                "seperated by \":\". If the phone number and text message are in Headers, specify them as $ctx.num and $ctx.msg");
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
                                String httpResponse) throws IOException, AuthenticationFailedException {

        HttpURLConnection httpConnection = null;
        HttpsURLConnection httpsConnection = null;
        String smsMessage = SMSOTPConstants.SMS_MESSAGE;
        try {
            smsUrl = smsUrl.replaceAll("\\$ctx.num", mobile).replaceAll("\\$ctx.msg",
                    smsMessage.replaceAll("\\s", "+") + otpToken);
            URL smsProviderUrl = new URL(smsUrl);
            String subUrl = smsProviderUrl.getProtocol();
            if (subUrl.equals("https")) {
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
                        writer = new OutputStreamWriter(httpsConnection.getOutputStream(), "UTF-8");
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
                        writer = new OutputStreamWriter(httpConnection.getOutputStream(), "UTF-8");
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
}
