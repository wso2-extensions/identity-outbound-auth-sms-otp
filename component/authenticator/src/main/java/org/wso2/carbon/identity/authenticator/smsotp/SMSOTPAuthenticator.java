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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Authenticator of SMSOTP
 */
public class SMSOTPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(SMSOTPAuthenticator.class);
    AuthenticationContext authContext = new AuthenticationContext();
    Map<String, String> newAuthenticatorProperties;
    private String otpToken;
    private String mobile;
    private String smsUrl = "";
    private String clientId = "";
    private String clientSecret = "";
    private String fullUrl = "";

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
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
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String resourceName = SMSOTPConstants.PROPERTIES_FILE;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Properties prop = new Properties();

        InputStream resourceStream = loader.getResourceAsStream(resourceName);
        try {
            prop.load(resourceStream);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Can not find the file", e);
        }

        newAuthenticatorProperties = context
                .getAuthenticatorProperties();
        newAuthenticatorProperties.put("username", prop.getProperty("username"));
        newAuthenticatorProperties.put("password", prop.getProperty("password"));
        newAuthenticatorProperties.put("from", prop.getProperty("from"));
        newAuthenticatorProperties.put("text", prop.getProperty("text"));
        context.setAuthenticatorProperties(newAuthenticatorProperties);

        OneTimePassword token = new OneTimePassword();
        String secret = OneTimePassword.getRandomNumber(SMSOTPConstants.SECRET_KEY_LENGTH);
        otpToken = token.generateToken(secret, "" + SMSOTPConstants.NUMBER_BASE, SMSOTPConstants.NUMBER_DIGIT);
        Object myToken = otpToken;
        authContext.setProperty(otpToken, myToken);

        Map<String, String> authenticatorProperties = context
                .getAuthenticatorProperties();
        clientId = authenticatorProperties
                .get(SMSOTPConstants.API_KEY);
        clientSecret = authenticatorProperties
                .get(SMSOTPConstants.API_SECRET);
        smsUrl = authenticatorProperties.get(SMSOTPConstants.SMS_URL);

        String loginPage=ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                .replace("authenticationendpoint/login.do", SMSOTPConstants.LOGIN_PAGE);
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(),
                context.getContextIdentifier());
        String retryParam = "";

        if (context.isRetrying()) {
            retryParam = SMSOTPConstants.RETRY_PARAMS;
        }

        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) + "&authenticators=" +
                    getName() + retryParam);
        } catch (IOException e) {
            log.error("Authentication failed!", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

        String username = null;
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet())
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {

                username = String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                break;
            }
        if (username != null) {
            UserRealm userRealm = null;
            try {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            } catch (Exception e) {
                throw new AuthenticationFailedException("Cannot find the user realm", e);
            }
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                try {
                    mobile = userRealm.getUserStoreManager().getUserClaimValue(username, SMSOTPConstants.MOBILE_CLAIM, null).toString();
                } catch (UserStoreException e) {
                    log.error("Cannot find the user claim for mobile", e);
                    throw new AuthenticationFailedException("Cannot find the user claim for mobile " + e.getMessage(), e);
                }
            }
        }

        if (!StringUtils.isEmpty(clientId) && !StringUtils.isEmpty(clientSecret) && !StringUtils.isEmpty(mobile)) {
            fullUrl = setUrl();
            try {
                if (!sendRESTCall(smsUrl, fullUrl)) {
                    log.error("Unable to send the code");
                    throw new AuthenticationFailedException("Unable to send the code");
                }
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while sending the HTTP request", e);
                }
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
            context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier("an authorised user"));
        } else {
            log.error("Code Mismatch");
            throw new AuthenticationFailedException("Code mismatch");
        }
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

        Property clientId = new Property();
        clientId.setName(SMSOTPConstants.API_KEY);
        clientId.setDisplayName("API Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter client identifier value");
        configProperties.add(clientId);

        Property smsUrl = new Property();
        smsUrl.setName(SMSOTPConstants.SMS_URL);
        smsUrl.setDisplayName("SMS URL");
        smsUrl.setRequired(true);
        smsUrl.setDescription("Enter client sms url value");
        configProperties.add(smsUrl);

        Property clientSecret = new Property();
        clientSecret.setName(SMSOTPConstants.API_SECRET);
        clientSecret.setDisplayName("API Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        configProperties.add(clientSecret);

        return configProperties;
    }

    public boolean sendRESTCall(String url, String urlParameters) throws IOException {
        HttpsURLConnection connection = null;
        try {
            URL smsProviderUrl = new URL(url + urlParameters);
            connection = (HttpsURLConnection) smsProviderUrl.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod(SMSOTPConstants.HTTP_METHOD);
            if (connection.getResponseCode() == 200) {
                if (log.isDebugEnabled()) {
                    log.debug("Code is successfully sent to your mobile number");
                }
                return true;
            }
            connection.disconnect();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid URL", e);
            }
            throw new MalformedURLException();
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while setting the HTTP method", e);
            }
            throw new ProtocolException();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting the HTTP response", e);
            }
            throw new IOException();
        } finally {
            connection.disconnect();
        }
        return false;
    }

    public String setUrl() {
        fullUrl = newAuthenticatorProperties.get("username") + clientId + newAuthenticatorProperties.get("password") + clientSecret +
                newAuthenticatorProperties.get("from") + mobile + newAuthenticatorProperties.get("text") + otpToken;
        return fullUrl;
    }
}

