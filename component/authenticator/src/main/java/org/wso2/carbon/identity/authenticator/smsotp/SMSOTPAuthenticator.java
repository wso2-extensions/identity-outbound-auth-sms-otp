/*
 *  Copyright (c) 2015-2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
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

import com.google.gson.Gson;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.slf4j.MDC;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.smsotp.exception.SMSOTPException;
import org.wso2.carbon.identity.authenticator.smsotp.internal.SMSOTPServiceDataHolder;
import org.wso2.carbon.identity.captcha.connector.recaptcha.SMSOTPCaptchaConnector;
import org.wso2.carbon.identity.captcha.exception.CaptchaException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.CHAR_SET_UTF_8;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.CONTENT_TYPE;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.ERROR_MESSAGE_DETAILS;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.ERROR_USER_RESEND_COUNT_EXCEEDED;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.JSON_CONTENT_TYPE;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.LogConstants.ActionIDs.SEND_SMS_OTP;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.LogConstants.OUTBOUND_AUTH_SMSOTP_SERVICE;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.MASKING_VALUE_SEPARATOR;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.MOBILE_NUMBER_REGEX;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.OTP_RESEND_ATTEMPTS;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.POST_METHOD;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.RESEND;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.XML_CONTENT_TYPE;

import static java.util.Base64.getEncoder;
import static org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants.REQUESTED_USER_MOBILE;

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
            log.debug("Inside SMSOTPAuthenticator canHandle method and check the existence of mobile number and " +
                    "otp code");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(SMSOTPConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.CODE))
                || StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.MOBILE_NUMBER)));
    }

    @Override
    public boolean canHandleRequestFromMultiOptionStep(HttpServletRequest request, AuthenticationContext context) {

        // Since all SMSOTP as 1FA, basic, and IDF authenticators has the username parameter in the request, we need to
        // use the currentAuthenticator context to identify if the request is coming from SMSOTP authenticator.
        // For basic and IDF authenticators, the currentAuthenticator context will be null.
        boolean canHandleRequest = canHandle(request) ||
                (StringUtils.isNotBlank(request.getParameter(SMSOTPConstants.USER_NAME)) &&
                        getName().equalsIgnoreCase(context.getCurrentAuthenticator()));
        if (canHandleRequest) {
            log.debug("SMSOTPAuthenticator can handle the request from multi-option step.");
        } else {
            log.debug("SMSOTPAuthenticator cannot handle the request from multi-option step.");
        }
        return canHandleRequest;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // If the current authenticator is not SMS OTP, then set the flow to not retrying which could have been
        // set from other authenticators and not cleared.
        if (!SMSOTPConstants.AUTHENTICATOR_NAME.equals(context.getCurrentAuthenticator())) {
            context.setRetrying(false);
        }
        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.MOBILE_NUMBER))) {
            // if the request comes with MOBILE_NUMBER, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } else if (StringUtils.isEmpty(request.getParameter(SMSOTPConstants.CODE)) &&
                !Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND))) {
            AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
            if (authenticatedUser == null) {
                if (StringUtils.isEmpty(request.getParameter(SMSOTPConstants.USER_NAME))) {
                    redirectUserToIDF(response, context);
                    context.setProperty(SMSOTPConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                } else {
                    authenticatedUser = resolveUserFromRequest(request, context);
                    authenticatedUser = resolveUserFromUserStore(authenticatedUser);
                    setResolvedUserInContext(context, authenticatedUser);
                }
            } else if (isPreviousIdPAuthenticationFlowHandler(context)) {
                boolean isUserResolved = FrameworkUtils.getIsUserResolved(context);
                // Resolve the user from user store if the user is not resolved in IDF handler.
                if (!isUserResolved) {
                    authenticatedUser = resolveUserFromUserStore(authenticatedUser);
                }
                setResolvedUserInContext(context, authenticatedUser);
            }
            if (authenticatedUser != null) {
                // if the request comes with code, it will go through this flow.
                initiateAuthenticationRequest(request, response, context);
                publishPostSMSOTPGeneratedEvent(request, context);
                if (context.getProperty(SMSOTPConstants.AUTHENTICATION)
                        .equals(SMSOTPConstants.AUTHENTICATOR_NAME)) {
                    // if the request comes with authentication is SMSOTP, it will go through this flow.
                    return AuthenticatorFlowStatus.INCOMPLETE;
                } else {
                    // if the request comes with authentication is basic, complete the flow.
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
            } else {
                log.debug("The user does not exist in the user stores.");
                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(), context.getContextIdentifier());
                redirectToErrorPage(response, context, queryParams, SMSOTPConstants.ERROR_USER_NOT_FOUND);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        } else if (Boolean.parseBoolean(request.getParameter(RESEND))) {
            if (!SMSOTPUtils.isEnableResendCode(context)) {
                throw new InvalidCredentialsException("Resend code is not enabled for this authenticator");
            }
            AuthenticatorFlowStatus authenticatorFlowStatus = super.process(request, response, context);
            publishPostSMSOTPGeneratedEvent(request, context);
            return authenticatorFlowStatus;
        } else {
            AuthenticatorFlowStatus authenticatorFlowStatus = super.process(request, response, context);
            publishPostSMSOTPValidatedEvent(request, context);
            return authenticatorFlowStatus;
        }
    }

    /**
     * Initiate the authentication request.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            String username = null;
            Object propertiesFromLocal = null;
            String usecase;
            AuthenticatedUser authenticatedUser = null;
            Map<String, String> smsOTParameters = getAuthenticatorConfig().getParameterMap();
            String mobileNumber;
            String tenantDomain = context.getTenantDomain();
            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.AUTHENTICATOR_NAME);
            if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
                propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
            }
            if (propertiesFromLocal != null || tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
                usecase = smsOTParameters.get(SMSOTPConstants.USE_CASE);
            } else {
                usecase = (String) context.getProperty(SMSOTPConstants.USE_CASE);
            }

            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            // This multi option URI is used to navigate back to multi option page to select a different
            // authentication option from SMS OTP pages.
            String multiOptionURI = getMultiOptionURIQueryParam(request);
            if (StringUtils.isNotEmpty(multiOptionURI)) {
                queryParams += multiOptionURI;
            }

            if (StringUtils.isEmpty(usecase)) {
                // Iterate through the steps to identify from which step the user need to extracted
                for (StepConfig stepConfig : stepConfigMap.values()) {
                    authenticatedUser = stepConfig.getAuthenticatedUser();
                    if (authenticatedUser != null && isPreviousIdPAuthenticationFlowHandler(context)) {
                        authenticatedUser = resolveUserFromUserStore(authenticatedUser);
                        if (authenticatedUser != null) {
                            username = authenticatedUser.toFullQualifiedUsername();
                        }
                    }
                    if (authenticatedUser != null && stepConfig.isSubjectAttributeStep()) {
                        username = authenticatedUser.toFullQualifiedUsername();
                        break;
                    }
                    if (username == null && isSMSOTPAsFirstFactor(context)) {
                        if (!(context.isRetrying()
                                && Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND)))) {
                            context.setProperty(SMSOTPConstants.CODE_MISMATCH, true);
                        }
                        redirectToSMSOTPLoginPage(response, request, context, queryParams);
                        return;
                    } else if (username == null) {
                        log.debug("Cannot find the subject attributed step with authenticated user.");
                        throw new AuthenticationFailedException
                                ("Authentication failed. Cannot find the subject attributed step with authenticated user.");
                    }
                }
                context.setProperty(SMSOTPConstants.USER_NAME, username);
                context.setProperty(SMSOTPConstants.AUTHENTICATED_USER, authenticatedUser);
            } else {
                FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
                username = String.valueOf(context.getProperty(SMSOTPConstants.USER_NAME));
                authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
            }

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
            String errorPage = getErrorPage(context);
            // SMS OTP authentication is mandatory and user doesn't disable SMS OTP claim in user's profile.
            if (isSMSOTPMandatory) {
                if (log.isDebugEnabled()) {
                    log.debug("SMS OTP is mandatory. Hence processing in mandatory path");
                }
                processSMSOTPMandatoryCase(context, request, response, queryParams, username, isUserExists);
            } else if (isUserExists && !SMSOTPUtils.isSMSOTPDisableForLocalUser(username, context)) {
                boolean isResendCode = Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND));
                if ((context.isRetrying() && !isResendCode && !isMobileNumberUpdateFailed(context))
                        || (SMSOTPUtils.isLocalUser(context) && SMSOTPUtils.isAccountLocked(authenticatedUser))) {
                    if (log.isDebugEnabled()) {
                        log.debug("Triggering SMS OTP retry flow");
                    }
                    checkStatusCode(response, context, queryParams, errorPage);
                } else if (context.isRetrying() && isResendCode && !isMobileNumberUpdateFailed(context)) {
                    handleResendOTP(request, response, context, queryParams, username, errorPage);
                } else {
                    mobileNumber = getMobileNumber(request, response, context, username, queryParams);
                    proceedWithOTP(request, response, context, errorPage, mobileNumber, queryParams, username);
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
     * Get MultiOptionURI query parameter from the request.
     * @param request Http servlet request.
     * @return MultiOptionURI query parameter.
     */
    private String getMultiOptionURIQueryParam(HttpServletRequest request) {

        if (request != null) {
            String multiOptionURI = request.getParameter(SMSOTPConstants.MULTI_OPTION_URI);
            if (StringUtils.isNotEmpty(multiOptionURI)) {
                return "&" + SMSOTPConstants.MULTI_OPTION_URI + "="
                        + Encode.forUriComponent(multiOptionURI);
            }
        }
        return StringUtils.EMPTY;
    }

    /**
     * Get the mobile number from user's profile to send an otp.
     *
     * @param request     The HttpServletRequest.
     * @param response    The HttpServletResponse.
     * @param context     The AuthenticationContext.
     * @param username    The Username.
     * @param queryParams The queryParams.
     * @return the mobile number
     * @throws AuthenticationFailedException
     * @throws SMSOTPException
     */
    private String getMobileNumber(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationContext context, String username,
                                   String queryParams) throws AuthenticationFailedException, SMSOTPException {

        String mobileNumber = SMSOTPUtils.getMobileNumberForUsername(username);
        if (StringUtils.isEmpty(mobileNumber)) {
            String requestMobile = request.getParameter(SMSOTPConstants.MOBILE_NUMBER);
            if (StringUtils.isBlank(requestMobile) && !isMobileNumberUpdateFailed(context) && isCodeMismatch(context)) {
                mobileNumber = String.valueOf(context.getProperty(SMSOTPConstants.REQUESTED_USER_MOBILE));
            } else if (StringUtils.isBlank(requestMobile)) {
                if (log.isDebugEnabled()) {
                    log.debug("User has not registered a mobile number: " + username);
                }
                redirectToMobileNoReqPage(response, context, queryParams);
            } else {
                context.setProperty(SMSOTPConstants.REQUESTED_USER_MOBILE, requestMobile);
                mobileNumber = requestMobile;
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
        try {
            return buildURL(loginPage, SMSOTPConstants.SMS_LOGIN_PAGE);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building SMS OTP login page URL.", e);
        }
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
        try {
            return buildURL(errorPage, SMSOTPConstants.ERROR_PAGE);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building SMS OTP error page URL.", e);
        }
    }

    /**
     * Get the mobile number request page from authentication.xml file or use the request page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the mobile number request page
     * @throws AuthenticationFailedException
     */
    private String getMobileNumberRequestPage(AuthenticationContext context) throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OUTBOUND_AUTH_SMSOTP_SERVICE, SEND_SMS_OTP);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context))
                    .resultMessage("Requesting mobile number for SMS OTP.");
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        String mobileNumberRequestPage = SMSOTPUtils.getMobileNumberRequestPage(context);
        if (StringUtils.isEmpty(mobileNumberRequestPage)) {
            mobileNumberRequestPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.MOBILE_NO_REQ_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used");
            }
        }
        try {
            return buildURL(mobileNumberRequestPage, SMSOTPConstants.MOBILE_NO_REQ_PAGE);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building mobile number request page URL.", e);
        }
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
     * @throws UserStoreException
     */
    private void updateMobileNumberForUsername(AuthenticationContext context, HttpServletRequest request,
                                               String username, String tenantDomain)
            throws SMSOTPException, UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Updating mobile number for user : " + username);
        }
        Map<String, String> attributes = new HashMap<>();
        attributes.put(SMSOTPConstants.MOBILE_CLAIM, String.valueOf(context.getProperty(SMSOTPConstants.REQUESTED_USER_MOBILE)));
        SMSOTPUtils.updateUserAttribute(MultitenantUtils.getTenantAwareUsername(username), attributes,
                tenantDomain);
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
        boolean isResendCode = Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND));
        if (context.isRetrying() && !isResendCode && !isMobileNumberUpdateFailed(context)) {
            if (log.isDebugEnabled()) {
                log.debug("Trigger retry flow when it is not request for resending OTP or it is not mobile number update failure");
            }
            checkStatusCode(response, context, queryParams, errorPage);
        } else if (context.isRetrying() && isResendCode && !isMobileNumberUpdateFailed(context)) {
            handleResendOTP(request, response, context, queryParams, username, errorPage);
        } else {
            processSMSOTPFlow(context, request, response, isUserExists, username, queryParams, tenantDomain, errorPage);
        }
    }

    private void proceedOTPWithFederatedMobileNumber(AuthenticationContext context, HttpServletRequest request,
                                                     HttpServletResponse response,
                                                     String username, String queryParams,
                                                     boolean sendOtpToFederatedMobile)
            throws AuthenticationFailedException {

        try {
            String federatedMobileAttributeKey;
            String mobile = null;
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
            String previousStepAuthenticator = stepConfig.getAuthenticatedAutenticator().getName();
            if (sendOtpToFederatedMobile) {
                federatedMobileAttributeKey = getFederatedMobileAttributeKey(context, previousStepAuthenticator);
                if (StringUtils.isEmpty(federatedMobileAttributeKey)) {
                    federatedMobileAttributeKey = getFederatedMobileAttributeKey(context, getName());
                }
                Map<ClaimMapping, String> userAttributes = context.getCurrentAuthenticatedIdPs().values().
                        iterator().next().getUser().getUserAttributes();
                for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                    String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
                    String value = entry.getValue();
                    if (key.equals(federatedMobileAttributeKey)) {
                        mobile = String.valueOf(value);
                        proceedWithOTP(request, response, context, getErrorPage(context), mobile, queryParams,
                                username);
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
     * Handle resend OTP flow considering maximum number of resend attempts of the user.
     *
     * @param request     HttpServletRequest.
     * @param response    HttpServletResponse.
     * @param context     AuthenticationContext.
     * @param queryParams QueryParams.
     * @param username    Username.
     * @param errorPage   ErrorPage.
     * @throws AuthenticationFailedException If an error occurred while handling resend OTP flow.
     * @throws SMSOTPException If an error occurred while handling resend OTP flow.
     */
    private void handleResendOTP(HttpServletRequest request, HttpServletResponse response,
                                 AuthenticationContext context, String queryParams, String username, String errorPage)
            throws SMSOTPException, AuthenticationFailedException {

        Optional<Integer> maxResendAttempts = SMSOTPUtils.getMaxResendAttempts(context);
        if (maxResendAttempts.isPresent()) {
            int currentUserResendAttempts = context.getProperty(OTP_RESEND_ATTEMPTS) != null
                    ? Integer.parseInt(context.getProperty(OTP_RESEND_ATTEMPTS).toString()) : 0;
            if (currentUserResendAttempts >= maxResendAttempts.get()) {
                redirectToErrorPage(response, context, queryParams, ERROR_USER_RESEND_COUNT_EXCEEDED);
                return;
            }
        }

        updateUserResendAttempts(context);
        String mobileNumber = getMobileNumber(request, response, context, username, queryParams);
        proceedWithOTP(request, response, context, errorPage, mobileNumber, queryParams, username);
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
                mobileNumber = getMobileNumber(request, response, context, username, queryParams);
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
                String loginPage = getMobileNumberRequestPage(context);
                try {
                    String url = getURL(loginPage, queryParams);
                    String mobileNumberPatternViolationError = SMSOTPConstants.MOBILE_NUMBER_PATTERN_POLICY_VIOLATED;
                    String mobileNumberPattern =
                            context.getAuthenticatorProperties().get(SMSOTPConstants.MOBILE_NUMBER_REGEX);
                    if (StringUtils.isNotEmpty(mobileNumberPattern)) {
                        // Check for regex is violation error message configured in idp configuration.
                        if (StringUtils.isNotEmpty(context.getAuthenticatorProperties()
                                .get(SMSOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE))) {
                            mobileNumberPatternViolationError = context.getAuthenticatorProperties()
                                    .get(SMSOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE);
                        }
                        // Send the response with encoded regex pattern and error message.
                        response.sendRedirect(FrameworkUtils
                                .appendQueryParamsStringToUrl(url, SMSOTPConstants.MOBILE_NUMBER_REGEX_PATTERN_QUERY +
                                        getEncoder().encodeToString(context.getAuthenticatorProperties()
                                                .get(MOBILE_NUMBER_REGEX)
                                                .getBytes()) +
                                        SMSOTPConstants.MOBILE_NUMBER_PATTERN_POLICY_FAILURE_ERROR_MESSAGE_QUERY +
                                        getEncoder().encodeToString(mobileNumberPatternViolationError.getBytes())));
                    } else {
                        response.sendRedirect(url);
                    }
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
            proceedOTPWithFederatedMobileNumber(context, request, response, username, queryParams,
                    SMSOTPUtils.sendOtpToFederatedMobile(context));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("SMS OTP is mandatory. But couldn't find a mobile number.");
            }
            redirectToErrorPage(response, context, queryParams, SMSOTPConstants.SEND_OTP_DIRECTLY_DISABLE);
        }
        proceedWithOTP(request, response, context, errorPage, mobileNumber, queryParams, username);
    }

    /**
     * Proceed with One Time Password.
     *
     * @param request      the HttpServletRequest
     * @param response     the HttpServletResponse
     * @param context      the AuthenticationContext
     * @param errorPage    the errorPage
     * @param mobileNumber the mobile number
     * @param queryParams  the queryParams
     * @param username     the Username
     * @throws AuthenticationFailedException
     */
    private void proceedWithOTP(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context,
                                String errorPage, String mobileNumber, String queryParams, String username)
            throws AuthenticationFailedException {

        if (StringUtils.isEmpty(mobileNumber)) {
            return;
        }

        String screenValue;
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        boolean isEnableResendCode = SMSOTPUtils.isEnableResendCode(context);
        String loginPage = getLoginPage(context);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
        try {
            boolean isCharInOTP = isAlphaNumericOTPEnabled(authenticatorProperties, context);
            context.setProperty(SMSOTPConstants.IS_CHAR_IN_OTP, isCharInOTP);

            long expiryTime = getSMSOTPExpiryTime(authenticatorProperties, context);
            context.setProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME,
                    Long.toString(expiryTime));

            int numOfDigitsInOTP = getSMSOTPLength(authenticatorProperties, context);
            context.setProperty(SMSOTPConstants.SMS_OTP_LENGTH, numOfDigitsInOTP);

            String otpToken = generateOTP(context);
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
                String serviceProviderName = context.getServiceProviderName();
                triggerNotification(authenticatedUser.getUserName(), authenticatedUser.getTenantDomain(),
                        authenticatedUser.getUserStoreDomain(), mobileNumber, otpToken, serviceProviderName,
                        expiryTime);
            }

            if (!connectionResult) {
                String retryParam;
                if (context.getProperty(SMSOTPConstants.ERROR_CODE) != null) {
                    String errorCode = context.getProperty(SMSOTPConstants.ERROR_CODE).toString();
                    // If UseInternalErrorCodes is configured as true, then http response error codes will be mapped
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
                url += getCaptchaParams(request, context);
                context.setProperty(SMSOTPConstants.IS_REDIRECT_TO_SMS_OTP, "true");
                response.sendRedirect(url);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while sending the HTTP request. ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from user store. ", e);
        }
    }

    /**
     * Redirect the flow to SMS OTP login page to enter the OTP.
     *
     * @param response    HTTP Servlet Response.
     * @param request     HTTP Servlet Request.
     * @param context     Authentication Context.
     * @param queryParams Query Params.
     * @throws AuthenticationFailedException If error occurred while redirecting to SMS OTP login page.
     */
    private void redirectToSMSOTPLoginPage(HttpServletResponse response, HttpServletRequest request,
                                           AuthenticationContext context,
                                           String queryParams) throws AuthenticationFailedException {
        try {
            // Full url of the login page
            String smsOTPLoginPage = getLoginPage(context);
            if (log.isDebugEnabled()) {
                log.debug("The SMSOTP login page url is " + smsOTPLoginPage);
            }
            if (StringUtils.isEmpty(smsOTPLoginPage)) {
                String authenticationEndpointURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
                smsOTPLoginPage = authenticationEndpointURL.replace(SMSOTPConstants.LOGIN_PAGE,
                        SMSOTPConstants.SMS_LOGIN_PAGE);
                if (log.isDebugEnabled()) {
                    log.debug("The default authentication endpoint URL " + authenticationEndpointURL +
                            "is replaced by default sms otp login page " + smsOTPLoginPage);
                }
                if (!smsOTPLoginPage.contains(SMSOTPConstants.SMS_LOGIN_PAGE)) {
                    throw new AuthenticationFailedException("The default authentication page is not replaced by default"
                            + " sms otp page");
                }
            }
            String url = getURL(smsOTPLoginPage, queryParams);
            if (context.isRetrying()
                    && !Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND))) {
                url = url + SMSOTPConstants.RETRY_PARAMS;
            }
            url += getCaptchaParams(request, context);
            context.setProperty(SMSOTPConstants.IS_REDIRECT_TO_SMS_OTP, "true");
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed: An IOException was caught while " +
                    "redirecting to login page. ", e);
        }
    }

    /**
     * Checks whether alpha numeric OTP is enabled.
     *
     * @param authenticatorProperties Map of authenticator properties.
     * @param context                 Authentication context.
     * @return True if alpha numeric OTP is enabled.
     */
    private boolean isAlphaNumericOTPEnabled (Map<String, String> authenticatorProperties,
                                              AuthenticationContext context) {

        String onlyNumericCharactersAllowed = authenticatorProperties.get(SMSOTPConstants.SMS_OTP_NUMERIC_OTP);
        if (StringUtils.isNotEmpty(onlyNumericCharactersAllowed)) {
            return !Boolean.parseBoolean(onlyNumericCharactersAllowed);
        }
        return SMSOTPUtils.isEnableAlphanumericToken(context);
    }

    /**
     * Retrieve the SMS OTP length.
     *
     * @param authenticatorProperties Map of authenticator properties.
     * @return int value of the SMS OTP length.
     */
    private int getSMSOTPLength(Map<String, String> authenticatorProperties, AuthenticationContext context) {

        int numOfDigitsInOTP = SMSOTPConstants.NUMBER_DIGIT;
        if (StringUtils.isNotEmpty(
                authenticatorProperties.get(SMSOTPConstants.SMS_OTP_LENGTH))) {
            int numDigitsInProperties = Integer.parseInt(authenticatorProperties
                    .get(SMSOTPConstants.SMS_OTP_LENGTH));
            if (numDigitsInProperties >= SMSOTPConstants.SMS_OTP_MIN_LENGTH
                    && numDigitsInProperties <= SMSOTPConstants.SMS_OTP_MAX_LENGTH) {
                numOfDigitsInOTP = numDigitsInProperties;
            }
        } else if (SMSOTPUtils.getTokenLength(context) != null) {
            String tokenLength = SMSOTPUtils.getTokenLength(context);
            if (StringUtils.isNumeric(tokenLength)) {
                numOfDigitsInOTP = Integer.parseInt(tokenLength);
            }
        }
        return numOfDigitsInOTP;
    }

    /**
     * Retrieve the SMS OTP expiry time in milliseconds.
     *
     * @param authenticatorProperties Map of authenticator properties.
     * @return long value of the SMS OTP expiry time.
     */
    private long getSMSOTPExpiryTime(Map<String, String> authenticatorProperties, AuthenticationContext context) {

        long expiryTime = Long.parseLong(SMSOTPConstants.OTP_EXPIRE_TIME_DEFAULT);
        if (StringUtils.isNotEmpty(
                authenticatorProperties.get(SMSOTPConstants.SMS_OTP_EXPIRY_TIME))) {
            int expiryTimeInMinutes = Integer.parseInt(authenticatorProperties
                    .get(SMSOTPConstants.SMS_OTP_EXPIRY_TIME));
            if (expiryTimeInMinutes <= SMSOTPConstants.SMS_OTP_MAX_EXPIRY_TIME
                    && expiryTimeInMinutes >= SMSOTPConstants.SMS_OTP_MIN_EXPIRY_TIME) {
                // In the SMS OTP configuration in the UI, the expiry time is configured in minutes.
                // Therefore, it is converted to milliseconds.
                expiryTime = expiryTimeInMinutes * 60 * 1000;
            }
        } else if (SMSOTPUtils.getTokenExpiryTime(context) != null) {
            String tokenExpiryTime = SMSOTPUtils.getTokenExpiryTime(context);
            if (StringUtils.isNumeric(tokenExpiryTime)) {
                // In the SMS OTP configuration in the toml file, the expiry time is configured in seconds.
                // Therefore, it is converted to milliseconds.
                expiryTime = Long.parseLong(tokenExpiryTime) * 1000;
            }
        }
        return expiryTime;
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
        AuthenticatedUser authenticatedUser =
                (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
        String url = getURL(loginPage, queryParams);
        if (StringUtils.isNotEmpty(getScreenValue(context))) {
            url = url + SMSOTPConstants.SCREEN_VALUE + getScreenValue(context);
        }
        try {
            if (SMSOTPUtils.isLocalUser(context) && SMSOTPUtils.isAccountLocked(authenticatedUser)) {
                boolean showAuthFailureReason = SMSOTPUtils.isShowAuthFailureReason(context);
                String retryParam;
                if (showAuthFailureReason) {
                    long unlockTime = getUnlockTimeInMilliSeconds(authenticatedUser);
                    long timeToUnlock = unlockTime - System.currentTimeMillis();
                    if (timeToUnlock > 0) {
                        queryParams += "&unlockTime=" + Math.round((double) timeToUnlock / 1000 / 60);
                    }
                    retryParam = SMSOTPConstants.ERROR_USER_ACCOUNT_LOCKED;
                } else {
                    retryParam = SMSOTPConstants.RETRY_PARAMS;
                }
                redirectToErrorPage(response, context, queryParams, retryParam);
            } else if (context.getProperty(FrameworkConstants.USER_TENANT_DOMAIN_MISMATCH) != null &&
                    (Boolean) context.getProperty(FrameworkConstants.USER_TENANT_DOMAIN_MISMATCH)) {
                context.setProperty(FrameworkConstants.USER_TENANT_DOMAIN_MISMATCH, false);
                redirectToErrorPage(response, context, queryParams, SMSOTPConstants.ERROR_TENANT_MISMATCH);
            } else if (isRetryEnabled) {
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
            String loginPage = getMobileNumberRequestPage(context);
            try {
                String url = getURL(loginPage, queryParams);
                if (log.isDebugEnabled()) {
                    log.debug("Redirecting to mobile number request page : " + url);
                }
                String mobileNumberPatternViolationError = SMSOTPConstants.MOBILE_NUMBER_PATTERN_POLICY_VIOLATED;
                String mobileNumberPattern =
                        context.getAuthenticatorProperties().get(SMSOTPConstants.MOBILE_NUMBER_REGEX);
                if (isMobileNumberUpdateFailed(context)) {
                    url = FrameworkUtils.appendQueryParamsStringToUrl(url, SMSOTPConstants.RETRY_PARAMS);
                    if (context.getProperty(SMSOTPConstants.PROFILE_UPDATE_FAILURE_REASON) != null) {
                        String failureReason = String.valueOf(
                                context.getProperty(SMSOTPConstants.PROFILE_UPDATE_FAILURE_REASON));
                        String urlEncodedFailureReason = URLEncoder.encode(failureReason, CHAR_SET_UTF_8);
                        String failureQueryParam = ERROR_MESSAGE_DETAILS + urlEncodedFailureReason;
                        url = FrameworkUtils.appendQueryParamsStringToUrl(url, failureQueryParam);
                    }
                }
                if (StringUtils.isNotEmpty(mobileNumberPattern)) {
                    // Check for regex is violation error message configured in idp configuration.
                    if (StringUtils.isNotEmpty(context.getAuthenticatorProperties()
                            .get(SMSOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE))) {
                        mobileNumberPatternViolationError = context.getAuthenticatorProperties()
                                .get(SMSOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE);
                    }
                    // Send the response with encoded regex pattern and error message.
                    response.sendRedirect(FrameworkUtils
                            .appendQueryParamsStringToUrl(url, SMSOTPConstants.MOBILE_NUMBER_REGEX_PATTERN_QUERY +
                                    getEncoder().encodeToString(context.getAuthenticatorProperties()
                                            .get(SMSOTPConstants.MOBILE_NUMBER_REGEX)
                                            .getBytes()) +
                                    SMSOTPConstants.MOBILE_NUMBER_PATTERN_POLICY_FAILURE_ERROR_MESSAGE_QUERY +
                                    getEncoder().encodeToString(mobileNumberPatternViolationError.getBytes())));
                } else {
                    response.sendRedirect(url);
                }
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

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
        boolean isLocalUser = SMSOTPUtils.isLocalUser(context);
        if (authenticatedUser == null) {
            String errorMessage = "Could not find an Authenticated user in the context.";
            throw new AuthenticationFailedException(errorMessage);
        }
        if (isPreviousIdPAuthenticationFlowHandler(context)) {
            authenticatedUser = resolveUserFromUserStore(authenticatedUser);
        }

        SequenceConfig sequenceConfig = context.getSequenceConfig();
        // Tenant domain validation for non SaaS applications.
        if (isLocalUser && !sequenceConfig.getApplicationConfig().isSaaSApp()) {
            String spTenantDomain = context.getTenantDomain();
            String userTenantDomain = authenticatedUser.getTenantDomain();
            if (StringUtils.isNotEmpty(userTenantDomain)) {
                if (StringUtils.isNotEmpty(spTenantDomain) && !spTenantDomain.equals(userTenantDomain)) {
                    context.setProperty(FrameworkConstants.USER_TENANT_DOMAIN_MISMATCH, true);
                    throw new AuthenticationFailedException("Service Provider tenant domain must be " +
                            "equal to user tenant domain for non-SaaS applications", context.getSubject());
                }
            }
        }

        if (isLocalUser && SMSOTPUtils.isAccountLocked(authenticatedUser)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Authentication failed since authenticated user: %s,  account is locked.",
                        authenticatedUser));
            }
            context.setProperty(SMSOTPConstants.ACCOUNT_LOCKED, true);
            throw new AuthenticationFailedException("User account is locked.");
        }

        String userToken = request.getParameter(SMSOTPConstants.CODE);
        String contextToken = (String) context.getProperty(SMSOTPConstants.OTP_TOKEN);
        if (StringUtils.isEmpty(request.getParameter(SMSOTPConstants.CODE))) {
            throw new InvalidCredentialsException("Code cannot not be null");
        }
        if (Boolean.parseBoolean(request.getParameter(SMSOTPConstants.RESEND))) {
            if (log.isDebugEnabled()) {
                log.debug("Retrying to resend the OTP");
            }
            throw new InvalidCredentialsException("Retrying to resend the OTP");
        }

        if (context.getProperty(SMSOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE) != null) {
            context.setProperty(SMSOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "false");
        }

        boolean succeededAttempt = false;
        if (userToken.equals(contextToken)) {
            context.removeProperty(SMSOTPConstants.CODE_MISMATCH);
            processValidUserToken(context, authenticatedUser);
            succeededAttempt = true;
        } else if (isLocalUser && "true".equals(SMSOTPUtils.getBackupCode(context))) {
            succeededAttempt = checkWithBackUpCodes(context, userToken, authenticatedUser);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Given otp code is a mismatch.");
            }
            context.setProperty(SMSOTPConstants.CODE_MISMATCH, true);
        }

        if (succeededAttempt && isLocalUser) {
            String username = String.valueOf(context.getProperty(SMSOTPConstants.USER_NAME));
            String mobileNumber;
            try {
                mobileNumber = SMSOTPUtils.getMobileNumberForUsername(username);
            } catch (SMSOTPException e) {
                throw new AuthenticationFailedException("Failed to get the parameters from authentication xml file " +
                        "for user:  " + username + " for tenant: " + context.getTenantDomain(), e);
            }

            if (StringUtils.isBlank(mobileNumber)) {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                Object verifiedMobileObject = context.getProperty(SMSOTPConstants.REQUESTED_USER_MOBILE);
                if (verifiedMobileObject != null) {
                    try {
                        Utils.setThreadLocalToSkipSendingSmsOtpVerificationOnUpdate(IdentityRecoveryConstants.
                                SkipMobileNumberVerificationOnUpdateStates.SKIP_ON_SMS_OTP_FLOW.toString());
                        updateMobileNumberForUsername(context, request, username, tenantDomain);
                    } catch (SMSOTPException e) {
                        throw new AuthenticationFailedException("Failed accessing the userstore for user: " + username, e.getCause());
                    } catch (UserStoreClientException e) {
                        context.setProperty(SMSOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
                        throw new AuthenticationFailedException("Mobile claim update failed for user :" + username, e);
                    } catch (UserStoreException e) {
                        Throwable ex = e.getCause();
                        if (ex instanceof UserStoreClientException) {
                            context.setProperty(SMSOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
                            context.setProperty(SMSOTPConstants.PROFILE_UPDATE_FAILURE_REASON, ex.getMessage());
                        }
                        throw new AuthenticationFailedException("Mobile claim update failed for user " + username, e);
                    } finally {
                        Utils.unsetThreadLocalToSkipSendingSmsOtpVerificationOnUpdate();
                    }
                }
            }
        }

        if (!succeededAttempt) {
            handleSmsOtpVerificationFail(context);
            context.setProperty(SMSOTPConstants.CODE_MISMATCH, true);
            throw new AuthenticationFailedException("Invalid code. Verification failed.");
        }
        // It reached here means the authentication was successful.
        resetSmsOtpFailedAttempts(context);
    }

    private void processValidUserToken(AuthenticationContext context, AuthenticatedUser authenticatedUser) throws
            AuthenticationFailedException {
        Optional<Object> tokenValidityTime = Optional.ofNullable(context.getProperty(SMSOTPConstants.
                TOKEN_VALIDITY_TIME));
        if (!tokenValidityTime.isPresent() || !NumberUtils.isNumber(tokenValidityTime.get().toString())) {
            log.error("TokenExpiryTime property is not configured in application-authentication.xml or SMS OTP " +
                    "Authenticator UI");
            context.setSubject(authenticatedUser);
            return;
        }

        Optional<Object> otpTokenSentTime = Optional.ofNullable(context.getProperty(SMSOTPConstants.
                SENT_OTP_TOKEN_TIME));
        if (!otpTokenSentTime.isPresent() || !NumberUtils.isNumber(otpTokenSentTime.get().toString())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find OTP sent time");
            }
            throw new AuthenticationFailedException("Internal Error Occurred");
        }

        long elapsedTokenTime = System.currentTimeMillis() - Long.parseLong(otpTokenSentTime.get().toString());

        if (elapsedTokenTime <= (Long.parseLong(tokenValidityTime.get().toString()))) {
            context.removeProperty(SMSOTPConstants.TOKEN_EXPIRED);
            context.setSubject(authenticatedUser);
        } else {
            context.setProperty(SMSOTPConstants.TOKEN_EXPIRED, SMSOTPConstants.TOKEN_EXPIRED_VALUE);
            handleSmsOtpVerificationFail(context);
            throw new AuthenticationFailedException("OTP code has expired");
        }
    }

    /**
     * If user forgets the mobile, then user can use the back up codes to authenticate the user.
     * Check whether the entered code matches with a backup code.
     *
     * @param context           The AuthenticationContext.
     * @param userToken         The userToken.
     * @param authenticatedUser The authenticatedUser.
     * @return True if the user entered code matches with a backup code.
     * @throws AuthenticationFailedException If an error occurred while retrieving user claim for OTP list.
     */
    private boolean checkWithBackUpCodes(AuthenticationContext context, String userToken,
                                         AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        boolean isMatchingToken = false;
        String[] savedOTPs = null;
        String username = context.getProperty(SMSOTPConstants.USER_NAME).toString();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = getUserRealm(username);
        String backupCodesClaim = null;
        try {
            if (userRealm != null) {
                UserStoreManager userStoreManager = userRealm.getUserStoreManager();
                boolean isHandleBackupCodesAsIdentityClaim = Boolean.parseBoolean(IdentityUtil
                        .getProperty(SMSOTPConstants.HANDLE_BACKUP_CODES_AS_IDENTITY_CLAIM));
                if (isHandleBackupCodesAsIdentityClaim) {
                    if (log.isDebugEnabled()) {
                        log.debug(SMSOTPConstants.HANDLE_BACKUP_CODES_AS_IDENTITY_CLAIM + " property is enabled, " +
                                "hence treating OTP backup code claim as " + SMSOTPConstants.OTP_BACKUP_CODES_IDENTITY_CLAIM);
                    }
                    backupCodesClaim = SMSOTPConstants.OTP_BACKUP_CODES_IDENTITY_CLAIM;
                } else {
                    backupCodesClaim = SMSOTPConstants.SAVED_OTP_LIST;
                }

                if (userStoreManager != null) {
                    Map<String, String> returnedClaimMap = userStoreManager
                            .getUserClaimValues(tenantAwareUsername, new String[]{backupCodesClaim}, null);
                    if (!returnedClaimMap.isEmpty()) {
                        String savedOTPString = returnedClaimMap.get(backupCodesClaim);
                        if (StringUtils.isNotEmpty(savedOTPString)) {
                            savedOTPs = savedOTPString.split(SMSOTPConstants.BACKUP_CODES_SEPARATOR);
                        }
                    }
                }
            }

            // Check whether there is any backup OTPs and return.
            if (ArrayUtils.isEmpty(savedOTPs)) {
                if (log.isDebugEnabled()) {
                    log.debug("The claim " + backupCodesClaim + " does not contain any values.");
                }
                return false;
            }
            if (isBackUpCodeValid(savedOTPs, userToken)) {
                if (log.isDebugEnabled()) {
                    log.debug("Found saved backup SMS OTP for user :" + authenticatedUser);
                }
                isMatchingToken = true;
                context.setSubject(authenticatedUser);
                savedOTPs = (String[]) ArrayUtils.removeElement(savedOTPs, userToken);
                if (log.isDebugEnabled()) {
                    log.debug("Removing backup code from saved backup codes list.");
                }
                Map<String, String> updatedClaims = new HashMap<>();
                updatedClaims.put(backupCodesClaim, String.join(SMSOTPConstants.BACKUP_CODES_SEPARATOR, savedOTPs));
                userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, updatedClaims, null);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User entered OTP :" + userToken + " does not match with any of the saved " +
                            "backup codes");
                }
                context.setProperty(SMSOTPConstants.CODE_MISMATCH, true);
            }
        } catch (UserStoreException e) {
            log.error("Cannot find the user claim for OTP list for user : " + authenticatedUser, e);
        }
        return isMatchingToken;
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
     * Returns AuthenticatedUser object from context.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser
     */
    public AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser authenticatedUserInStepConfig = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && authenticatedUserInStepConfig != null) {
                // Make a copy of the user from the subject attribute step as we might modify this within
                // the authenticator.
                authenticatedUser = new AuthenticatedUser(authenticatedUserInStepConfig);
                break;
            }
        }
        if (context.getLastAuthenticatedUser() != null && context.getLastAuthenticatedUser().getUserName() != null) {
            authenticatedUser = context.getLastAuthenticatedUser();
        }
        return authenticatedUser;
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
     * Get the user realm of the logged in user.
     *
     * @param authenticatedUser Authenticated user.
     * @return The userRealm.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private UserRealm getUserRealm(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        UserRealm userRealm = null;
        try {
            if (authenticatedUser != null) {
                String tenantDomain = authenticatedUser.getTenantDomain();
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm.", e);
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
                "specify them as $ctx.num and $ctx.msg or $ctx.otp");
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
                "separated by \":\". If the phone number and text message are in Headers, specify them as $ctx.num " +
                "and $ctx.msg or $ctx.otp");
        headers.setDisplayOrder(2);
        configProperties.add(headers);

        Property payload = new Property();
        payload.setName(SMSOTPConstants.PAYLOAD);
        payload.setDisplayName("HTTP Payload");
        payload.setRequired(false);
        payload.setDescription("Enter the HTTP Payload used by the SMS API. If the phone number and text message are " +
                "in Payload, specify them as $ctx.num and $ctx.msg or $ctx.otp");
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

        Property mobileNumberRegex = new Property();
        mobileNumberRegex.setName(SMSOTPConstants.MOBILE_NUMBER_REGEX);
        mobileNumberRegex.setDisplayName("Mobile Number Regex Pattern");
        mobileNumberRegex.setRequired(false);
        mobileNumberRegex.setDescription("Enter regex format to validate mobile number while capture and update " +
                "mobile number.");
        mobileNumberRegex.setDisplayOrder(7);
        configProperties.add(mobileNumberRegex);

        Property RegexFailureErrorMessage = new Property();
        RegexFailureErrorMessage.setName(SMSOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE);
        RegexFailureErrorMessage.setDisplayName("Regex Violation Error Message");
        RegexFailureErrorMessage.setRequired(false);
        RegexFailureErrorMessage.setDescription("Enter error message for invalid mobile number patterns.");
        RegexFailureErrorMessage.setDisplayOrder(8);
        configProperties.add(RegexFailureErrorMessage);

        Property lengthOTP = new Property();
        lengthOTP.setName(SMSOTPConstants.SMS_OTP_LENGTH);
        lengthOTP.setDisplayName("SMS OTP length");
        lengthOTP.setRequired(false);
        lengthOTP.setDescription("The number of allowed characters in the OTP. Please pick a value between 4-10.");
        lengthOTP.setType("string");
        lengthOTP.setDefaultValue(Integer.toString(SMSOTPConstants.NUMBER_DIGIT));
        lengthOTP.setDisplayOrder(9);
        configProperties.add(lengthOTP);

        Property expiryTimeOTP = new Property();
        expiryTimeOTP.setName(SMSOTPConstants.SMS_OTP_EXPIRY_TIME);
        expiryTimeOTP.setDisplayName("SMS OTP expiry time (Minutes)");
        expiryTimeOTP.setRequired(false);
        expiryTimeOTP.setDescription("Please pick a value between 1 minute and 1440 minutes (1 day).");
        expiryTimeOTP.setType("string");
        expiryTimeOTP.setDefaultValue(SMSOTPConstants.OTP_EXPIRE_TIME_DEFAULT_IN_MINS);
        expiryTimeOTP.setDisplayOrder(10);
        configProperties.add(expiryTimeOTP);

        Property numericOTP = new Property();
        numericOTP.setName(SMSOTPConstants.SMS_OTP_NUMERIC_OTP);
        numericOTP.setDisplayName("Use only numeric characters for OTP");
        numericOTP.setRequired(false);
        numericOTP.setDescription("Please enter either 'true' or 'false' to use only numeric characters" +
                " or enable alphanumeric characters respectively.");
        numericOTP.setType("string");
        numericOTP.setDefaultValue("true");
        numericOTP.setDisplayOrder(11);
        configProperties.add(numericOTP);

        return configProperties;
    }

    /**
     * Get the connection and proceed with SMS API's rest call.
     *
     * @param httpConnection       The connection.
     * @param context              The authenticationContext.
     * @param headerString         The header string.
     * @param payload              The payload.
     * @param httpResponse         The http response.
     * @param receivedMobileNumber The encoded mobileNo.
     * @param smsMessage           The sms message.
     * @param otpToken             The token.
     * @param httpMethod           The http method.
     * @return true or false
     * @throws AuthenticationFailedException
     */
    private boolean getConnection(HttpURLConnection httpConnection, AuthenticationContext context, String headerString,
                                  String payload, String httpResponse, String receivedMobileNumber, String smsMessage,
                                  String otpToken, String httpMethod) throws AuthenticationFailedException {

        try {
            httpConnection.setDoInput(true);
            httpConnection.setDoOutput(true);
            String encodedMobileNo = URLEncoder.encode(receivedMobileNumber, CHAR_SET_UTF_8);
            String encodedSMSMessage;
            String[] headerArray;
            HashMap<String, Object> headerElementProperties = new HashMap<>();
            if (StringUtils.isNotEmpty(headerString)) {
                if (log.isDebugEnabled()) {
                    log.debug("Processing HTTP headers since header string is available");
                }
                headerString = replacePlaceholders(headerString.trim(), otpToken, receivedMobileNumber, smsMessage);
                headerArray = headerString.split(",");
                for (String header : headerArray) {
                    String[] headerElements = header.split(":", 2);
                    if (headerElements.length > 1) {
                        httpConnection.setRequestProperty(headerElements[0], headerElements[1]);
                        headerElementProperties.put(headerElements[0], headerElements[1]);
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
                    String contentType =
                            StringUtils.trimToEmpty((String) headerElementProperties.get(CONTENT_TYPE));
                    /*
                    If the enable_payload_encoding_for_sms_otp configuration is disabled, mobile number in the
                    payload will be URL encoded for all the content-types except for application/json content type
                    preserving the previous implementation to support backward compatibility.
                    */
                    if (SMSOTPUtils.isPayloadEncodingForSMSOTPEnabled(context)) {
                        /*
                        here only the mobile number and SMS message will be encoded, assuming the rest of the content is
                        in correct format.
                        */
                        encodedMobileNo = getEncodedValue(contentType, receivedMobileNumber);
                        encodedSMSMessage = getEncodedValue(contentType, smsMessage);
                    } else {
                        encodedSMSMessage = smsMessage;
                        if (StringUtils.isNotBlank(contentType) && POST_METHOD.equals(httpMethod) &&
                                (JSON_CONTENT_TYPE).equals(contentType)) {
                            encodedMobileNo = receivedMobileNumber;
                        }
                    }
                    payload = replacePlaceholders(payload, otpToken, encodedMobileNo, encodedSMSMessage);
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
                        log.debug("Code is successfully sent to the mobile and received expected response code : " +
                                httpResponse);
                    }
                    return true;
                } else {
                    log.error("Error while sending SMS: error code is " + httpConnection.getResponseCode()
                            + " and error message is " + httpConnection.getResponseMessage());
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
                    if (httpConnection.getErrorStream() != null) {
                        String content = getSanitizedErrorInfo(httpConnection.getErrorStream(), context, encodedMobileNo);

                        log.error("Error while sending SMS: error code is " + httpConnection.getResponseCode()
                                + " and error message is " + httpConnection.getResponseMessage());
                        context.setProperty(SMSOTPConstants.ERROR_INFO, content);
                    }
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


    private String getSanitizedErrorInfo(InputStream errorStream, AuthenticationContext context, String
            encodedMobileNo) throws IOException, AuthenticationFailedException {

        String contentRaw = readContent(errorStream);

        String screenValue = getScreenValue(context);
        if (StringUtils.isEmpty(screenValue)) {
            int noOfDigits = 0;
            if ((SMSOTPUtils.getNoOfDigits(context)) != null) {
                noOfDigits = Integer.parseInt(SMSOTPUtils.getNoOfDigits(context));
            }
            screenValue = getMaskedValue(context, encodedMobileNo, noOfDigits);
        }
        String content = contentRaw.replace(encodedMobileNo, screenValue);
        String decodedMobileNo = URLDecoder.decode(encodedMobileNo);
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

    private String readContent(InputStream errorStream) throws IOException {

        BufferedReader br = new BufferedReader(new InputStreamReader(errorStream));
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
        String receivedMobileNumber = URLEncoder.encode(mobile, CHAR_SET_UTF_8);

        String encodedSmsMessage = smsMessage.replaceAll("\\s", "+");
        smsUrl = replacePlaceholders(smsUrl, otpToken, receivedMobileNumber, encodedSmsMessage);
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
        } else {
            httpConnection = (HttpURLConnection) smsProviderUrl.openConnection();
        }
        connection = getConnection(httpConnection, context, headerString, payload, httpResponse,
                mobile, smsMessage, otpToken, httpMethod);
        return connection;
    }

    /**
     * Replace the placeholders with their actual values in the request payload.
     *
     * @param payload       Message payload with placeholders
     * @param otpToken      Generated OTP token
     * @param mobileNumber  Mobile phone number
     * @param message       Message content (without OTP)
     * @return  Message payload string after populating actual values for the placeholders
     */
    private String replacePlaceholders(String payload, String otpToken, String mobileNumber, String message) {

        return payload.replaceAll("\\$ctx.num", mobileNumber)
                .replaceAll("\\$ctx.msg", message + otpToken)
                .replaceAll("\\$ctx.otp", otpToken);
    }

    /**
     * Get the corresponding encoded value based on the provided content-type.
     *
     * @param contentType The content type in the request header.
     * @param value       String value that needed to be encoded.
     * @return The encoded value based on the content-type.
     * @throws IOException
     */
    private String getEncodedValue(String contentType, String value) throws IOException {

        String encodedValue;
        switch (contentType) {
            case XML_CONTENT_TYPE:
                encodedValue = Encode.forXml(value);
                break;
            case JSON_CONTENT_TYPE:
                Gson gson = new Gson();
                encodedValue = gson.toJson(value);
                break;
            default:
                encodedValue = URLEncoder.encode(value, CHAR_SET_UTF_8);
        }
        return encodedValue;
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
            throws UserStoreException {

        String screenUserAttributeParam;
        String screenUserAttributeValue = null;
        String screenValue = null;
        int noOfDigits = 0;

        screenUserAttributeParam = SMSOTPUtils.getScreenUserAttribute(context);
        if (screenUserAttributeParam != null) {
            screenUserAttributeValue = userRealm.getUserStoreManager()
                    .getUserClaimValue(username, screenUserAttributeParam, null);

            if (StringUtils.isBlank(screenUserAttributeValue)) {
                screenUserAttributeValue = String.valueOf(context.getProperty(REQUESTED_USER_MOBILE));
            }
        }

        if (StringUtils.isNotBlank(screenUserAttributeValue)) {
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
        String maskingRegex = SMSOTPUtils.getScreenValueRegex(context);

        if (StringUtils.isNotEmpty(maskingRegex)) {
            screenValue = screenUserAttributeValue.replaceAll(maskingRegex, SMSOTPConstants.SCREEN_VALUE_MASKING_CHARACTER);
            return screenValue;
        }

        int screenAttributeLength = screenUserAttributeValue.length();
        // Ensure noOfDigits is not greater than screenAttributeLength.
        noOfDigits = Math.min(noOfDigits, screenAttributeLength);
        if (screenAttributeLength <= noOfDigits && log.isDebugEnabled()) {
            log.debug("Mobile number length is less than or equal to noOfDigits: " + noOfDigits);
        }
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
    protected void triggerNotification(String userName, String tenantDomain, String userStoreDomainName,
                                       String mobileNumber, String otpCode, String serviceProviderName,
                                       long otpExpiryTime) {

        String eventName = TRIGGER_SMS_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        properties.put(SMSOTPConstants.ATTRIBUTE_SMS_SENT_TO, mobileNumber);
        properties.put(SMSOTPConstants.OTP_TOKEN, otpCode);
        properties.put(SMSOTPConstants.CORRELATION_ID, getCorrelationId());
        properties.put(SMSOTPConstants.TEMPLATE_TYPE, SMSOTPConstants.EVENT_NAME);
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, serviceProviderName);
        properties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, String.valueOf(otpExpiryTime / 60));
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

    /**
     * Get correlation id of current thread.
     *
     * @return correlation-id.
     */
    public static String getCorrelationId() {

        return StringUtils.isBlank(MDC.get(SMSOTPConstants.CORRELATION_ID_MDC))
                ? UUID.randomUUID().toString() : MDC.get(SMSOTPConstants.CORRELATION_ID_MDC);
    }

    private String getHttpErrorResponseCode(String errorMsg) {

        String errorCode = errorMsg;
        if (StringUtils.contains(errorCode, ":")) {
            errorCode = errorCode.split(":")[0];
        }
        return StringUtils.trim(errorCode);
    }

    /**
     * Reset SMS OTP Failed Attempts count upon successful completion of the SMS OTP verification.
     *
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void resetSmsOtpFailedAttempts(AuthenticationContext context) throws AuthenticationFailedException {
        
        /*
        Check whether account locking enabled for SMS OTP to keep backward compatibility.
        Account locking is not done for federated flows.
         */
        if (!SMSOTPUtils.isLocalUser(context) || !SMSOTPUtils.isAccountLockingEnabledForSmsOtp(context)) {
            return;
        }
        AuthenticatedUser authenticatedUser =
                (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
        Property[] connectorConfigs = SMSOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());

        // Return if account lock handler is not enabled.
        for (Property connectorConfig : connectorConfigs) {
            if ((SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE.equals(connectorConfig.getName())) &&
                    !Boolean.parseBoolean(connectorConfig.getValue())) {
                return;
            }
        }

        String usernameWithDomain = IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                authenticatedUser.getUserStoreDomain());
        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            // Avoid updating the claims if they are already zero.
            String[] claimsToCheck = {SMSOTPConstants.SMS_OTP_FAILED_ATTEMPTS_CLAIM};
            Map<String, String> userClaims = userStoreManager.getUserClaimValues(usernameWithDomain, claimsToCheck,
                    UserCoreConstants.DEFAULT_PROFILE);
            String failedSmsOtpAttempts = userClaims.get(SMSOTPConstants.SMS_OTP_FAILED_ATTEMPTS_CLAIM);

            if (NumberUtils.isNumber(failedSmsOtpAttempts) && Integer.parseInt(failedSmsOtpAttempts) > 0) {
                Map<String, String> updatedClaims = new HashMap<>();
                updatedClaims.put(SMSOTPConstants.SMS_OTP_FAILED_ATTEMPTS_CLAIM, "0");
                userStoreManager
                        .setUserClaimValues(usernameWithDomain, updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
            }
        } catch (UserStoreException e) {
            log.error("Error while resetting failed SMS OTP attempts", e);
            String errorMessage =
                    String.format("Failed to reset failed attempts count for user : %s.", authenticatedUser);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Execute account lock flow for OTP verification failures.
     *
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void handleSmsOtpVerificationFail(AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser =
                (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);

        /*
        Account locking is not done for federated flows.
        Check whether account locking enabled for SMS OTP to keep backward compatibility.
        No need to continue if the account is already locked.
         */
        if (!SMSOTPUtils.isLocalUser(context) || !SMSOTPUtils.isAccountLockingEnabledForSmsOtp(context) ||
                SMSOTPUtils.isAccountLocked(authenticatedUser)) {
            return;
        }
        int maxAttempts = 0;
        long unlockTimePropertyValue = 0;
        double unlockTimeRatio = 1;

        Property[] connectorConfigs = SMSOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());
        for (Property connectorConfig : connectorConfigs) {
            switch (connectorConfig.getName()) {
                case SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE:
                    if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                        return;
                    }
                case SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        maxAttempts = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_TIME:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        unlockTimePropertyValue = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case SMSOTPConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        double value = Double.parseDouble(connectorConfig.getValue());
                        if (value > 0) {
                            unlockTimeRatio = value;
                        }
                    }
                    break;
            }
        }
        Map<String, String> claimValues = getUserClaimValues(authenticatedUser);
        if (claimValues == null) {
            claimValues = new HashMap<>();
        }
        int currentAttempts = 0;
        if (NumberUtils.isNumber(claimValues.get(SMSOTPConstants.SMS_OTP_FAILED_ATTEMPTS_CLAIM))) {
            currentAttempts = Integer.parseInt(claimValues.get(SMSOTPConstants.SMS_OTP_FAILED_ATTEMPTS_CLAIM));
        }
        int failedLoginLockoutCountValue = 0;
        if (NumberUtils.isNumber(claimValues.get(SMSOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM))) {
            failedLoginLockoutCountValue =
                    Integer.parseInt(claimValues.get(SMSOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM));
        }

        Map<String, String> updatedClaims = new HashMap<>();
        if ((currentAttempts + 1) >= maxAttempts) {
            // Calculate the incremental unlock-time-interval in milli seconds.
            unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow(unlockTimeRatio,
                    failedLoginLockoutCountValue));
            // Calculate unlock-time by adding current-time and unlock-time-interval in milli seconds.
            long unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
            updatedClaims.put(SMSOTPConstants.ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString());
            updatedClaims.put(SMSOTPConstants.SMS_OTP_FAILED_ATTEMPTS_CLAIM, "0");
            updatedClaims.put(SMSOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM, String.valueOf(unlockTime));
            updatedClaims.put(SMSOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                    String.valueOf(failedLoginLockoutCountValue + 1));
            updatedClaims.put(SMSOTPConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                    SMSOTPConstants.MAX_SMS_OTP_ATTEMPTS_EXCEEDED);
            IdentityUtil.threadLocalProperties.get().put(SMSOTPConstants.ADMIN_INITIATED, false);
            setUserClaimValues(authenticatedUser, updatedClaims);
            String errorMessage = String.format("User account: %s is locked.", authenticatedUser.getUserName());
            throw new AuthenticationFailedException(errorMessage);
        } else {
            updatedClaims.put(SMSOTPConstants.SMS_OTP_FAILED_ATTEMPTS_CLAIM, String.valueOf(currentAttempts + 1));
            setUserClaimValues(authenticatedUser, updatedClaims);
        }
    }

    private Map<String, String> getUserClaimValues(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        Map<String, String> claimValues;
        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            claimValues = userStoreManager.getUserClaimValues(IdentityUtil.addDomainToName(
                            authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain()), new String[]{
                            SMSOTPConstants.SMS_OTP_FAILED_ATTEMPTS_CLAIM,
                            SMSOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM},
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.error("Error while reading user claims", e);
            String errorMessage = String.format("Failed to read user claims for user : %s.", authenticatedUser);
            throw new AuthenticationFailedException(errorMessage, e);
        }
        return claimValues;
    }

    private void setUserClaimValues(AuthenticatedUser authenticatedUser, Map<String, String> updatedClaims)
            throws AuthenticationFailedException {

        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                    authenticatedUser.getUserStoreDomain()), updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.error("Error while updating user claims", e);
            String errorMessage = String.format("Failed to update user claims for user : %s.", authenticatedUser);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Get user account unlock time in milli seconds. If no value configured for unlock time user claim, return 0.
     *
     * @param authenticatedUser The authenticated user.
     * @return User account unlock time in milli seconds. If no value is configured return 0.
     * @throws AuthenticationFailedException If an error occurred while getting the user unlock time.
     */
    private long getUnlockTimeInMilliSeconds(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        String username = authenticatedUser.toFullQualifiedUsername();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        try {
            UserRealm userRealm = getUserRealm(username);
            if (userRealm == null) {
                throw new AuthenticationFailedException("UserRealm is null for user : " + username);
            }
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                if (log.isDebugEnabled()) {
                    log.debug("userStoreManager is null for user: " + username);
                }
                throw new AuthenticationFailedException("userStoreManager is null for user: " + username);
            }
            Map<String, String> claimValues = userStoreManager
                    .getUserClaimValues(tenantAwareUsername, new String[]{SMSOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM},
                            null);
            if (claimValues.get(SMSOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM) == null) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("No value configured for claim: %s, of user: %s",
                            SMSOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM, username));
                }
                return 0;
            }
            return Long.parseLong(claimValues.get(SMSOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM));
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user claim for unlock time for user : " +
                    username, e);
        }
    }

    /**
     * Trigger event after generating SMS OTP.
     *
     * @param request HttpServletRequest.
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void publishPostSMSOTPGeneratedEvent(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCallerSessionKey());
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants
                .AUTHENTICATED_USER);
        eventProperties.put(IdentityEventConstants.EventProperty.USER_NAME, authenticatedUser.getUserName());
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, context.getTenantDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, authenticatedUser
                .getUserStoreDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_AGENT, request.getHeader(
                SMSOTPConstants.USER_AGENT));
        if (request.getParameter(SMSOTPConstants.RESEND) != null) {
            if (log.isDebugEnabled()) {
                log.debug("Setting true resend-code property in event since http request has resendCode parameter.");
            }
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE,
                    request.getParameter(SMSOTPConstants.RESEND));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Setting false resend-code property in event since http request has not resendCode parameter.");
            }
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, false);
        }

        eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP, context.getProperty(
                SMSOTPConstants.OTP_TOKEN));

        Object otpGeneratedTimeProperty = context.getProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME);
        if (otpGeneratedTimeProperty != null) {
            long otpGeneratedTime = (long) otpGeneratedTimeProperty;
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME, otpGeneratedTime);

            String otpValidityPeriod = (String) context.getProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME);
            long expiryTime = otpGeneratedTime + (StringUtils.isEmpty(otpValidityPeriod) ?
                    SMSOTPConstants.DEFAULT_VALIDITY_PERIOD : Long.parseLong(otpValidityPeriod));
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);
        }

        eventProperties.put(IdentityEventConstants.EventProperty.CLIENT_IP, IdentityUtil.getClientIpAddress(request));
        Event postOtpGenEvent = new Event(IdentityEventConstants.Event.POST_GENERATE_SMS_OTP, eventProperties);
        try {
            SMSOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(postOtpGenEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "An error occurred while triggering post event in SMS OTP generation flow. " + e.getMessage();
            throw new AuthenticationFailedException(errorMsg, e);
        }
    }

    /**
     * Trigger event after validating SMS OTP.
     *
     * @param request HttpServletRequest.
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void publishPostSMSOTPValidatedEvent(HttpServletRequest request,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, Object> eventProperties = new HashMap<>();
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants
                .AUTHENTICATED_USER);
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCallerSessionKey());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_NAME, authenticatedUser.getUserName());
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, context.getTenantDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, authenticatedUser
                .getUserStoreDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_AGENT, request.getHeader(
                SMSOTPConstants.USER_AGENT));

        eventProperties.put(IdentityEventConstants.EventProperty.CLIENT_IP, IdentityUtil.getClientIpAddress(request));
        eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP, context.getProperty(
                SMSOTPConstants.OTP_TOKEN));
        eventProperties.put(IdentityEventConstants.EventProperty.USER_INPUT_OTP, request.getParameter(
                SMSOTPConstants.CODE));
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_USED_TIME, System.currentTimeMillis());

        long otpGeneratedTime = (long) context.getProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME);
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME,
                otpGeneratedTime);

        long otpExpiryTime = getSMSOTPExpiryTime(authenticatorProperties, context);
        long expiryTime = otpGeneratedTime + otpExpiryTime;
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);

        String status;
        if (SMSOTPConstants.TOKEN_EXPIRED_VALUE.equals(context.getProperty(SMSOTPConstants.TOKEN_EXPIRED))) {
            status = SMSOTPConstants.STATUS_OTP_EXPIRED;
        } else if (context.getProperty(SMSOTPConstants.CODE_MISMATCH) != null && (boolean) context.getProperty(
                SMSOTPConstants.CODE_MISMATCH)) {
            status = SMSOTPConstants.STATUS_CODE_MISMATCH;
        } else {
            status = SMSOTPConstants.STATUS_SUCCESS;
        }

        eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS, status);
        Event postOtpValidateEvent = new Event(IdentityEventConstants.Event.POST_VALIDATE_SMS_OTP, eventProperties);

        try {
            SMSOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(postOtpValidateEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "An error occurred while triggering post event in SMS OTP validation flow. " + e.getMessage();
            throw new AuthenticationFailedException(errorMsg, e);
        }
    }

    /*
     * This method returns the boolean value of the mobile number update failed context property.
     *
     * @param context
     * @return The status of mobile number update failed parameter
     */
    private boolean isMobileNumberUpdateFailed(AuthenticationContext context) {

        return Boolean.parseBoolean(String.valueOf(context.getProperty(SMSOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE)));
    }

    /**
     * This method returns the boolean value of the code mismatch context property.
     *
     * @param context
     * @return The staut of the code mismatch parameter
     */
    private boolean isCodeMismatch(AuthenticationContext context) {

        return Boolean.parseBoolean(String.valueOf(context.getProperty(SMSOTPConstants.CODE_MISMATCH)));
    }

    /**
     * This method generates the URL from the provided context.
     *
     * @param urlFromConfig URL from the configurations.
     * @param defaultContext Default context.
     * @return The generated URL.
     */
    private static String buildURL(String urlFromConfig, String defaultContext) throws URLBuilderException {

        String contextToBuildURL = defaultContext;
        if (StringUtils.isNotBlank(urlFromConfig)) {
            contextToBuildURL = urlFromConfig;
        }
        try {
            if (isURLRelative(contextToBuildURL)) {
                // When tenant qualified URL feature is enabled, this will generate a tenant qualified URL.
                return ServiceURLBuilder.create().addPath(contextToBuildURL).build().getAbsolutePublicURL();
            }
        } catch (URISyntaxException e) {
            throw new URLBuilderException("Error while building public absolute URL for context: " + defaultContext, e);
        }

        // URL from the configuration was an absolute one. We return the same without any modification.
        return contextToBuildURL;
    }

    /**
     * This method returns whether the URL is relative or not.
     *
     * @param url The URL to be checked.
     * @return Returns true if the URL is relative and false if the URL is absolute.
     * @throws URISyntaxException
     */
    private static boolean isURLRelative(String url) throws URISyntaxException {

        return !new URI(url).isAbsolute();
    }

    /**
     * Get application details from the authentication context.
     * @param context Authentication context.
     * @return Map of application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    /**
     * This method is used to redirect the user to the username entering page (IDF: Identifier first).
     *
     * @param context  Authentication context.
     * @param response Response.
     * @throws AuthenticationFailedException If error occurred while redirecting.
     */
    private void redirectUserToIDF(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        StringBuilder redirectUrl = new StringBuilder();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        redirectUrl.append(loginPage);
        redirectUrl.append("?");

        String queryParams = context.getContextIdIncludedQueryParams();
        try {
            if (log.isDebugEnabled()) {
                String logMsg = String.format("Redirecting to identifier first flow since "
                        + "last authenticated user is null in SP: %s", context.getServiceProviderName());
                log.debug(logMsg);
            }
            queryParams += "&" + SMSOTPConstants.NAME_OF_AUTHENTICATORS + SMSOTPConstants.IDF_HANDLER_NAME + ":" +
                    SMSOTPConstants.LOCAL_AUTHENTICATOR;
            redirectUrl.append(queryParams);
            response.sendRedirect(redirectUrl.toString());
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while redirecting to the login page.", e);
        }
    }

    /**
     * This method is used to resolve the username from authentication request.
     *
     * @param request HTTP Servlet Request.
     * @throws AuthenticationFailedException If error occurred while resolving username from request.
     */
    private String resolveUsernameFromRequest(HttpServletRequest request) throws AuthenticationFailedException {

        String identifierFromRequest = request.getParameter(SMSOTPConstants.USER_NAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw new AuthenticationFailedException("Username cannot be null or empty");
        }
        return identifierFromRequest;
    }

    /**
     * This method is used to resolve the user from authentication request from identifier handler.
     *
     * @param request HTTP Servlet Request.
     * @param context Authentication context.
     * @throws AuthenticationFailedException If error occurred while resolving user from request.
     */
    private AuthenticatedUser resolveUserFromRequest(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = resolveUsernameFromRequest(request);
        username = FrameworkUtils.preprocessUsername(username, context);
        AuthenticatedUser user = new AuthenticatedUser();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        user.setAuthenticatedSubjectIdentifier(tenantAwareUsername);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * This method is used to resolve an authenticated user from the user stores.
     *
     * @param authenticatedUser Authenticated user.
     * @return Authenticated user retrieved from the user store.
     * @throws AuthenticationFailedException If error occurred while resolving user from userstore.
     */
    private AuthenticatedUser resolveUserFromUserStore(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        User user = getUser(authenticatedUser);
        if (user == null) {
            return null;
        }
        authenticatedUser = new AuthenticatedUser(user);
        authenticatedUser.setAuthenticatedSubjectIdentifier(user.getUsername());
        return authenticatedUser;
    }

    /**
     * This method is used to set the resolved user in context.
     *
     * @param context           Authentication context.
     * @param authenticatedUser Authenticated user.
     */
    private void setResolvedUserInContext(AuthenticationContext context, AuthenticatedUser authenticatedUser) {

        if (authenticatedUser != null) {
            String username = authenticatedUser.getUserName();
            authenticatedUser.setAuthenticatedSubjectIdentifier(username);
            context.setSubject(authenticatedUser);

            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
            currentStepConfig.setAuthenticatedUser(authenticatedUser);
            currentStepConfig.setAuthenticatedIdP(SMSOTPConstants.LOCAL_AUTHENTICATOR);
        }
    }

    /**
     * Generate the OTP according to the configuration parameters.
     *
     * @param context Authentication Context.
     * @return Generated OTP.
     * @throws AuthenticationFailedException If an error occurred while generating OTP.
     */
    private String generateOTP(AuthenticationContext context) throws AuthenticationFailedException {

        String charSet = getOTPCharset(context);
        int otpLength = (int) context.getProperty(SMSOTPConstants.SMS_OTP_LENGTH);

        char[] chars = charSet.toCharArray();
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            stringBuilder.append(chars[secureRandom.nextInt(chars.length)]);
        }
        return stringBuilder.toString();
    }

    /**
     * Get the OTP character set according to the configuration.
     *
     * @param context Authentication Context.
     * @return OTP character set.
     */
    private String getOTPCharset(AuthenticationContext context) {

        boolean useOnlyNumericChars = !Boolean.parseBoolean
                (String.valueOf(context.getProperty(SMSOTPConstants.IS_CHAR_IN_OTP)));
        if (useOnlyNumericChars) {
            return SMSOTPConstants.SMS_OTP_NUMERIC_CHAR_SET;
        }
        return SMSOTPConstants.SMS_OTP_UPPER_CASE_ALPHABET_CHAR_SET
                + SMSOTPConstants.SMS_OTP_NUMERIC_CHAR_SET;
    }

    /**
     * Append the recaptcha related params if recaptcha is enabled for SMS OTP.
     *
     * @param request Http Servlet Request.
     * @return String with the appended recaptcha params.
     */
    private String getCaptchaParams(HttpServletRequest request, AuthenticationContext context) {

        String captchaParams = "";
        SMSOTPCaptchaConnector smsOTPCaptchaConnector = new SMSOTPCaptchaConnector();
        smsOTPCaptchaConnector.init(SMSOTPServiceDataHolder.getInstance().getIdentityGovernanceService());
        try {
            if (smsOTPCaptchaConnector.isSmsRecaptchaEnabled(request) && isSMSOTPAsFirstFactor(context)) {
                captchaParams = "&reCaptcha=true";
            }
        } catch (CaptchaException e) {
            log.error("Failed to determine if recaptcha for SMS OTP is enabled", e);
        }
        return captchaParams;
    }

    /**
     * This method checks if all the authentication steps up to now have been performed by authenticators that
     * implements AuthenticationFlowHandler interface. If so, it returns true.
     * AuthenticationFlowHandlers may not perform actual authentication though the authenticated user is set in the
     * context. Hence, this method can be used to determine if the user has been authenticated by a previous step.
     *
     * @param context AuthenticationContext.
     * @return True if all the authentication steps up to now have been performed by AuthenticationFlowHandlers.
     */
    private boolean isPreviousIdPAuthenticationFlowHandler(AuthenticationContext context) {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIdPs = context.getCurrentAuthenticatedIdPs();
        return currentAuthenticatedIdPs != null && !currentAuthenticatedIdPs.isEmpty() &&
                currentAuthenticatedIdPs.values().stream().filter(Objects::nonNull)
                        .map(AuthenticatedIdPData::getAuthenticators).filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .allMatch(authenticator ->
                                authenticator.getApplicationAuthenticator() instanceof AuthenticationFlowHandler);
    }

    /**
     * This method checks if SMS OTP is the first factor of the authentication flow.
     *
     * @param context Authentication Context.
     * @return True if SMS OTP is the first factor of the authentication flow.
     */
    private boolean isSMSOTPAsFirstFactor(AuthenticationContext context) {

        return (context.getCurrentStep() == 1 || isPreviousIdPAuthenticationFlowHandler(context));
    }

    /**
     * This method is responsible for validating whether the authenticator is supported for API Based Authentication.
     *
     * @return true if the authenticator is supported for API Based Authentication.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     *         If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     *         an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        String idpName = null;
        AuthenticatedUser authenticatedUser = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
            authenticatedUser = getAuthenticatedUser(context);
        }

        authenticatorData.setIdp(idpName);
        authenticatorData.setI18nKey(SMSOTPConstants.AUTHENTICATOR_SMS_OTP);

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        List<String> requiredParams = new ArrayList<>();
        if (authenticatedUser == null) {
            AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                    SMSOTPConstants.USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                    0, Boolean.FALSE, SMSOTPConstants.USERNAME_PARAM);
            authenticatorParamMetadataList.add(usernameMetadata);
            requiredParams.add(SMSOTPConstants.USER_NAME);
        } else {
            AuthenticatorParamMetadata codeMetadata = new AuthenticatorParamMetadata(
                    SMSOTPConstants.CODE, FrameworkConstants.AuthenticatorParamType.STRING,
                    1, Boolean.TRUE, SMSOTPConstants.CODE_PARAM);
            authenticatorParamMetadataList.add(codeMetadata);
            requiredParams.add(SMSOTPConstants.CODE);
        }
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        authenticatorData.setRequiredParams(requiredParams);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);
        return Optional.of(authenticatorData);
    }

    /**
     * Initialize or increment the number of times the OTP was resent to the user.
     *
     * @param context   Authentication Context.
     */
    private void updateUserResendAttempts(AuthenticationContext context) {

        if (context.getProperty(OTP_RESEND_ATTEMPTS) == null ||
                StringUtils.isBlank(context.getProperty(OTP_RESEND_ATTEMPTS).toString())) {
            context.setProperty(OTP_RESEND_ATTEMPTS, 1);
        } else {
            context.setProperty(OTP_RESEND_ATTEMPTS, (int) context.getProperty(OTP_RESEND_ATTEMPTS) + 1);
        }
    }
}
