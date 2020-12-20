/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.authenticator.smsotp.test;

import org.apache.axis2.context.ConfigurationContextFactory;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.MockitoAnnotations.initMocks;

import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;

import static org.mockito.Mockito.verify;

import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPAuthenticator;
import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants;
import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPUtils;
import org.wso2.carbon.identity.authenticator.smsotp.exception.SMSOTPException;
import org.wso2.carbon.identity.authenticator.smsotp.internal.SMSOTPServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.mgt.config.ConfigBuilder;
import org.wso2.carbon.identity.mgt.mail.NotificationBuilder;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ConfigurationFacade.class, SMSOTPUtils.class, FederatedAuthenticatorUtil.class, FrameworkUtils.class,
        IdentityTenantUtil.class, SMSOTPServiceDataHolder.class})
@PowerMockIgnore({"org.wso2.carbon.identity.application.common.model.User"})
public class SMSOTPAuthenticatorTest {
    private SMSOTPAuthenticator smsotpAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Spy
    private SMSOTPAuthenticator spy;

    @Mock
    SMSOTPUtils smsotpUtils;

    @Mock
    private ConfigurationFacade configurationFacade;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock private ClaimManager claimManager;
    @Mock private Claim claim;
    @Mock private SMSOTPServiceDataHolder sMSOTPServiceDataHolder;
    @Mock private IdentityEventService identityEventService;
    @Mock private Enumeration<String> requestHeaders;
    @Mock private AuthenticatedUser authenticatedUser;

    @BeforeMethod
    public void setUp() throws Exception {
        smsotpAuthenticator = new SMSOTPAuthenticator();
        mockStatic(SMSOTPServiceDataHolder.class);
        when(SMSOTPServiceDataHolder.getInstance()).thenReturn(sMSOTPServiceDataHolder);
        when(sMSOTPServiceDataHolder.getIdentityEventService()).thenReturn(identityEventService);
        Mockito.doNothing().when(identityEventService).handleEvent(anyObject());
        when(httpServletRequest.getHeaderNames()).thenReturn(requestHeaders);
        initMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }


    @Test
    public void testGetFriendlyName() {
        Assert.assertEquals(smsotpAuthenticator.getFriendlyName(), SMSOTPConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test
    public void testGetName() {
        Assert.assertEquals(smsotpAuthenticator.getName(), SMSOTPConstants.AUTHENTICATOR_NAME);
    }

    @Test
    public void testRetryAuthenticationEnabled() throws Exception {
        SMSOTPAuthenticator smsotp = PowerMockito.spy(smsotpAuthenticator);
        Assert.assertTrue((Boolean) Whitebox.invokeMethod(smsotp, "retryAuthenticationEnabled"));
    }

    @Test
    public void testGetContextIdentifierPassed() {
        when(httpServletRequest.getParameter(FrameworkConstants.SESSION_DATA_KEY)).thenReturn
                ("0246893");
        Assert.assertEquals(smsotpAuthenticator.getContextIdentifier(httpServletRequest), "0246893");
    }

    @Test
    public void testCanHandleTrue() {
        when(httpServletRequest.getParameter(SMSOTPConstants.CODE)).thenReturn(null);
        when(httpServletRequest.getParameter(SMSOTPConstants.RESEND)).thenReturn("resendCode");
        Assert.assertEquals(smsotpAuthenticator.canHandle(httpServletRequest), true);
    }

    @Test
    public void testCanHandleFalse() {
        when(httpServletRequest.getParameter(SMSOTPConstants.CODE)).thenReturn(null);
        when(httpServletRequest.getParameter(SMSOTPConstants.RESEND)).thenReturn(null);
        when(httpServletRequest.getParameter(SMSOTPConstants.MOBILE_NUMBER)).thenReturn(null);
        Assert.assertEquals(smsotpAuthenticator.canHandle(httpServletRequest), false);
    }

    @Test
    public void testGetURL() throws Exception {
        SMSOTPAuthenticator smsotp = PowerMockito.spy(smsotpAuthenticator);
        Assert.assertEquals(Whitebox.invokeMethod(smsotp, "getURL",
                SMSOTPConstants.LOGIN_PAGE, null),
                "authenticationendpoint/login.do?authenticators=SMSOTP");
    }

    @Test
    public void testGetURLwithQueryParams() throws Exception {
        SMSOTPAuthenticator smsotp = PowerMockito.spy(smsotpAuthenticator);
        Assert.assertEquals(Whitebox.invokeMethod(smsotp, "getURL",
                SMSOTPConstants.LOGIN_PAGE, "n=John&n=Susan"),
                "authenticationendpoint/login.do?n=John&n=Susan&authenticators=SMSOTP");
    }


    @Test
    public void testGetMobileNumber() throws Exception {
        mockStatic(SMSOTPUtils.class);
        when(SMSOTPUtils.getMobileNumberForUsername(anyString())).thenReturn("0775968325");
        Assert.assertEquals(Whitebox.invokeMethod(smsotpAuthenticator, "getMobileNumber",
                httpServletRequest, httpServletResponse, any(AuthenticationContext.class),
                "Kanapriya", "queryParams"), "0775968325");
    }

    @Test
    public void testGetLoginPage() throws Exception {
        mockStatic(SMSOTPUtils.class);
        mockStatic(ConfigurationFacade.class);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("/authenticationendpoint/login.do");
        when(SMSOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).thenReturn(null);
        Assert.assertNotEquals(Whitebox.invokeMethod(smsotpAuthenticator, "getLoginPage",
                new AuthenticationContext()), "/authenticationendpoint/login.do");
        Assert.assertEquals(Whitebox.invokeMethod(smsotpAuthenticator, "getLoginPage",
                new AuthenticationContext()), "/smsotpauthenticationendpoint/smsotp.jsp");
    }

    @Test
    public void testGetErrorPage() throws Exception {
        mockStatic(SMSOTPUtils.class);
        mockStatic(ConfigurationFacade.class);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("/authenticationendpoint/login.do");
        when(SMSOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).thenReturn(null);
        Assert.assertNotEquals(Whitebox.invokeMethod(smsotpAuthenticator, "getErrorPage",
                new AuthenticationContext()), "/authenticationendpoint/login.do");
        Assert.assertEquals(Whitebox.invokeMethod(smsotpAuthenticator, "getErrorPage",
                new AuthenticationContext()), "/smsotpauthenticationendpoint/smsotpError.jsp");
    }

    @Test
    public void testRedirectToErrorPage() throws Exception {
        mockStatic(SMSOTPUtils.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        when(SMSOTPUtils.getErrorPageFromXMLFile(authenticationContext))
                .thenReturn("/smsotpauthenticationendpoint/smsotpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "redirectToErrorPage",
                httpServletResponse, authenticationContext, null, null);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testRedirectToMobileNumberReqPage() throws Exception {
        mockStatic(SMSOTPUtils.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        when(SMSOTPUtils.isEnableMobileNoUpdate(authenticationContext)).thenReturn(true);
        when(SMSOTPUtils.getMobileNumberRequestPage(authenticationContext))
                .thenReturn("/smsotpauthenticationendpoint/mobile.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "redirectToMobileNoReqPage",
                httpServletResponse, authenticationContext, null);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCode() throws Exception {
        mockStatic(SMSOTPUtils.class);
        context.setProperty(SMSOTPConstants.STATUS_CODE, "");
        when(SMSOTPUtils.isRetryEnabled(context)).thenReturn(true);
        when(SMSOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/smsotpauthenticationendpoint/smsotp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "checkStatusCode",
                httpServletResponse, context, null, SMSOTPConstants.ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCodeWithNullValue() throws Exception {
        mockStatic(SMSOTPUtils.class);
        context.setProperty(SMSOTPConstants.STATUS_CODE, null);
        when(SMSOTPUtils.isRetryEnabled(context)).thenReturn(true);
        when(SMSOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/smsotpauthenticationendpoint/smsotp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "checkStatusCode",
                httpServletResponse, context, null, SMSOTPConstants.ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCodeWithMismatch() throws Exception {
        mockStatic(SMSOTPUtils.class);
        context.setProperty(SMSOTPConstants.CODE_MISMATCH, "true");
        when(SMSOTPUtils.isRetryEnabled(context)).thenReturn(false);
        when(SMSOTPUtils.isEnableResendCode(context)).thenReturn(true);
        when(SMSOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/smsotpauthenticationendpoint/smsotpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "checkStatusCode",
                httpServletResponse, context, null, SMSOTPConstants.ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.ERROR_CODE_MISMATCH));
    }

    @Test
    public void testCheckStatusCodeWithTokenExpired() throws Exception {
        mockStatic(SMSOTPUtils.class);
        context.setProperty(SMSOTPConstants.TOKEN_EXPIRED, "token.expired");
        when(SMSOTPUtils.isEnableResendCode(context)).thenReturn(true);
        when(SMSOTPUtils.isRetryEnabled(context)).thenReturn(true);
        when(SMSOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/smsotpauthenticationendpoint/smsotp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "checkStatusCode",
                httpServletResponse, context, null, SMSOTPConstants.SMS_LOGIN_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.TOKEN_EXPIRED_VALUE));
    }

    @Test
    public void testProcessSMSOTPFlow() throws Exception {
        mockStatic(SMSOTPUtils.class);
        when(SMSOTPUtils.isSMSOTPDisableForLocalUser("John", context)).thenReturn(true);
        when(SMSOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(SMSOTPConstants.ERROR_PAGE);
        when(SMSOTPUtils.isEnableMobileNoUpdate(any(AuthenticationContext.class))).thenReturn(true);
        context.setProperty(SMSOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "processSMSOTPFlow", context,
                httpServletRequest, httpServletResponse, true, "John@carbon.super", "", "carbon.super", SMSOTPConstants
                        .ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testSendOTPDirectlyToMobile() throws Exception {
        mockStatic(SMSOTPUtils.class);
        when(SMSOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(true);
        when(SMSOTPUtils.getMobileNumberRequestPage(any(AuthenticationContext.class))).
                thenReturn("/smsotpauthenticationendpoint/mobile.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "processSMSOTPFlow", context,
                httpServletRequest, httpServletResponse, false, "John@carbon.super", "", "carbon.super", SMSOTPConstants
                        .ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testProcessSMSOTPDisableFlow() throws Exception {
        mockStatic(SMSOTPUtils.class);
        when(SMSOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        when(SMSOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(SMSOTPConstants.ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "processSMSOTPFlow", context,
                httpServletRequest, httpServletResponse, false, "John@carbon.super", "", "carbon.super", SMSOTPConstants
                        .ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
    }

    @Test
    public void testProcessWithLogoutTrue() throws AuthenticationFailedException, LogoutFailedException {
        when(context.isLogoutRequest()).thenReturn(true);
        AuthenticatorFlowStatus status = smsotpAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithLogoutFalse() throws Exception {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(SMSOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        when(context.isLogoutRequest()).thenReturn(false);
        when(httpServletRequest.getParameter(SMSOTPConstants.MOBILE_NUMBER)).thenReturn("true");
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when(context.getProperty(SMSOTPConstants.OTP_GENERATED_TIME)).thenReturn(anyLong());
        when((AuthenticatedUser)context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        when(SMSOTPUtils.isSMSOTPMandatory(context)).thenReturn(true);
        when(SMSOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(SMSOTPConstants.ERROR_PAGE);
        when(SMSOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "processSMSOTPFlow", context,
                httpServletRequest, httpServletResponse, false, "John@carbon.super", "", "carbon.super", SMSOTPConstants
                        .ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcessWithLogout() throws AuthenticationFailedException, LogoutFailedException {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(SMSOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        when(context.isLogoutRequest()).thenReturn(false);
        when(httpServletRequest.getParameter(SMSOTPConstants.CODE)).thenReturn("");
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setUserStoreDomain("secondary");
        context.setProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME, 1608101321322l);
        when((AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        when(SMSOTPUtils.isSMSOTPMandatory(context)).thenReturn(true);
        when(SMSOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(SMSOTPConstants.ERROR_PAGE);
        when(SMSOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        when(SMSOTPUtils.getBackupCode(context)).thenReturn("false");

        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testInitiateAuthenticationRequestWithSMSOTPMandatory() throws Exception {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(SMSOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when((AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        when(SMSOTPUtils.isSMSOTPMandatory(context)).thenReturn(true);
        when(SMSOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(SMSOTPConstants.ERROR_PAGE);
        when(SMSOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        when(SMSOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(SMSOTPConstants.ERROR_PAGE);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        when(SMSOTPUtils.getBackupCode(context)).thenReturn("false");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "initiateAuthenticationRequest",
                httpServletRequest, httpServletResponse, context);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
    }

    @Test
    public void testInitiateAuthenticationRequestWithSMSOTPOptional() throws Exception {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(SMSOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        context.setTenantDomain("carbon.super");
        context.setProperty(SMSOTPConstants.TOKEN_EXPIRED, "token.expired");
        when(context.isRetrying()).thenReturn(true);
        when(httpServletRequest.getParameter(SMSOTPConstants.RESEND)).thenReturn("false");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when((AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        when(SMSOTPUtils.isSMSOTPMandatory(context)).thenReturn(false);
        when(SMSOTPUtils.isRetryEnabled(context)).thenReturn(true);
        when(FederatedAuthenticatorUtil.isUserExistInUserStore(anyString())).thenReturn(true);
        when(SMSOTPUtils.getMobileNumberForUsername(anyString())).thenReturn("0778965320");
        when(SMSOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(SMSOTPConstants.LOGIN_PAGE);
        when(SMSOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(SMSOTPConstants.ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(smsotpAuthenticator, "initiateAuthenticationRequest",
                httpServletRequest, httpServletResponse, context);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(SMSOTPConstants.TOKEN_EXPIRED_VALUE));
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestWithoutAuthenticatedUser() throws Exception {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(SMSOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        context.setTenantDomain("carbon.super");
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        Whitebox.invokeMethod(smsotpAuthenticator, "initiateAuthenticationRequest",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {InvalidCredentialsException.class})
    public void testProcessAuthenticationResponseWithoutOTPCode() throws Exception {

        mockStatic(SMSOTPUtils.class);
        when(httpServletRequest.getParameter(SMSOTPConstants.CODE)).thenReturn("");
        when(SMSOTPUtils.isLocalUser(context)).thenReturn(true);
        Whitebox.invokeMethod(smsotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {InvalidCredentialsException.class})
    public void testProcessAuthenticationResponseWithResend() throws Exception {

        mockStatic(SMSOTPUtils.class);
        when(httpServletRequest.getParameter(SMSOTPConstants.CODE)).thenReturn("123456");
        when(httpServletRequest.getParameter(SMSOTPConstants.RESEND)).thenReturn("true");
        when(SMSOTPUtils.isLocalUser(context)).thenReturn(true);
        Whitebox.invokeMethod(smsotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test
    public void testProcessAuthenticationResponse() throws Exception {

        mockStatic(SMSOTPUtils.class);
        mockStatic(IdentityTenantUtil.class);
        context.setProperty(SMSOTPConstants.CODE_MISMATCH, false);
        when(httpServletRequest.getParameter(SMSOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(SMSOTPConstants.OTP_TOKEN,"123456");
        context.setProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME,"");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("admin");
        authenticatedUser.setTenantDomain("carbon.super");
        when((AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);

        Property property = new Property();
        property.setName(SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        when(SMSOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        Whitebox.invokeMethod(smsotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test
    public void testProcessAuthenticationResponseWithvalidBackupCode() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(SMSOTPUtils.class);
        when(httpServletRequest.getParameter(SMSOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(SMSOTPConstants.OTP_TOKEN,"123");
        context.setProperty(SMSOTPConstants.USER_NAME,"admin");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("admin");
        when((AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        when(SMSOTPUtils.getBackupCode(context)).thenReturn("true");

        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager
                .getUserClaimValue(anyString(),anyString(), anyString())).thenReturn("123456,789123");
        mockStatic(FrameworkUtils.class);
        when (FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");

        Property property = new Property();
        property.setName(SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        when(SMSOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});
        when(SMSOTPUtils.isLocalUser(context)).thenReturn(true);
        when(userStoreManager.getClaimManager()).thenReturn(claimManager);
        when(userStoreManager.getClaimManager().getClaim(SMSOTPConstants.SAVED_OTP_LIST)).thenReturn(claim);
        when(context.getProperty(SMSOTPConstants.CODE_MISMATCH)).thenReturn(false);

        Whitebox.invokeMethod(smsotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessAuthenticationResponseWithCodeMismatch() throws Exception {
        mockStatic(SMSOTPUtils.class);
        mockStatic(IdentityTenantUtil.class);
        when(httpServletRequest.getParameter(SMSOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(SMSOTPConstants.OTP_TOKEN,"123");
        context.setProperty(SMSOTPConstants.USER_NAME,"admin");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setTenantDomain("carbon.super");
        when((AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        when(SMSOTPUtils.getBackupCode(context)).thenReturn("false");

        Property property = new Property();
        property.setName(SMSOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        when(SMSOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});

        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        Whitebox.invokeMethod(smsotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test
    public void testCheckWithBackUpCodes() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        context.setProperty(SMSOTPConstants.USER_NAME,"admin");
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when((AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        SMSOTPConstants.SAVED_OTP_LIST, null)).thenReturn("12345,4568,1234,7896");
        AuthenticatedUser user = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
        mockStatic(FrameworkUtils.class);
        when (FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");
        Whitebox.invokeMethod(smsotpAuthenticator, "checkWithBackUpCodes",
                context,"1234",user);
    }

    public void testCheckWithInvalidBackUpCodes() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        mockStatic(SMSOTPUtils.class);
        context.setProperty(SMSOTPConstants.USER_NAME,"admin");
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when((AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        mockStatic(FrameworkUtils.class);
        when (FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        SMSOTPConstants.SAVED_OTP_LIST, null)).thenReturn("12345,4568,1234,7896");
        Whitebox.invokeMethod(smsotpAuthenticator, "checkWithBackUpCodes",
                context, "45698789", authenticatedUser);
    }

    @Test
    public void testGetScreenAttribute() throws UserStoreException, AuthenticationFailedException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(SMSOTPUtils.class);
        when(SMSOTPUtils.getScreenUserAttribute(context)).thenReturn
                ("http://wso2.org/claims/mobile");
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue("admin", "http://wso2.org/claims/mobile", null)).thenReturn("0778965231");
        when(SMSOTPUtils.getNoOfDigits(context)).thenReturn("4");

        // with forward order
        Assert.assertEquals(smsotpAuthenticator.getScreenAttribute(context,userRealm,"admin"),"0778******");

        // with backward order
        when(SMSOTPUtils.getDigitsOrder(context)).thenReturn("backward");
        Assert.assertEquals(smsotpAuthenticator.getScreenAttribute(context,userRealm,"admin"),"******5231");
    }

    @Test(expectedExceptions = {SMSOTPException.class})
    public void testUpdateMobileNumberForUsername() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
        Whitebox.invokeMethod(smsotpAuthenticator, "updateMobileNumberForUsername",
                context,httpServletRequest,"admin","carbon.super");
    }

    @Test
    public void testGetConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();
        Property smsUrl = new Property();
        configProperties.add(smsUrl);
        Property httpMethod = new Property();
        configProperties.add(httpMethod);
        Property headers = new Property();
        configProperties.add(headers);
        Property payload = new Property();
        configProperties.add(payload);
        Property httpResponse = new Property();
        configProperties.add(httpResponse);
        Property showErrorInfo = new Property();
        configProperties.add(showErrorInfo);
        Property maskValues = new Property();
        configProperties.add(maskValues);
        Property mobileNumberRegexPattern = new Property();
        configProperties.add(mobileNumberRegexPattern);
        Property mobileNumberPatternFailureErrorMessage = new Property();
        configProperties.add(mobileNumberPatternFailureErrorMessage);
        Assert.assertEquals(configProperties.size(), smsotpAuthenticator.getConfigurationProperties().size());
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}