/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants;
import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPUtils;
import org.wso2.carbon.identity.authenticator.smsotp.exception.SMSOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({FileBasedConfigurationBuilder.class, IdentityTenantUtil.class})
public class SMSOTPUtilsTest {

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    @Spy
    private AuthenticationContext context;


    @BeforeMethod
    public void setUp() throws Exception {
        mockStatic(FileBasedConfigurationBuilder.class);
        initMocks(this);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testGetConfigurationFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_SMSOTP_MANDATORY, true);
        authenticationContext.setProperty("getPropertiesFromLocal", null);
        Assert.assertEquals(SMSOTPUtils.getConfiguration(authenticationContext,
                SMSOTPConstants.IS_SMSOTP_MANDATORY), "true");
    }

    @Test
    public void testGetConfigurationFromLocalFile() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("carbon.super");
        authenticationContext.setProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY,
                IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(SMSOTPConstants.IS_SMSOTP_MANDATORY, "true");
        parameters.put(SMSOTPConstants.IS_ENABLED_RESEND, "true");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(SMSOTPUtils.getConfiguration(authenticationContext,
                SMSOTPConstants.IS_SMSOTP_MANDATORY), "true");
    }

    @Test
    public void testGetBackupCodeFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.BACKUP_CODE, true);
        Assert.assertEquals(SMSOTPUtils.getBackupCode(authenticationContext), "true");
    }

    @Test
    public void testGetDigitsOrderFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.ORDER, "backward");
        Assert.assertEquals(SMSOTPUtils.getDigitsOrder(authenticationContext), "backward");
    }

    @Test
    public void testGetNoOfDigitsFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.NO_DIGITS, "4");
        Assert.assertEquals(SMSOTPUtils.getNoOfDigits(authenticationContext), "4");
    }

    @Test
    public void testGetScreenUserAttributeFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.SCREEN_USER_ATTRIBUTE, "http://wso2.org/claims/mobile");
        Assert.assertEquals(SMSOTPUtils.getScreenUserAttribute(authenticationContext),
                "http://wso2.org/claims/mobile");
    }

    @Test
    public void testGetMobileNumberRequestPageFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE,
                "smsotpauthenticationendpoint/mobile.jsp");
        Assert.assertEquals(SMSOTPUtils.getMobileNumberRequestPage(authenticationContext),
                "smsotpauthenticationendpoint/mobile.jsp");
    }

    @Test
    public void testIsRetryEnabledFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_ENABLED_RETRY, "true");
        Assert.assertEquals(SMSOTPUtils.isRetryEnabled(authenticationContext), true);
    }

    @Test
    public void testGetErrorPageFromXMLFileFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL,
                SMSOTPConstants.ERROR_PAGE);
        Assert.assertEquals(SMSOTPUtils.getErrorPageFromXMLFile(authenticationContext),
                "smsotpauthenticationendpoint/smsotpError.jsp");
    }

    @Test
    public void testGetLoginPageFromXMLFileFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL,
                SMSOTPConstants.SMS_LOGIN_PAGE);
        Assert.assertEquals(SMSOTPUtils.getLoginPageFromXMLFile(authenticationContext),
                "smsotpauthenticationendpoint/smsotp.jsp");
    }

    @Test
    public void testIsEnableResendCodeFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_ENABLED_RESEND, "true");
        Assert.assertEquals(SMSOTPUtils.isEnableResendCode(authenticationContext), true);
    }

    @Test
    public void testIsEnableMobileNoUpdateFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE, "true");
        Assert.assertEquals(SMSOTPUtils.isEnableMobileNoUpdate(authenticationContext), true);
    }

    @Test
    public void testIsSMSOTPEnableByUserFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER, "true");
        Assert.assertEquals(SMSOTPUtils.isSMSOTPEnableOrDisableByUser(authenticationContext), true);
    }

    @Test
    public void testIsSendOTPDirectlyToMobileFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE, "true");
        Assert.assertEquals(SMSOTPUtils.isSendOTPDirectlyToMobile(authenticationContext), true);
    }

    @Test
    public void testIsSMSOTPMandatoryFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_SMSOTP_MANDATORY, "true");
        Assert.assertEquals(SMSOTPUtils.isSMSOTPMandatory(authenticationContext), true);
    }

    @Test
    public void testIsSMSOTPMandatoryFromLocalFile() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY,
                IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        authenticationContext.setProperty(SMSOTPConstants.IS_SMSOTP_MANDATORY, "true");
        authenticationContext.setTenantDomain("carbon.super");
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(SMSOTPConstants.IS_SMSOTP_MANDATORY, "true");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(SMSOTPUtils.isSMSOTPMandatory(authenticationContext), true);
    }

    @Test
    public void testIsEnableAlphanumericTokenFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_ENABLE_ALPHANUMERIC_TOKEN, "true");
        Assert.assertEquals(SMSOTPUtils.isEnableAlphanumericToken(authenticationContext), true);
    }

    @Test
    public void testTokenExpiryTimeFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.TOKEN_EXPIRY_TIME, "30");
        Assert.assertEquals(SMSOTPUtils.getTokenExpiryTime(authenticationContext), "30");
    }

    @Test
    public void testTokenLengthFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.TOKEN_LENGTH, "8");
        Assert.assertEquals(SMSOTPUtils.getTokenLength(authenticationContext), "8");
    }

    @Test
    public void testGetSMSParameters() {
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(SMSOTPConstants.IS_SMSOTP_MANDATORY, "true");
        parameters.put(SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE, "false");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);

        //test with empty parameters map.
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(null);
        Assert.assertEquals(SMSOTPUtils.getSMSParameters(), Collections.emptyMap());

        //test with non-empty parameters map.
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(SMSOTPUtils.getSMSParameters(), parameters);
    }

    @Test
    public void testIsSMSOTPDisableForLocalUser() throws UserStoreException, AuthenticationFailedException,
            SMSOTPException {
        mockStatic(IdentityTenantUtil.class);
        String username = "admin";
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(SMSOTPUtils.isSMSOTPEnableOrDisableByUser(context)).thenReturn(true);
        Map<String, String> claims = new HashMap<>();
        claims.put(SMSOTPConstants.USER_SMSOTP_DISABLED_CLAIM_URI, "false");
        userStoreManager.setUserClaimValues(MultitenantUtils.getTenantAwareUsername(username), claims, null);
        Assert.assertEquals(SMSOTPUtils.isSMSOTPDisableForLocalUser(anyString(), context), false);
    }

    @Test(expectedExceptions = {SMSOTPException.class})
    public void testVerifyUserExists() throws UserStoreException, AuthenticationFailedException, SMSOTPException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(SMSOTPUtils.getUserRealm("carbon.super")).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        SMSOTPUtils.verifyUserExists("admin", "carbon.super");
    }

    @Test
    public void testGetMobileNumberForUsername() throws UserStoreException, SMSOTPException,
            AuthenticationFailedException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Assert.assertEquals(SMSOTPUtils.getMobileNumberForUsername("admin"), null);
    }

    @Test(expectedExceptions = {SMSOTPException.class})
    public void testGetMobileNumberForUsernameWithException() throws UserStoreException, SMSOTPException,
            AuthenticationFailedException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
        SMSOTPUtils.getMobileNumberForUsername("admin");
    }

    @Test(expectedExceptions = {SMSOTPException.class})
    public void testUpdateUserAttributeWithException() throws UserStoreException, SMSOTPException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
        Map<String, String> claims = new HashMap<>();
        SMSOTPUtils.updateUserAttribute(anyString(), claims, "carbon.super");
    }

    @Test
    public void testUpdateUserAttribute() throws UserStoreException, SMSOTPException {
        mockStatic(IdentityTenantUtil.class);
        Map<String, String> claims = new HashMap<>();
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        SMSOTPUtils.updateUserAttribute("admin", claims, "carbon.super");
    }
}