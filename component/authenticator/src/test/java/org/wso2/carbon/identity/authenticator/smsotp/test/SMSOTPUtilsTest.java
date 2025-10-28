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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

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

    private AutoCloseable mocks;

    @BeforeMethod
    public void setUp() throws Exception {
        mocks = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
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
        try (MockedStatic<FileBasedConfigurationBuilder> fbcbMock = Mockito.mockStatic(FileBasedConfigurationBuilder.class)) {
            fbcbMock.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
            authenticatorConfig.setParameterMap(parameters);
            when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
            Assert.assertEquals(SMSOTPUtils.getConfiguration(authenticationContext,
                    SMSOTPConstants.IS_SMSOTP_MANDATORY), "true");
        }
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
                "authenticationendpoint/mobile.jsp");
        Assert.assertEquals(SMSOTPUtils.getMobileNumberRequestPage(authenticationContext),
                "authenticationendpoint/mobile.jsp");
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
                "authenticationendpoint/smsOtpError.jsp");
    }

    @Test
    public void testGetLoginPageFromXMLFileFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL,
                SMSOTPConstants.SMS_LOGIN_PAGE);
        Assert.assertEquals(SMSOTPUtils.getLoginPageFromXMLFile(authenticationContext),
                "authenticationendpoint/smsOtp.jsp");
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
        try (MockedStatic<FileBasedConfigurationBuilder> fbcbMock = Mockito.mockStatic(FileBasedConfigurationBuilder.class)) {
            fbcbMock.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
            authenticatorConfig.setParameterMap(parameters);
            when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
            Assert.assertEquals(SMSOTPUtils.isSMSOTPMandatory(authenticationContext), true);
        }
    }

    @DataProvider
    public Object[][] maximumResendAttemptsDataProvider() {

        return new Object[][]{
                {false, "2", Optional.of(2)},
                {false, "0", Optional.of(0)},
                {false, null, Optional.empty()},
                {true, "-2", null},
                {true, "test", null}
        };
    }

    @Test(dataProvider = "maximumResendAttemptsDataProvider")
    public void testMaximumResendAttemptsFromLocalFile(boolean expectException, String maxAttemptsFromFile,
                                                       Optional<Integer> expectedResult) throws SMSOTPException {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY,
                IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        authenticationContext.setTenantDomain("carbon.super");
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();

        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(SMSOTPConstants.MAXIMUM_RESEND_ATTEMPTS, maxAttemptsFromFile);
        try (MockedStatic<FileBasedConfigurationBuilder> fbcbMock = Mockito.mockStatic(FileBasedConfigurationBuilder.class)) {
            fbcbMock.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
            authenticatorConfig.setParameterMap(parameters);
            when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
            if (expectException) {
                Assert.assertThrows(SMSOTPException.class, () -> SMSOTPUtils.getMaxResendAttempts(authenticationContext));
            } else {
                Assert.assertEquals(SMSOTPUtils.getMaxResendAttempts(authenticationContext), expectedResult);
            }
        }
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

        try (MockedStatic<FileBasedConfigurationBuilder> fbcbMock = Mockito.mockStatic(FileBasedConfigurationBuilder.class)) {
            fbcbMock.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);

            // test with empty parameters map.
            when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(null);
            Assert.assertEquals(SMSOTPUtils.getSMSParameters(), Collections.emptyMap());

            // test with non-empty parameters map.
            authenticatorConfig.setParameterMap(parameters);
            when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
            Assert.assertEquals(SMSOTPUtils.getSMSParameters(), parameters);
        }
    }

    @Test
    public void testIsSMSOTPDisableForLocalUser() throws UserStoreException, AuthenticationFailedException,
            SMSOTPException {
        String username = "admin@carbon.super";
        try (MockedStatic<IdentityTenantUtil> identityTenantUtilMock = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<SMSOTPUtils> smsotpUtilsStatic = Mockito.mockStatic(SMSOTPUtils.class, Mockito.CALLS_REAL_METHODS)) {

            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
            identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
            when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
            when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

            smsotpUtilsStatic.when(() -> SMSOTPUtils.isSMSOTPEnableOrDisableByUser(context)).thenReturn(true);

            Map<String, String> claims = new HashMap<>();
            claims.put(SMSOTPConstants.USER_SMSOTP_DISABLED_CLAIM_URI, "false");
            when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), any()))
                    .thenReturn(claims);

            Assert.assertFalse(SMSOTPUtils.isSMSOTPDisableForLocalUser(username, context));
        }
    }

    @Test(expectedExceptions = {SMSOTPException.class})
    public void testVerifyUserExists() throws UserStoreException, AuthenticationFailedException, SMSOTPException {
        try (MockedStatic<IdentityTenantUtil> identityTenantUtilMock = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<SMSOTPUtils> smsotpUtilsStatic = Mockito.mockStatic(SMSOTPUtils.class, Mockito.CALLS_REAL_METHODS)) {

            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
            identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
            when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);

            smsotpUtilsStatic.when(() -> SMSOTPUtils.getUserRealm("carbon.super")).thenReturn(userRealm);
            when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

            // Default for isExistingUser is false -> should throw SMSOTPException.
            SMSOTPUtils.verifyUserExists("admin", "carbon.super");
        }
    }

    @Test
    public void testGetMobileNumberForUsername() throws UserStoreException, SMSOTPException,
            AuthenticationFailedException {
        try (MockedStatic<IdentityTenantUtil> identityTenantUtilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
            identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
            when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
            when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
            Assert.assertEquals(SMSOTPUtils.getMobileNumberForUsername("admin@carbon.super"), null);
        }
    }

    @Test(expectedExceptions = {SMSOTPException.class})
    public void testGetMobileNumberForUsernameWithException() throws UserStoreException, SMSOTPException,
            AuthenticationFailedException {
        try (MockedStatic<IdentityTenantUtil> identityTenantUtilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
            identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
            when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
            SMSOTPUtils.getMobileNumberForUsername("admin@carbon.super");
        }
    }

    @Test(expectedExceptions = {SMSOTPException.class})
    public void testUpdateUserAttributeWithException() throws UserStoreException, SMSOTPException {
        try (MockedStatic<IdentityTenantUtil> identityTenantUtilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
            identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
            when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
            Map<String, String> claims = new HashMap<>();
            SMSOTPUtils.updateUserAttribute("admin", claims, "carbon.super");
        }
    }

    @Test
    public void testUpdateUserAttribute() throws UserStoreException, SMSOTPException {
        try (MockedStatic<IdentityTenantUtil> identityTenantUtilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            Map<String, String> claims = new HashMap<>();
            identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
            identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
            when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
            when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
            when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
            SMSOTPUtils.updateUserAttribute("admin", claims, "carbon.super");
        }
    }
}
