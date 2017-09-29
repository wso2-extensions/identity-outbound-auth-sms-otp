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
import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants;
import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({FileBasedConfigurationBuilder.class})
public class SMSOTPUtilsTest {

    private SMSOTPUtils smsotpUtils;

    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    @BeforeMethod
    public void setUp() throws Exception {
        smsotpUtils = new SMSOTPUtils();
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
    public void testGetConfigurationFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_SMSOTP_MANDATORY, true);
        authenticationContext.setProperty("getPropertiesFromLocal", null);
        Assert.assertEquals(SMSOTPUtils.getConfiguration(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME,
                SMSOTPConstants.IS_SMSOTP_MANDATORY), "true");
    }

    @Test
    public void testGetConfigurationFromLocalFile() throws Exception {
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
        Assert.assertEquals(SMSOTPUtils.getConfiguration(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME,
                SMSOTPConstants.IS_SMSOTP_MANDATORY), "true");
    }

    @Test
    public void testGetBackupCodeFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.BACKUP_CODE, true);
        Assert.assertEquals(SMSOTPUtils.getBackupCode(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                "true");
    }

    @Test
    public void testGetDigitsOrderFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.ORDER, "backward");
        Assert.assertEquals(SMSOTPUtils.getDigitsOrder(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                "backward");
    }

    @Test
    public void testGetNoOfDigitsFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.NO_DIGITS, "4");
        Assert.assertEquals(SMSOTPUtils.getNoOfDigits(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                "4");
    }

    @Test
    public void testGetScreenUserAttributeFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.SCREEN_USER_ATTRIBUTE, "http://wso2.org/claims/mobile");
        Assert.assertEquals(SMSOTPUtils.getScreenUserAttribute(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                "http://wso2.org/claims/mobile");
    }

    @Test
    public void testGetMobileNumberRequestPageFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE,
                "smsotpauthenticationendpoint/mobile.jsp");
        Assert.assertEquals(SMSOTPUtils.getMobileNumberRequestPage(authenticationContext,
                SMSOTPConstants.AUTHENTICATOR_NAME), "smsotpauthenticationendpoint/mobile.jsp");
    }

    @Test
    public void testIsRetryEnabledFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_ENABLED_RETRY, "true");
        Assert.assertEquals(SMSOTPUtils.isRetryEnabled(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                true);
    }

    @Test
    public void testGetErrorPageFromXMLFileFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL,
                SMSOTPConstants.ERROR_PAGE);
        Assert.assertEquals(SMSOTPUtils.getErrorPageFromXMLFile(authenticationContext,
                SMSOTPConstants.AUTHENTICATOR_NAME), "smsotpauthenticationendpoint/smsotpError.jsp");
    }

    @Test
    public void testGetLoginPageFromXMLFileFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL,
                SMSOTPConstants.SMS_LOGIN_PAGE);
        Assert.assertEquals(SMSOTPUtils.getLoginPageFromXMLFile(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                "smsotpauthenticationendpoint/smsotp.jsp");
    }

    @Test
    public void testIsEnableResendCodeFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_ENABLED_RESEND, "true");
        Assert.assertEquals(SMSOTPUtils.isEnableResendCode(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                true);
    }

    @Test
    public void testIsEnableMobileNoUpdateFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE, "true");
        Assert.assertEquals(SMSOTPUtils.isEnableMobileNoUpdate(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                true);
    }

    @Test
    public void testIsSMSOTPEnableByUserFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER, "true");
        Assert.assertEquals(SMSOTPUtils.isSMSOTPEnableOrDisableByUser(authenticationContext,
                SMSOTPConstants.AUTHENTICATOR_NAME), true);
    }

    @Test
    public void testIsSendOTPDirectlyToMobileFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE, "true");
        Assert.assertEquals(SMSOTPUtils.isSendOTPDirectlyToMobile(authenticationContext,
                SMSOTPConstants.AUTHENTICATOR_NAME), true);
    }

    @Test
    public void testIsSMSOTPMandatoryFromRegistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(SMSOTPConstants.IS_SMSOTP_MANDATORY, "true");
        Assert.assertEquals(SMSOTPUtils.isSMSOTPMandatory(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                true);
    }

    @Test
    public void testIsSMSOTPMandatoryFromLocalFile() throws Exception {
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
        Assert.assertEquals(SMSOTPUtils.isSMSOTPMandatory(authenticationContext, SMSOTPConstants.AUTHENTICATOR_NAME),
                true);
    }

    @Test
    public void testGetSMSParameters() throws Exception {
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
}