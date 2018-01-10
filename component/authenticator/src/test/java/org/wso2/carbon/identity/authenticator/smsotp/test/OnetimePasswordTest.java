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

import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.authenticator.smsotp.OneTimePassword;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.mockito.MockitoAnnotations.initMocks;

public class OnetimePasswordTest {
    private OneTimePassword oneTimePassword;

    @BeforeMethod
    public void setUp() throws Exception {
        oneTimePassword = new OneTimePassword();
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
    public void testCalcChecksum() {
        Assert.assertEquals(OneTimePassword.calcChecksum(100, 10), 8);
    }

    @Test
    public void testGetRandomNumber() {
        Assert.assertNotNull(OneTimePassword.getRandomNumber(10));
    }

    @Test
    public void testHmacShaGenerate() throws InvalidKeyException, NoSuchAlgorithmException {
        String input = "Hello World";
        byte[] bytes = input.getBytes(Charset.forName("UTF-8"));
        byte[] answer = OneTimePassword.hmacShaGenerate(bytes, bytes);
        String s = new String(answer, Charset.forName("UTF-8"));
        Assert.assertNotNull(OneTimePassword.hmacShaGenerate(bytes, bytes));
    }

    @Test
    public void testGenerateTokenWithNumericToken() throws Exception {
        OneTimePassword otp = PowerMockito.spy(oneTimePassword);
        Assert.assertEquals(Whitebox.invokeMethod(otp, "generateToken", "Hello", "32", 10, false),
                "0701282405");
    }

    @Test
    public void testGenerateTokenWithAlphaNumericToken() throws Exception {
        OneTimePassword otp = PowerMockito.spy(oneTimePassword);
        Assert.assertEquals(Whitebox.invokeMethod(otp, "generateToken", "Hello", "32", 10, true),
                "IWYTV8DJ31");
    }
}
