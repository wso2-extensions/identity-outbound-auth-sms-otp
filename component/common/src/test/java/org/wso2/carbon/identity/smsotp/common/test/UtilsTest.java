/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.smsotp.common.test;

import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.smsotp.common.constant.Constants;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPClientException;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPServerException;
import org.wso2.carbon.identity.smsotp.common.util.Utils;

@PrepareForTest({ IdentityEventConfigBuilder.class })
public class UtilsTest {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.initMocks(this);
    }

    @AfterMethod
    public void tearDown() {

    }

    @Test
    public void testHandleClientException() {

        String data = "sample data";
        SMSOTPClientException exception =
                Utils.handleClientException(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED, data);
        Assert.assertEquals(exception.getErrorCode(), Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getCode());
        Assert.assertEquals(exception.getMessage(), Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getMessage());
        Assert.assertEquals(exception.getDescription(),
                String.format(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getDescription(), data));
    }

    @Test
    public void testHandleClientExceptionWithThrowable() {

        String data = "sample data";
        Exception e = new Exception();
        SMSOTPClientException exception =
                Utils.handleClientException(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED, data, e);
        Assert.assertEquals(exception.getErrorCode(), Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getCode());
        Assert.assertEquals(exception.getMessage(), Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getMessage());
        Assert.assertEquals(exception.getCause(), e);
        Assert.assertEquals(exception.getDescription(),
                String.format(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getDescription(), data));
    }

    @Test
    public void testHandleServerException() {

        String data = "sample data";
        SMSOTPServerException exception =
                Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR, data);
        Assert.assertEquals(exception.getErrorCode(), Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getCode());
        Assert.assertEquals(exception.getMessage(), Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getMessage());
        Assert.assertEquals(exception.getDescription(),
                String.format(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getDescription(), data));
    }

    @Test
    public void testHandleServerExceptionWithThrowable() {

        String data = "sample data";
        Exception e = new Exception();
        SMSOTPServerException exception =
                Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR, data, e);
        Assert.assertEquals(exception.getErrorCode(), Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getCode());
        Assert.assertEquals(exception.getMessage(), Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getMessage());
        Assert.assertEquals(exception.getCause(), e);
        Assert.assertEquals(exception.getDescription(),
                String.format(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getDescription(), data));
    }
}
