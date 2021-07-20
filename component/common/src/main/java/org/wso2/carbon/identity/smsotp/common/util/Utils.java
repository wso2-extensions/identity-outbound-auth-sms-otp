/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.smsotp.common.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.smsotp.common.constant.Constants;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPClientException;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPServerException;

/**
 * Util functions for SMS OTP service.
 */
public class Utils {

    public static SMSOTPClientException handleClientException(Constants.ErrorMessage error, String data) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new SMSOTPClientException(error.getMessage(), description, error.getCode());
    }

    public static SMSOTPClientException handleClientException(Constants.ErrorMessage error, String data,
            Throwable e) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new SMSOTPClientException(error.getMessage(), description, error.getCode(), e);
    }

    public static SMSOTPServerException handleServerException(Constants.ErrorMessage error, String data,
            Throwable e) {

        String message;
        if (StringUtils.isNotBlank(data)) {
            message = String.format(error.getMessage(), data);
        } else {
            message = error.getMessage();
        }
        return new SMSOTPServerException(message, error.getCode(), e);
    }

    public static SMSOTPServerException handleServerException(Constants.ErrorMessage error, String data) {

        String message;
        if (StringUtils.isNotBlank(data)) {
            message = String.format(error.getMessage(), data);
        } else {
            message = error.getMessage();
        }
        return new SMSOTPServerException(message, error.getCode());
    }
}
