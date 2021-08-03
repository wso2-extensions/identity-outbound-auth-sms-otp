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

package org.wso2.carbon.identity.smsotp.common.exception;

import org.wso2.carbon.identity.event.IdentityEventException;

/**
 * SMS OTP exception.
 */
public class SMSOTPException extends IdentityEventException {

    private String errorCode;
    private String message;
    private String description;

    public SMSOTPException(String errorCode, String message) {

        super(errorCode, message);
        this.errorCode = errorCode;
        this.message = message;
    }

    public SMSOTPException(String errorCode, String message, Throwable throwable) {

        super(errorCode, message, throwable);
        this.errorCode = errorCode;
        this.message = message;
    }

    public SMSOTPException(String errorCode, String message, String description) {

        super(errorCode, message);
        this.errorCode = errorCode;
        this.message = message;
        this.description = description;
    }

    public SMSOTPException(String errorCode, String message, String description, Throwable e) {

        super(errorCode, message, e);
        this.errorCode = errorCode;
        this.message = message;
        this.description = description;
    }

    @Override
    public String getErrorCode() {

        return errorCode;
    }

    @Override
    public String getMessage() {

        return message;
    }

    public String getDescription() {

        return description;
    }
}
