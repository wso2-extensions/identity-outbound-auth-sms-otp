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

package org.wso2.carbon.identity.smsotp.common;

import org.wso2.carbon.identity.smsotp.common.dto.GenerationResponseDTO;
import org.wso2.carbon.identity.smsotp.common.dto.ValidationResponseDTO;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPException;

/**
 * SMS OTP service interface.
 */
public interface SMSOTPService {

    /**
     * This method validates a provided OTP.
     *
     * @param transactionId                     UUID to track the flow.
     * @param userId                            SCIM Id.
     * @param smsOTP                            OTP to be validated.
     * @return {@link ValidationResponseDTO}    OTP validation result.
     * @throws {@link SMSOTPException}          Thrown if any server or client error occurred.
     */
    // TODO remove transaction Id after testing.
    ValidationResponseDTO validateSMSOTP(String transactionId, String userId, String smsOTP) throws SMSOTPException;

    /**
     * This method will generate an OTP and send an SMS notification.
     *
     * @param userId                            SCIM Id.
     * @return {@link GenerationResponseDTO}    OTP generation response.
     * @throws SMSOTPException                  Thrown if any server or client error occurred.
     */
    GenerationResponseDTO generateSMSOTP(String userId) throws SMSOTPException;
}
