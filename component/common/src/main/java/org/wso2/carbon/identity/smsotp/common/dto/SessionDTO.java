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

package org.wso2.carbon.identity.smsotp.common.dto;

import java.io.Serializable;
import java.util.Objects;

/**
 *  Session object model.
 */
public class SessionDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String otp;
    private long generatedTime;
    private long expiryTime;
    private String transactionId;
    private String fullQualifiedUserName;
    private String userId;

    public String getOtp() {

        return otp;
    }

    public void setOtp(String otp) {

        this.otp = otp;
    }

    public long getGeneratedTime() {

        return generatedTime;
    }

    public void setGeneratedTime(long generatedTime) {

        this.generatedTime = generatedTime;
    }

    public long getExpiryTime() {

        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {

        this.expiryTime = expiryTime;
    }

    public String getTransactionId() {

        return transactionId;
    }

    public void setTransactionId(String transactionId) {

        this.transactionId = transactionId;
    }

    public String getFullQualifiedUserName() {

        return fullQualifiedUserName;
    }

    public void setFullQualifiedUserName(String fullQualifiedUserName) {

        this.fullQualifiedUserName = fullQualifiedUserName;
    }

    public String getUserId() {

        return userId;
    }

    public void setUserId(String userId) {

        this.userId = userId;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (!(o instanceof SessionDTO)) {
            return false;
        }
        SessionDTO that = (SessionDTO) o;
        return getGeneratedTime() == that.getGeneratedTime() &&
                getExpiryTime() == that.getExpiryTime() &&
                getOtp().equals(that.getOtp()) &&
                getTransactionId().equals(that.getTransactionId()) &&
                getFullQualifiedUserName().equals(that.getFullQualifiedUserName()) &&
                getUserId().equals(that.getUserId());
    }

    @Override
    public int hashCode() {

        return Objects.hash(getOtp(), getGeneratedTime(), getExpiryTime(), getTransactionId(),
                getFullQualifiedUserName(), getUserId());
    }

    @Override
    public String toString() {

        return "SessionDTO{" +
                "otpToken='" + otp + '\'' +
                ", generatedTime=" + generatedTime +
                ", expiryTime=" + expiryTime +
                ", transactionId='" + transactionId + '\'' +
                ", fullQualifiedUserName='" + fullQualifiedUserName + '\'' +
                ", userId='" + userId + '\'' +
                '}';
    }
}
