/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.authenticator.smsotp;

public class SMSOTPConstants {
    public static final String AUTHENTICATOR_NAME = "SMSOTP";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "SMS OTP";
    public static final String ALGORITHM_NAME = "SHA1PRNG";
    public static final String ALGORITHM_HMAC = "HmacSHA1";
    public static final String ALGORITHM_HMAC_SHA = "HMAC-SHA-1";
    public static final String CHAR_SET = "UTF-8";

    public static final int SECRET_KEY_LENGTH = 5;
    public static final int NUMBER_BASE = 2;
    public static final int NUMBER_DIGIT = 6;
    public static final String CODE = "code";
    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    public static final String SAVED_OTP_LIST = "http://wso2.org/claims/otpbackupcodes";
    public static final String USER_SMSOTP_DISABLED_CLAIM_URI = "http://wso2.org/claims/identity/smsotp_disabled";

    public static final String SMS_URL = "sms_url";
    public static final String HTTP_METHOD = "http_method";
    public static final String HEADERS = "headers";
    public static final String PAYLOAD = "payload";
    public static final String HTTP_RESPONSE = "http_response";
    public static final String SMS_MESSAGE = "Verification Code: ";
    public static final String BACKUP_CODE = "BackupCode";
    public static final String IS_ENABLED_RETRY = "RetryEnable";
    public static final String IS_ENABLED_RESEND = "ResendEnable";
    public static final String IS_SMSOTP_MANDATORY = "SMSOTPMandatory";
    public static final String IS_SMSOTP_ENABLE_BY_USER = "EnableByUserClaim";
    public static final String IS_ENABLE_MOBILE_NO_UPDATE = "IsEnableMobileNoUpdate";
    public static final String IS_MOBILE_CLAIM = "MobileClaim";

    public static final String GET_METHOD = "GET";
    public static final String POST_METHOD = "POST";

    public static final String SMSOTP_AUTHENTICATION_ENDPOINT_URL = "SMSOTPAuthenticationEndpointURL";
    public static final String SMSOTP_AUTHENTICATION_ERROR_PAGE_URL = "SMSOTPAuthenticationEndpointErrorPage";

    public static final String LOGIN_PAGE = "authenticationendpoint/login.do";
    public static final String SMS_LOGIN_PAGE = "smsotpauthenticationendpoint/smsotp.jsp";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String ERROR_PAGE = "smsotpauthenticationendpoint/smsotpError.jsp";
    public static final String MOBILE_NUMBER_REQ_PAGE = "MobileNumberRegPage";
    public static final String MOBILE_NUMBER = "MOBILE_NUMBER";

    public static final String RESEND = "resendCode";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String RESEND_CODE = "&resendCode=";
    public static final String OTP_TOKEN = "otpToken";
    public static final String AUTHENTICATION = "authentication";
    public static final String BASIC = "basic";
    public static final String HTTPS = "https";
    public static final String SUPER_TENANT = "carbon.super";
    public static final String FEDERETOR = "federator";
    public static final String USER_NAME = "username";
    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String STATUS_CODE = "statusCode";
    public static final String UNABLE_SEND_CODE = "UnableSend";
    public static final String UNABLE_SEND_CODE_PARAM = "&authFailure=true&authFailureMsg=unable.send.code";
    public static final String ERROR_SMSOTP_DISABLE = "&authFailure=true&authFailureMsg=smsotp.disable";
}
