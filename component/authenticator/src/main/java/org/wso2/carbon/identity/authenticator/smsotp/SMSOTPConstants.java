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

import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

public class SMSOTPConstants {

    private static final String SMSOTP_PREFIX = "SMSOTP-";
    public static final String AUTHENTICATOR_NAME = "SMSOTP";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "SMS OTP";
    public static final String ALGORITHM_NAME = "DRBG";
    public static final String ALGORITHM_HMAC = "HmacSHA256";
    public static final String ALGORITHM_HMAC_SHA = "HMAC-SHA-256";
    public static final String CHAR_SET_UTF_8 = "UTF-8";

    public static final int SECRET_KEY_LENGTH = 5;
    public static final int NUMBER_BASE = 2;
    public static final int NUMBER_DIGIT = 6;
    public static final int DEFAULT_VALIDITY_PERIOD = 900;
    public static final String CODE = "OTPcode";
    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    public static final String SAVED_OTP_LIST = "http://wso2.org/claims/otpbackupcodes";
    public static final String OTP_BACKUP_CODES_IDENTITY_CLAIM = "http://wso2.org/claims/identity/otpbackupcodes";
    public static final String HANDLE_BACKUP_CODES_AS_IDENTITY_CLAIM = "OTPBackupCodes.UseIdentityClaims";
    public static final String BACKUP_CODES_SEPARATOR = ",";
    public static final String USER_SMSOTP_DISABLED_CLAIM_URI = "http://wso2.org/claims/identity/smsotp_disabled";
    public static final String SMS_OTP_FAILED_ATTEMPTS_CLAIM = "http://wso2.org/claims/identity/failedSmsOtpAttempts";
    public static final String FAILED_LOGIN_LOCKOUT_COUNT_CLAIM =
            "http://wso2.org/claims/identity/failedLoginLockoutCount";
    public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
    public static final String ACCOUNT_LOCKED_REASON_CLAIM_URI = "http://wso2.org/claims/identity/lockedReason";

    public static final String SMS_URL = "sms_url";
    public static final String HTTP_METHOD = "http_method";
    public static final String HEADERS = "headers";
    public static final String PAYLOAD = "payload";
    public static final String HTTP_RESPONSE = "http_response";
    public static final String MOBILE_NUMBER_REGEX = "mobile_number_regex";
    public static final String MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE =
            "mobile_number_pattern_failure_error_message";
    public static final String SHOW_ERROR_INFO = "show_detailed_error_info";
    public static final String VALUES_TO_BE_MASKED_IN_ERROR_INFO = "values_to_be_masked";
    public static final String SMS_MESSAGE = "Verification Code: ";
    public static final String BACKUP_CODE = "BackupCode";
    public static final String IS_ENABLED_RETRY = "RetryEnable";
    public static final String IS_ENABLED_RESEND = "ResendEnable";
    public static final String IS_SMSOTP_MANDATORY = "SMSOTPMandatory";
    public static final String IS_SEND_OTP_DIRECTLY_TO_MOBILE = "SendOTPDirectlyToMobile";
    public static final String IS_SMSOTP_ENABLE_BY_USER = "SMSOTPEnableByUserClaim";
    public static final String IS_ENABLE_MOBILE_NO_UPDATE = "CaptureAndUpdateMobileNumber";
    public static final String IS_ENABLE_ALPHANUMERIC_TOKEN = "EnableAlphanumericToken";
    public static final String TOKEN_EXPIRY_TIME = "TokenExpiryTime";
    public static final String TOKEN_LENGTH = "TokenLength";
    public static final String USE_INTERNAL_ERROR_CODES = "UseInternalErrorCodes";
    public static final String SHOW_AUTH_FAILURE_REASON = "showAuthFailureReason";
    public static final String ENABLE_ACCOUNT_LOCKING_FOR_FAILED_ATTEMPTS = "EnableAccountLockingForFailedAttempts";
    public static final String ENABLE_PAYLOAD_ENCODING_FOR_SMS_OTP = "enable_payload_encoding_for_sms_otp";

    public static final String GET_METHOD = "GET";
    public static final String POST_METHOD = "POST";

    public static final String CONTENT_TYPE = "Content-Type";
    public static final String JSON_CONTENT_TYPE = "application/json";
    public static final String XML_CONTENT_TYPE = "text/xml;charset=UTF-8";

    public static final String SMSOTP_AUTHENTICATION_ENDPOINT_URL = "SMSOTPAuthenticationEndpointURL";
    public static final String SMSOTP_AUTHENTICATION_ERROR_PAGE_URL = "SMSOTPAuthenticationEndpointErrorPage";

    public static final String LOGIN_PAGE = "authenticationendpoint/login.do";
    public static final String SMS_LOGIN_PAGE = "authenticationendpoint/smsOtp.jsp";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String ERROR_PAGE = "authenticationendpoint/smsOtpError.jsp";
    public static final String MOBILE_NO_REQ_PAGE = "authenticationendpoint/mobile.jsp";
    public static final String MOBILE_NUMBER_REQ_PAGE = "MobileNumberRegPage";
    public static final String MOBILE_NUMBER = "MOBILE_NUMBER";
    public static final String REQUESTED_USER_MOBILE = "requestedUserMobile";
    public static final String MOBILE_NUMBER_UPDATE_FAILURE = "mobileUpdateFailure";
    public static final String PROFILE_UPDATE_FAILURE_REASON = "profileUpdateFailureReason";

    public static final String RESEND = "resendCode";
    public static final String NAME_OF_AUTHENTICATORS = "authenticators=";
    public static final String RESEND_CODE = "&resendCode=";
    public static final String MOBILE_NUMBER_REGEX_PATTERN_QUERY = "&mobileNumberRegexPattern=";
    public static final String MOBILE_NUMBER_REGEX_PATTERN = "mobileNumberRegexPattern";
    public static final String MOBILE_NUMBER_PATTERN_POLICY_FAILURE_ERROR_MESSAGE_QUERY =
            "&mobileNumberPatternPolicyFailureErrorMessage=";
    public static final String MOBILE_NUMBER_PATTERN_POLICY_FAILURE_ERROR_MESSAGE =
            "mobileNumberPatternPolicyFailureErrorMessage";
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
    public static final String ERROR_MESSAGE = "&authFailure=true&authFailureMsg=";
    public static final String ERROR_MESSAGE_DETAILS = "&authFailureInfo=";
    public static final String AUTH_FAILURE_INFO = "authFailureInfo";
    public static final String ERROR_INFO = "errorInfo";
    public static final String MASKING_VALUE_SEPARATOR = ",";
    public static final String UNABLE_SEND_CODE_VALUE = "unable.send.code";
    public static final String ERROR_SMSOTP_DISABLE = "&authFailure=true&authFailureMsg=smsotp.disable";
    public static final String ERROR_SMSOTP_DISABLE_MSG = "smsotp.disable";
    public static final String SEND_OTP_DIRECTLY_DISABLE = "&authFailure=true&authFailureMsg=directly.send.otp.disable";
    public static final String ERROR_USER_NOT_FOUND = "&authFailure=true&authFailureMsg=error.user.not.found.smsotp";
    public static final String SEND_OTP_DIRECTLY_DISABLE_MSG = "directly.send.otp.disable";
    public static final String ERROR_CODE_MISMATCH = "code.mismatch";
    public static final String ERROR_CODE = "errorCode";
    public static final String SCREEN_USER_ATTRIBUTE = "screenUserAttribute";
    public static final String NO_DIGITS = "noOfDigits";
    public static final String ORDER = "order";
    public static final String BACKWARD = "backward";
    public static final String SCREEN_VALUE = "&screenvalue=";
    public static final String CODE_MISMATCH = "codeMismatch";
    public static final String ACCOUNT_LOCKED = "accountLocked";
    public static final String ACCOUNT_LOCKED_ERROR = "user.account.locked";
    public static final String TOKEN_VALIDITY_TIME = "tokenValidityTime";
    public static final String SENT_OTP_TOKEN_TIME = "sentOTPTokenTime";
    public static final String TOKEN_EXPIRED = "tokenExpired";
    public static final String TOKEN_EXPIRED_VALUE = "token.expired";
    public static final String ATTRIBUTE_SMS_SENT_TO = "send-to" ;
    public static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    public static final String EVENT_NAME = "SMSOTP";
    public static final String LOCAL_AUTHENTICATOR = "LOCAL";
    public static final String FEDERATED_MOBILE_ATTRIBUTE_KEY = "federatedMobileAttributeKey";
    public static final String IS_SEND_OTP_TO_FEDERATED_MOBILE = "SendOtpToFederatedMobile";
    public static final String MOBILE_NUMBER_PATTERN_POLICY_VIOLATED =
            "Mobile number pattern policy violated";

    public static final String PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO = "account.lock.handler.login.fail.timeout.ratio";
    public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE = "account.lock.handler.enable";
    public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX = "account.lock.handler.On.Failure.Max.Attempts";
    public static final String PROPERTY_ACCOUNT_LOCK_TIME = "account.lock.handler.Time";
    public static final String ERROR_USER_ACCOUNT_LOCKED = "&authFailure=true&authFailureMsg=user.account.locked";
    public static final String ERROR_TENANT_MISMATCH =
            "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message";
    public static final String ADMIN_INITIATED = "AdminInitiated";

    public static final String USER_AGENT = "user-agent";
    public static final String X_FORWARDED_FOR = "x-forwarded-for";
    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_OTP_EXPIRED = "otp-expired";
    public static final String STATUS_CODE_MISMATCH = "code-mismatch";
    public static final String OTP_GENERATED_TIME = "otp-generated-time";
    public static final String MULTI_OPTION_URI = "multiOptionURI";

    public static final String CORRELATION_ID_MDC = "Correlation-ID";
    public static final String CORRELATION_ID = "correlation-id";
    public static final String MAX_SMS_OTP_ATTEMPTS_EXCEEDED = "MAX_SMS_OTP_ATTEMPTS_EXCEEDED";

    public static final String IS_IDF_INITIATED_FROM_AUTHENTICATOR = "isIdfInitiatedFromAuthenticator";
    public static final String IDF_HANDLER_NAME = "IdentifierExecutor";
    public static final String USER = "user";
    public static final String SMS_OTP_NUMERIC_OTP = "OnlyNumericCharactersForSmsOtp";
    public static final String IS_CHAR_IN_OTP = "IsCharInOTP";
    public static final String SMS_OTP_EXPIRY_TIME = "SmsOtpExpiryTime";
    public static final int SMS_OTP_MAX_EXPIRY_TIME = 1440;
    public static final int SMS_OTP_MIN_EXPIRY_TIME = 1;
    public static final String OTP_EXPIRE_TIME_DEFAULT = "300000";
    public static final String OTP_EXPIRE_TIME_DEFAULT_IN_MINS = "5";
    public static final String SMS_OTP_LENGTH = "SmsOtpLength";
    public static final int SMS_OTP_MIN_LENGTH = 4;
    public static final int SMS_OTP_MAX_LENGTH = 10;
    public static final String SMS_OTP_NUMERIC_CHAR_SET = "9245378016";
    public static final String SMS_OTP_UPPER_CASE_ALPHABET_CHAR_SET = "KIGXHOYSPRWCEFMVUQLZDNABJT";
    public static final String IS_REDIRECT_TO_SMS_OTP = "isRedirectToSmsOTP";
    public static final String TOKEN_EXPIRE_TIME_IN_MILIS = "tokenExpirationTime";
    public static final String USE_CASE = "usecase";
    public static final String AUTHENTICATOR_SMS_OTP = "authenticator.sms.otp";
    public static final String CODE_PARAM = "code.param";
    public static final String USERNAME_PARAM = "username.param";

    /**
     * Enums for error messages.
     */
    public enum ErrorMessage {

        CLIENT_BAD_REQUEST("60001", "Bad request. Please check the request and re-submit"),
        CLIENT_UNAUTHORIZED("60002", "Unauthorized request. Server is not authorized to access the SMS Provider"),
        CLIENT_PAYMENT_REQUIRED("60003", "Payment requirement for the request."),
        CLIENT_FORBIDDEN("60004", "Server is permitted to access the SMS Provider URL."),
        CLIENT_NOT_FOUND("60005", "Not Found. Please note that SMS Provider resource is not found."),
        CLIENT_METHOD_NOT_ALLOWED("60006", "Method Not Allowed. HTTP method used by the Server to connect SMS " +
                "provider is allowed"),
        CLIENT_NOT_ACCEPTABLE("60007", "Not Acceptable. Please note that the requested media type cannot be " +
                "generated."), //406
        SERVER_INTERNAL_ERROR("65001", "Internal Error in the SMS Provider Server."),
        SERVER_NOT_IMPLEMENTED("65002", "Not Implemented. SMS Provider Server cannot recognize the request method."),
        SERVER_BAD_GATEWAY("65003", "Bad Gateway or SMS Provider server overloaded."),
        SERVER_UNAVAILABLE("65004", "SMS Service unavailable or gateway time-out."),
        SERVER_TIMEOUT("65005", "Secondary gateway or SMS provider server time-out."),
        MALFORMED_URL("10001", "The SMS URL does not conform to URL specification."),
        SERVER_UNKNOWN_ERROR("10002", "Unknown error occured. Please try again.");

        private final String code;
        private final String message;

        private static final Map<String, ErrorMessage> errorIndex = new HashMap<>(ErrorMessage.values().length);
        static final String BUNDLE = "ServerClientErrorMappings";
        static ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE);

        static {
            for (ErrorMessage em : ErrorMessage.values()) {
                errorIndex.put(em.getCode(), em);
            }
        }

        ErrorMessage(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return SMSOTP_PREFIX + code;
        }

        public String getMessage() {

            return message;
        }

        public String toString() {

            return getCode() + " | " + message;
        }

        /**
         * Get the proper error message mapped to the server error code.
         *
         * @param serverErrorCode Server error code.
         * @return Respective error message for the server error code.
         */
        public static String getMappedErrorMessage(String serverErrorCode) {

            return errorIndex.get(serverErrorCode).getMessage();
        }

        /**
         * Get the proper server side error code mapped to the error response from the SMS Provider.
         *
         * @param smsProviderErrorCode SMS Provider Error Code.
         * @return Respective server error code for the SMS Provider error code.
         */
        public static ErrorMessage getMappedInternalErrorCode(String smsProviderErrorCode) {

            if (resourceBundle.containsKey(smsProviderErrorCode)) {
                return errorIndex.get(SMSOTP_PREFIX + resourceBundle.getString(smsProviderErrorCode));
            } else if (errorIndex.containsKey(SMSOTPConstants.SMSOTP_PREFIX + smsProviderErrorCode)) {
                return errorIndex.get(SMSOTPConstants.SMSOTP_PREFIX + smsProviderErrorCode);
            }
            return ErrorMessage.SERVER_UNKNOWN_ERROR;
        }
    }

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String OUTBOUND_AUTH_SMSOTP_SERVICE = "outbound-auth-sms-otp";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String SEND_SMS_OTP = "send-sms-otp";
        }
    }
}
