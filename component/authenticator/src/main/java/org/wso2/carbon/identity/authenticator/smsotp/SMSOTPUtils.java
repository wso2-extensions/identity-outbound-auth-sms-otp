/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.smsotp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.authenticator.smsotp.exception.SMSOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

public class SMSOTPUtils {

    private static Log log = LogFactory.getLog(SMSOTPUtils.class);

    /**
     * Get parameter values from application-authentication.xml local file.
     */
    public static Map<String, String> getSMSParameters() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(SMSOTPConstants.AUTHENTICATOR_NAME);
        return authConfig.getParameterMap();
    }

    /**
     * Check whether SMSOTP is disable by user.
     *
     * @param username the user name
     * @param context  the authentication context
     * @return true or false
     * @throws SMSOTPException
     */
    public static boolean isSMSOTPDisableForLocalUser(String username, AuthenticationContext context) throws SMSOTPException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            boolean isEnableORDisableLocalUserClaim = Boolean.parseBoolean(getSMSParameters()
                    .get(SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER));
            if (userRealm != null) {
                if (isEnableORDisableLocalUserClaim) {
                    String isSMSOTPEnabledByUser = userRealm.getUserStoreManager().getUserClaimValue(username,
                            SMSOTPConstants.USER_SMSOTP_DISABLED_CLAIM_URI, null);
                    return Boolean.parseBoolean(isSMSOTPEnabledByUser);
                }
            } else {
                throw new SMSOTPException("Cannot find the user realm for the given tenant domain : " + CarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new SMSOTPException("Failed while trying to access userRealm of the user : " + username, e);
        }
        return false;
    }

    /**
     * Update the user attribute.
     *
     * @param username  the user name
     * @param attribute the attribute
     * @throws SMSOTPException
     */
    public static void updateUserAttribute(String username, Map<String, String> attribute, String tenantDomain)
            throws SMSOTPException {

        try {
            // updating user attributes is independent from tenant association.not tenant association check needed here.
            UserRealm userRealm;
            // user is always in the super tenant.
            userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
            if (userRealm == null) {
                throw new SMSOTPException(String.format("The specified tenant domain does not exist."));
            }
            // check whether user already exists in the system.
            SMSOTPUtils.validateUpdateUser(username, tenantDomain);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(username, attribute, null);
        } catch (Exception e) {
            throw new SMSOTPException(e.getMessage());
        }
    }

    /**
     * Validate the user.
     *
     * @param username the user name
     * @throws SMSOTPException
     */
    public static void validateUpdateUser(String username, String tenantDomain) throws SMSOTPException {
        UserRealm userRealm = null;
        boolean isUserExist = false;
        try {
            userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
            if (userRealm == null) {
                throw new SMSOTPException("Super tenant realm not loaded.");
            }
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager.isExistingUser(username)) {
                isUserExist = true;
            }
        } catch (Exception e) {
            throw new SMSOTPException("Error while validating the user" + e.getMessage());
        }

        if (!isUserExist) {
            throw new SMSOTPException("User does not exist in the system.");
        }
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param username the user name
     * @return th user realm
     * @throws AuthenticationFailedException
     */
    private static org.wso2.carbon.user.core.UserRealm getUserRealm(String username) throws AuthenticationFailedException {
        org.wso2.carbon.user.core.UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = (org.wso2.carbon.user.core.UserRealm) realmService.getTenantUserRealm(tenantId);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Cannot find the user realm", e);
        }
        return userRealm;
    }
}
