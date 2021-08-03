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

package org.wso2.carbon.identity.smsotp.common.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.smsotp.common.SMSOTPService;
import org.wso2.carbon.identity.smsotp.common.SMSOTPServiceImpl;
import org.wso2.carbon.identity.smsotp.common.constant.Constants;
import org.wso2.carbon.identity.smsotp.common.util.Utils;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Properties;

/**
 * OSGI service component of the SMS OTP service.
 */
@Component(name = "org.wso2.carbon.identity.api.server.smsotp.commons",
           immediate = true
)
public class SMSOTPServiceComponent {

    private static final Log log = LogFactory.getLog(SMSOTPServiceComponent.class);

    @Activate
    protected void activate(ComponentContext componentContext) {

        try {
            Properties properties = Utils.readConfigurations();
            boolean isEnabled = Boolean.parseBoolean(properties.getProperty(Constants.SMS_OTP_ENABLED));
            if (isEnabled) {
                BundleContext bundleContext = componentContext.getBundleContext();
                bundleContext.registerService(SMSOTPService.class.getName(), new SMSOTPServiceImpl(), null);
                if (log.isDebugEnabled()) {
                    log.debug("SMS OTP Service component activated successfully.");
                }
            }
        } catch (Throwable e) {
            log.error("Error while activating the SMS OTP service.", e);
        }
    }

    @Reference(name = "realm.service",
               service = org.wso2.carbon.user.core.service.RealmService.class,
               cardinality = ReferenceCardinality.MANDATORY,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service.");
        }
        SMSOTPServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unset the Realm Service.");
        }
        SMSOTPServiceDataHolder.getInstance().setRealmService(null);
    }

    @Reference(name = "event.service",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetEventService")
    protected void setEventService(IdentityEventService eventService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Event Service.");
        }
    }

    protected void unsetEventService(IdentityEventService eventService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Event Service.");
        }
    }
}
