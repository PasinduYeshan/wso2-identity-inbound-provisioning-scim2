/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim2.common.handlers;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.scim2.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.charon3.core.exceptions.CharonException;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class SCIMBulkUserOperationEventHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(SCIMBulkUserOperationEventHandler.class);

    @Override
    public String getName() {
        return "SCIMBulkUserOperationEventHandler";
    }

    public String getFriendlyName() {
        return "SCIM Bulk User Operation Notification Handler";
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {
        if (!isHandlerEnabled()) {
            log.debug("SCIM Bulk User Operation Event Handler is not enabled");
            return false;
        }

        Event event = ((IdentityEventMessageContext) messageContext).getEvent();
        String eventName = event.getEventName();

        // TODO: Implement PRE_BULK_ADD_USER event. -> Database save.
        if (IdentityEventConstants.Event.POST_BULK_ADD_USER.equals(eventName)) {
            return true;
        }
        return false;
    }

    /**
     * Handle Event
     *
     * @param event Event.
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {
        Map<String, Object> eventProperties = event.getEventProperties();
        String eventName = event.getEventName();
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(
                IdentityEventConstants.EventProperty.USER_STORE_MANAGER);

        // Handle POST_BULK_ADD_USER event.
        if (IdentityEventConstants.Event.POST_BULK_ADD_USER.equals(eventName)) {
            handlePostBulkUserAdd(event, userStoreManager);
        }
    }

    private void handlePostBulkUserAdd(Event event, UserStoreManager userStoreManager) throws
            IdentityEventException {
            User user = SCIMCommonUtils.getUser(event.getEventProperties(), userStoreManager);

            try {
                // TODO: Take catch to inside and combine the blank check with try catch
                String userEmail = SCIMCommonUtils.getEmailClaimValue(user, userStoreManager);

                if (StringUtils.isBlank(userEmail)) {
                    throw new IdentityEventException("Email claim is not available for user: " + user.getUserName());
                }

                // TODO: Add properties -> PDF
                HashMap<String, Object> properties = new HashMap<>();

                if (CollectionUtils.size(event.getEventProperties()) > 0) {
                    properties.putAll(event.getEventProperties());
                }

                triggerNotification(userEmail, IdentityRecoveryConstants.NOTIFICATION_TYPE_SELF_SIGNUP_NOTIFY, properties);
            } catch (CharonException e) {
                throw new IdentityEventException("Error while retrieving email claim for user: " + user.getUserName(), e);
            }
    }

    private void triggerNotification(String userEmail, String templateType, Map<String, Object> properties)
            throws IdentityEventException {

        properties.put(IdentityRecoveryConstants.SEND_TO, userEmail);
        properties.put(IdentityRecoveryConstants.TEMPLATE_TYPE, templateType);

        Event identityMgtEvent = new Event(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, properties);

        try {
            SCIMCommonComponentHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            throw new IdentityEventException("Error while sending notification for user", e);
        }
    }

    /**
     * Check whether the handler is enabled.
     *
     * @return True if the handler is enabled.
     */
    private boolean isHandlerEnabled() {

        if (this.configs.getModuleProperties() == null) {
            return false;
        }

        String handlerEnabled = this.configs.getModuleProperties()
                .getProperty(SCIMCommonConstants.SCIM_BULK_USER_OPERATION_EVENT_HANDLER_ENABLED);
        return Boolean.parseBoolean(handlerEnabled);
    }
}
