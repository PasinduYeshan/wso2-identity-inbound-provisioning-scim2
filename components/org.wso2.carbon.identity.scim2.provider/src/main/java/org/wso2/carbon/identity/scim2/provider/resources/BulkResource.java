/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim2.provider.resources;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim2.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim2.provider.util.SupportUtils;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.FormatNotSupportedException;
import org.wso2.charon3.core.extensions.RoleManager;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.BulkResourceManager;
import org.wso2.charon3.core.protocol.ResponseCodeConstants;
import org.wso2.charon3.core.schema.SCIMConstants;


import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;

import java.util.ArrayList;
import java.util.List;

@Path("/")
public class BulkResource extends AbstractResource {

    private static final String RESPOND_ASYNC = "respond-async";
    ExecutorService threadPool = Executors.newFixedThreadPool(SCIMProviderConstants.threadPoolSize);
    private static final Log logger = LogFactory.getLog(BulkResource.class);

    private UserManager userManager;
    private RoleManager roleManager;
    private BulkResourceManager bulkResourceManager;

    @POST
    public Response createUser(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @HeaderParam(SCIMProviderConstants.PREFER_HEADER) String respondType,
                               String resourceString) {
        try {
            // Validate input headers
            validateHeaders(inputFormat, outputFormat);

            // obtain the user store manager
             userManager = IdentitySCIMManager.getInstance().getUserManager();
            // Obtain the role manager.
             roleManager = IdentitySCIMManager.getInstance().getRoleManager();

            // create charon-SCIM bulk endpoint and hand-over the request.
            bulkResourceManager = new BulkResourceManager();

            // Extract context
            int tenantId = SupportUtils.getTenantId();
            String tenantDomain = SupportUtils.getTenantDomain();
            String appName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getApplicationName();
            String traceID = MDC.get(SCIMProviderConstants.CORRELATION_ID_MDC);

            User user = SupportUtils.getUser();

            // Handle async request
            if (RESPOND_ASYNC.equals(respondType)) {
                // Execute the main logic asynchronously and return 202 immediately
                CompletableFuture.runAsync(() -> {
                    try {
                        processBulkDataAsync(tenantId,
                                tenantDomain, appName, traceID, resourceString, user);
                    } catch (IdentityEventException e) {
                        logger.error("Error while publishing event for bulk user add.", e);
                        throw new RuntimeException(e);
                    } catch (CharonException e) {
                        logger.error("Error while processing bulk user add.", e);
                        throw new RuntimeException(e);
                    } catch (Exception e) {
                        logger.error("Error while processing bulk user add.", e);
                        throw new RuntimeException(e);
                    }
                }, threadPool);

                return SupportUtils.buildResponse(acceptedSCIMResponse());
            } else {
                SCIMResponse scimResponse = bulkResourceManager.processBulkData(resourceString,
                        userManager, roleManager);
                return SupportUtils.buildResponse(scimResponse);
            }

        } catch (CharonException e) {
            return handleCharonException(e);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    /**
     * Validate headers.
     * content-type header is compulsory in post request.
     *
     * @param inputFormat       content-type header value
     * @param outputFormat      accept header value
     * @throws FormatNotSupportedException  if the format is not supported.
     */
    private void validateHeaders(String inputFormat, String outputFormat) throws FormatNotSupportedException {
        if (inputFormat == null) {
            String error = SCIMProviderConstants.CONTENT_TYPE
                    + " not present in the request header";
            throw new FormatNotSupportedException(error);
        }

        if (!isValidInputFormat(inputFormat)) {
            String error = inputFormat + " is not supported.";
            throw new FormatNotSupportedException(error);
        }

        if (!isValidOutputFormat(outputFormat)) {
            String error = outputFormat + " is not supported.";
            throw new FormatNotSupportedException(error);
        }
    }

    /**
     * Process bulk data asynchronously.
     *
     * @param tenantId          tenant id
     * @param tenantDomain      tenant domain
     * @param appName           application name
     * @param traceId           correlation id
     * @param resourceString    resource string
     * @param user              user
     * @throws IdentityEventException  if an error occurred while publishing the event.
     */
    private void processBulkDataAsync(int tenantId, String tenantDomain, String appName,
                                     String traceId, String resourceString, User user)
            throws IdentityEventException, CharonException {

            // Set the MDC values.
            setMDCValues(tenantId, tenantDomain, appName, traceId);
            // Set the tenant information in the thread local carbon context.
            setPrivilegedCarbonContextValues(tenantId, tenantDomain);

            // Call for process bulk data.
            SCIMResponse scimResponse = bulkResourceManager.processBulkData(resourceString, userManager, roleManager);

            // TODO: Send email notification upon completion of the bulk import.
            // sendNotification(user, scimResponse);

            // Log the response.
            if (logger.isDebugEnabled()) {
                logger.info("Bulk request processed asynchronously. Response status: " +
                        scimResponse.getResponseStatus() + " Response message: " + scimResponse.getResponseMessage());
            }
    }

    /**
     * Generate a SCIMResponse for 202 Accepted status.
     *
     * @return SCIMResponse for 202 Accepted status.
     */
    private SCIMResponse acceptedSCIMResponse() {
        Map<String, String> responseHeaders = new HashMap<>();
        //add location header
        responseHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
        // TODO: Change ResponseCodeConstants.DESC_ACCEPTED to a proper message.
        return new SCIMResponse(ResponseCodeConstants.CODE_ACCEPTED,
                "ResponseCodeConstants.DESC_ACCEPTED", responseHeaders);
    }

    /**
     * Set the MDC values.
     *
     * @param tenantId      tenantId
     * @param tenantDomain  tenantDomain
     * @param appName       appName
     * @param traceID       traceID
     */
    private void setMDCValues(int tenantId, String tenantDomain, String appName, String traceID) {

        if (tenantDomain != null) {
            MDC.put(SCIMProviderConstants.TENANT_ID, String.valueOf(tenantId));
            MDC.put(SCIMProviderConstants.TENANT_DOMAIN, tenantDomain);
            MDC.put(SCIMProviderConstants.CORRELATION_ID_MDC, traceID);
        }
        if (StringUtils.isNotEmpty(appName)) {
            MDC.put(SCIMProviderConstants.APP_NAME, appName);
        }
    }

    /**
     * Set the tenant information in the thread local carbon context.
     *
     * @param tenantId      tenantId
     * @param tenantDomain  tenantDomain
     */
    private void setPrivilegedCarbonContextValues(int tenantId, String tenantDomain) {
        if (tenantDomain != null) {
            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            privilegedCarbonContext.setTenantId(tenantId);
            privilegedCarbonContext.setTenantDomain(tenantDomain);
        }
    }

    /**
     * Send email notification upon completion of the bulk import.
     *
     * @param user user
     * @param scimResponse SCIMResponse
     * @throws CharonException If an error occurred while getting the user store manager.
     * @throws IdentityEventException If an error occurred while publishing the event.
     */
    private void sendNotification(User user, SCIMResponse scimResponse) throws CharonException, IdentityEventException {

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, SCIMCommonUtils.getUserStoreManager(user));
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());

        // Publish event.
        SCIMCommonUtils.publishEvent(properties, IdentityEventConstants.Event.POST_BULK_ADD_USER);
    }

}

