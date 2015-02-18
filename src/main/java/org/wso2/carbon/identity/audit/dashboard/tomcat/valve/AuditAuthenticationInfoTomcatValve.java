/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.audit.dashboard.tomcat.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletException;
import java.io.IOException;


import org.wso2.carbon.identity.application.authentication.framework.handler.step.impl.AuthInfoBean;
import org.wso2.carbon.identity.application.authentication.framework.handler.step.impl.AuthInfoCache;

public class AuditAuthenticationInfoTomcatValve extends ValveBase{

    private static Log log = LogFactory.getLog(AuditAuthenticationInfoTomcatValve.class);


    public  String tempKey;
    private boolean isLogged;
    AuthInfoCache authInfoCache;


    public AuditAuthenticationInfoTomcatValve(){
        authInfoCache = new AuthInfoCache();
    }

    /**
     * @param request
     * @param response
     * @throws IOException
     * @throws ServletException
     */

    /**
     *
     * (request.getParameter("username") != null)
     */

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        if(request.getParameter("sessionDataKey") != null && request.getParameter("authenticators") != null ) {
            isLogged = true;
            tempKey = request.getParameter("sessionDataKey");
        }

        if(isLogged && authInfoCache.getValueFromCache(tempKey) != null )
        {
            allInfo(authInfoCache.getValueFromCache(tempKey));
            isLogged =false;
        }

        getNext().invoke(request, response);
    }

    static void allInfo(AuthInfoBean authInfoBean){

        String username = authInfoBean.getUserName();
        String serviceProvider = authInfoBean.getServiceProvider();
        String requestType = authInfoBean.getRequestTyep();
        String authenticationType = authInfoBean.getAuthenticationType();
        String response = authInfoBean.getResponse();
        authInfoBean.getSessionKeyValue();
        String ipAddress = authInfoBean.getIpAddress();

        String logMessage = "AuthInfoLogs#"+username+"#"+ipAddress+"#"+serviceProvider+"#"+requestType+"#"+authenticationType+"#"+response;

        log.info(logMessage);
    }

}
