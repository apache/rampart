/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.apache.rahas.test.util;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.rahas.Token;
import org.apache.rahas.TrustException;
import org.apache.rahas.client.STSClient;

/**
 * STS client for tests.
 */
public class TestSTSClient extends STSClient {

    public TestSTSClient(ConfigurationContext configCtx) throws TrustException {
        super(configCtx);
    }

    public Token processResponse(int version, OMElement result,
                                 String issuerAddress) throws TrustException {
        return super.processIssueResponse(version, result, issuerAddress);
    }

    public OMElement createRST(String appliesTo) throws TrustException {

        return super.createIssueRequest(appliesTo);
    }
}
