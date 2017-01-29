/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.rampart;

import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFault;
import org.apache.axiom.soap.SOAPFaultCode;
import org.apache.axiom.soap.SOAPFaultSubCode;
import org.apache.axiom.soap.SOAPFaultValue;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.Token;
import org.apache.rahas.TokenStorage;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.saml.SAMLAssertionHandler;
import org.apache.rampart.saml.SAMLAssertionHandlerFactory;
import org.apache.rampart.util.Axis2Util;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.security.*;
import org.apache.ws.security.components.crypto.Crypto;

import javax.xml.namespace.QName;
import java.security.cert.X509Certificate;
import java.util.*;

public class RampartEngine {

	private static Log log = LogFactory.getLog(RampartEngine.class);
	private static Log tlog = LogFactory.getLog(RampartConstants.TIME_LOG);
    private static ServiceNonceCache serviceNonceCache = new ServiceNonceCache();

	public List<WSSecurityEngineResult> process(MessageContext msgCtx) throws WSSPolicyException,
	RampartException, WSSecurityException, AxisFault {

		boolean dotDebug = tlog.isDebugEnabled();
		
		log.debug("Enter process(MessageContext msgCtx)");

		RampartMessageData rmd = new RampartMessageData(msgCtx, false);

		RampartPolicyData rpd = rmd.getPolicyData();
		
		msgCtx.setProperty(RampartMessageData.RAMPART_POLICY_DATA, rpd);

        RampartUtil.validateTransport(rmd);

        // If there is no policy information return immediately
        if (rpd == null) {
           return null;
        }


        //TODO these checks have to be done before the convertion to avoid unnecessary convertion to LLOM -> DOOM
        // If the message is a security fault or no security
        // header required by the policy
        if(isSecurityFault(rmd) || !RampartUtil.isSecHeaderRequired(rpd,rmd.isInitiator(),true)) {
			SOAPEnvelope env = Axis2Util.getSOAPEnvelopeFromDOMDocument(rmd.getDocument(), true);

			//Convert back to llom since the inflow cannot use llom
			msgCtx.setEnvelope(env);
			Axis2Util.useDOOM(false);
            log.debug("Return process MessageContext msgCtx)");
            return null;
		}


		List<WSSecurityEngineResult> results;

		WSSecurityEngine engine = new WSSecurityEngine();

		ValidatorData data = new ValidatorData(rmd);

		SOAPHeader header = rmd.getMsgContext().getEnvelope().getHeader();
		if(header == null) {
		    throw new RampartException("missingSOAPHeader");
		}
		
        ArrayList headerBlocks = header.getHeaderBlocksWithNSURI(WSConstants.WSSE_NS);
		SOAPHeaderBlock secHeader = null;
		//Issue is axiom - a returned collection must not be null
		if(headerBlocks != null) {
    		Iterator headerBlocksIterator = headerBlocks.iterator();
    		while (headerBlocksIterator.hasNext()) {
    			SOAPHeaderBlock elem = (SOAPHeaderBlock) headerBlocksIterator.next();
    			if(elem.getLocalName().equals(WSConstants.WSSE_LN)) {
    				secHeader = elem;
    				break;
    			}
    		}
		}
		
		if(secHeader == null) {
		    throw new RampartException("missingSecurityHeader");
		}
		
		long t0=0, t1=0, t2=0, t3=0;
		if(dotDebug){
			t0 = System.currentTimeMillis();
		}

		String actorValue = secHeader.getAttributeValue(new QName(rmd
				.getSoapConstants().getEnvelopeURI(), "actor"));

		Crypto signatureCrypto = RampartUtil.getSignatureCrypto(rpd.getRampartConfig(), 
        		msgCtx.getAxisService().getClassLoader());
        TokenCallbackHandler tokenCallbackHandler = new TokenCallbackHandler(rmd.getTokenStorage(), RampartUtil.getPasswordCB(rmd));
        if(rpd.isSymmetricBinding()) {
			//Here we have to create the CB handler to get the tokens from the 
			//token storage
			log.debug("Processing security header using SymetricBinding");
			results = engine.processSecurityHeader(rmd.getDocument(),
					actorValue, 
					tokenCallbackHandler,
					signatureCrypto, 
					        RampartUtil.getEncryptionCrypto(rpd.getRampartConfig(), 
					                msgCtx.getAxisService().getClassLoader()));

            // Remove encryption tokens if this is the initiator and if initiator is receiving a message

            if (rmd.isInitiator() && (msgCtx.getFLOW() == MessageContext.IN_FLOW ||
                    msgCtx.getFLOW() == MessageContext.IN_FAULT_FLOW)) {
                tokenCallbackHandler.removeEncryptedToken();
            }

		} else {

			log.debug("Processing security header in normal path");
			results = engine.processSecurityHeader(rmd.getDocument(),
					actorValue, 
					tokenCallbackHandler,
					signatureCrypto, 
							RampartUtil.getEncryptionCrypto(rpd.getRampartConfig(), 
									msgCtx.getAxisService().getClassLoader()));
		}

		if(dotDebug){
			t1 = System.currentTimeMillis();
		}

                //Store symm tokens
                //Pick the first SAML token
                //TODO : This is a hack , MUST FIX
                //get the sec context id from the req msg ctx 
		
		//Store username in MessageContext property

        for (int j = 0; j < results.size(); j++) {
            WSSecurityEngineResult wser = (WSSecurityEngineResult) results.get(j);
            final Integer actInt =
                    (Integer) wser.get(WSSecurityEngineResult.TAG_ACTION);
            if (WSConstants.ST_UNSIGNED == actInt.intValue()) {

                Object samlAssertion = wser.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);

                SAMLAssertionHandler samlAssertionHandler
                        = SAMLAssertionHandlerFactory.createAssertionHandler(samlAssertion);

                if (samlAssertionHandler.isBearerAssertion()) {
                    break;
                }
                //Store the token
                try {
                    TokenStorage store = rmd.getTokenStorage();
                    if (store.getToken(samlAssertionHandler.getAssertionId()) == null) {
                        Token token = new Token(samlAssertionHandler.getAssertionId(),
                                samlAssertionHandler.getAssertionElement(),
                                samlAssertionHandler.getDateNotBefore(),
                                samlAssertionHandler.getDateNotOnOrAfter());

                        token.setSecret(samlAssertionHandler.
                                getAssertionKeyInfoSecret(signatureCrypto, tokenCallbackHandler));
                        store.add(token);
                    }
                } catch (Exception e) {
                    throw new RampartException(
                            "errorInAddingTokenIntoStore", e);
                }
            } else if (WSConstants.UT == actInt) {

		        WSUsernameTokenPrincipal userNameTokenPrincipal = (WSUsernameTokenPrincipal)wser.get(WSSecurityEngineResult.TAG_PRINCIPAL);

                String username = userNameTokenPrincipal.getName();
                msgCtx.setProperty(RampartMessageData.USERNAME, username);
                
                if (userNameTokenPrincipal.getNonce() != null) {
                    // Check whether this is a replay attack. To verify that we need to check whether nonce value
                    // is a repeating one
                    int nonceLifeTimeInSeconds = 0;

                    if (rpd.getRampartConfig() != null) {
                        
                        String stringLifeTime = rpd.getRampartConfig().getNonceLifeTime();

                        try {
                            nonceLifeTimeInSeconds = Integer.parseInt(stringLifeTime);

                        } catch (NumberFormatException e) {
                            log.error("Invalid value for nonceLifeTime in rampart configuration file.", e);
                            throw new RampartException(
                                        "invalidNonceLifeTime", e);

                        }
                    }

                    String serviceEndpointName = msgCtx.getAxisService().getEndpointName();

                    boolean valueRepeating = serviceNonceCache.isNonceRepeatingForService(serviceEndpointName, username, userNameTokenPrincipal.getNonce());

                    if (valueRepeating){
                        throw new RampartException("repeatingNonceValue", new Object[]{ userNameTokenPrincipal.getNonce(), username} );
                    }

                    serviceNonceCache.addNonceForService(serviceEndpointName, username, userNameTokenPrincipal.getNonce(), nonceLifeTimeInSeconds);
                }
            } else if (WSConstants.SIGN == actInt) {
                X509Certificate cert = (X509Certificate) wser.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);

                if (rpd.isAsymmetricBinding() && cert == null && rpd.getInitiatorToken() != null
                        && !rpd.getInitiatorToken().isDerivedKeys()) {

                    // If symmetric binding is used, the certificate should be null.
                    // If certificate is not null then probably initiator and
                    // recipient are using 2 different bindings.
                    throw new RampartException("invalidSignatureAlgo");
                }

                msgCtx.setProperty(RampartMessageData.X509_CERT, cert);
            }

        }

		SOAPEnvelope env = Axis2Util.getSOAPEnvelopeFromDOMDocument(rmd.getDocument(), true);

		if(dotDebug){
			t2 = System.currentTimeMillis();
		}

		//Convert back to llom since the inflow cannot use DOOM
		msgCtx.setEnvelope(env);
		Axis2Util.useDOOM(false);
				
		PolicyValidatorCallbackHandler validator = RampartUtil.getPolicyValidatorCB(msgCtx, rpd);

        if (validator instanceof ExtendedPolicyValidatorCallbackHandler) {
            ExtendedPolicyValidatorCallbackHandler extendedPolicyValidatorCallbackHandler
                    = (ExtendedPolicyValidatorCallbackHandler)validator;
            extendedPolicyValidatorCallbackHandler.validate(data,results);
        } else {
            Vector resultsVector = new Vector(results);
            validator.validate(data, resultsVector);
        }


		if(dotDebug){
			t3 = System.currentTimeMillis();
			tlog.debug("processHeader by WSSecurityEngine took : " + (t1 - t0) +
					", DOOM conversion took :" + (t2 - t1) +
					", PolicyBasedResultsValidattor took " + (t3 - t2));
		}

		log.debug("Return process(MessageContext msgCtx)");
		return results;
	}
	
	// Check whether this a soap fault because of failure in processing the security header 
	//and if so, we don't expect the security header
	//
	//

	
	private boolean isSecurityFault(RampartMessageData rmd) {

		SOAPEnvelope soapEnvelope = rmd.getMsgContext().getEnvelope();
		SOAPFault soapFault = soapEnvelope.getBody().getFault();

		// This is not a soap fault
		if (soapFault == null) {
			return false;
		}

		String soapVersionURI = rmd.getMsgContext().getEnvelope().getNamespace().getNamespaceURI();
		SOAPFaultCode faultCode = soapFault.getCode();
		if(faultCode == null){
			//If no fault code is given, then it can't be security fault
			return false;
		}
		
		if (soapVersionURI.equals(SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI)) {
			// This is a fault processing the security header
			if (faultCode.getTextAsQName().getNamespaceURI().equals(WSConstants.WSSE_NS)) {
				return true;
			}
		} else if (soapVersionURI.equals(SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI)) {
			// TODO AXIOM API returns only one fault sub code, there can be many
			SOAPFaultSubCode faultSubCode = faultCode.getSubCode();
			if (faultSubCode != null) {
				SOAPFaultValue faultSubCodeValue = faultSubCode.getValue();

				// This is a fault processing the security header
				if (faultSubCodeValue != null && faultSubCodeValue.getTextAsQName().
						getNamespaceURI().equals(WSConstants.WSSE_NS)) {
					return true;
				}
			}
		}

		return false;
	}
}
