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

package org.apache.rahas.impl.util;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.dom.DOMMetaFactory;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.RahasData;
import org.apache.rahas.TrustException;
import org.apache.rahas.impl.SAMLTokenIssuerConfig;
import org.apache.rahas.impl.TokenIssuerUtil;
import org.apache.ws.security.*;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.Loader;
import org.apache.xml.security.utils.EncryptionConstants;
import org.opensaml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Data;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import static org.apache.axiom.om.OMAbstractFactory.FEATURE_DOM;

/**
 * This class implements some utility methods common to SAML1 and SAML2.
 */
public class CommonUtil {

    private static Log log = LogFactory.getLog(CommonUtil.class);

    /**
     * This method creates a DOM compatible Axiom document.
     * @return DOM compatible Axiom document
     * @throws TrustException If an error occurred while creating the Document.
     */
    public static Document getOMDOMDocument() throws TrustException {
        DOMMetaFactory metaFactory = (DOMMetaFactory) OMAbstractFactory.getMetaFactory(FEATURE_DOM);
            DocumentBuilderFactory dbf = metaFactory.newDocumentBuilderFactory();
        try {
            return  dbf.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new TrustException("Error creating Axiom compatible DOM Document", e);
        }
    }

    /**
     * Gets the certificates chain by alias. Always returns the first certificate if a certificate chain is found.
     * @param crypto Crypto to lookup certificate.
     * @param alias Alias name.
     * @return X509 certificate object.
     * @throws org.apache.rahas.TrustException If an error occurred
     *                              while retrieving the certificate or if no certificates are found for given alias.
     */
    public static X509Certificate getCertificateByAlias(Crypto crypto, String alias) throws TrustException {

        X509Certificate[] certificates = getCertificatesByAlias(crypto, alias);

        if (certificates == null) {
            log.error("Unable to retrieve certificate for alias " + alias);
            throw new TrustException("issuerCertificateNotFound");
        }

        return certificates[0];
    }

    /**
     * Gets the certificates chain by alias. If no certificates are found return an empty array.
     * @param crypto Crypto to lookup certificate.
     * @param alias Alias name.
     * @return X509 certificates array.
     * @throws org.apache.rahas.TrustException If an error occurred
     *                                          while retrieving the certificate.
     */
    public static X509Certificate[] getCertificatesByAlias(Crypto crypto, String alias) throws TrustException {

        // TODO are we always looking up by alias ? Dont we need to lookup by any other attribute ?
        CryptoType type = new CryptoType(CryptoType.TYPE.ALIAS);
        type.setAlias(alias);

        try {
            X509Certificate[] certificates = crypto.getX509Certificates(type);

            if (certificates == null) {
                log.debug("Unable to retrieve certificate for alias " + alias);
                return new X509Certificate[0];
            }
            return certificates;
        } catch (WSSecurityException e) {
            log.error("Unable to retrieve certificate for alias " + alias, e);
            throw new TrustException("issuerCertificateNotFound", e);
        }
    }

    /**
     * Decrypts the EncryptedKey element and returns the secret that was used.
     * @param callbackHandler Callback handler to pass to WSS4J framework.
     * @param crypto To get private key information.
     * @param encryptedKeyElement The encrypted Key element.
     * @return The secret as a byte stream.
     * @throws WSSecurityException If an error is occurred while decrypting the element.
     */
    public static byte[] getDecryptedBytes(CallbackHandler callbackHandler, Crypto crypto, Node encryptedKeyElement)
            throws WSSecurityException {

        EncryptedKeyProcessor encryptedKeyProcessor = new EncryptedKeyProcessor();

        RequestData requestData = new RequestData();
        requestData.setCallbackHandler(callbackHandler);
        requestData.setDecCrypto(crypto);

        final WSSConfig cfg = WSSConfig.getNewInstance();
        requestData.setWssConfig(cfg);

        WSDocInfo docInfo = new WSDocInfo(encryptedKeyElement.getOwnerDocument());

        List<WSSecurityEngineResult> resultList;

        resultList = encryptedKeyProcessor.handleToken((Element) encryptedKeyElement, requestData, docInfo);


        WSSecurityEngineResult wsSecurityEngineResult = resultList.get(0);

        return (byte[]) wsSecurityEngineResult.get(WSSecurityEngineResult.TAG_SECRET);
    }

    /**
     * Constructs crypto configuration based on the given properties. Provider is instantiated using
     * given class loader.
     * @param properties Crypto configuration properties.
     * @param classLoader Class loader used to create provider.
     * @return A crypto object.
     * @throws TrustException If an error occurred while creating the Crypto object.
     */
    public static Crypto getCrypto(Properties properties, ClassLoader classLoader) throws TrustException {
        try {
            return CryptoFactory.getInstance(properties, classLoader);
        } catch (WSSecurityException e) {
            log.error("An error occurred while loading crypto properties", e);
            throw new TrustException("errorLoadingCryptoProperties", e);

        }
    }

    /**
     * Constructs crypto configuration based on the given properties. Provider is instantiated using
     * given class loader.
     * @param propertiesFile Crypto configuration properties file name.
     * @param classLoader Class loader used to create provider.
     * @return A crypto object.
     * @throws TrustException If an error occurred while creating the Crypto object.
     */
    public static Crypto getCrypto(String propertiesFile, ClassLoader classLoader) throws TrustException {
        try {
            return CryptoFactory.getInstance(propertiesFile, classLoader);
        } catch (WSSecurityException e) {
            log.error("An error occurred while loading crypto properties with property file " + propertiesFile, e);
            throw new TrustException("errorLoadingCryptoProperties", new Object[]{propertiesFile}, e);

        }
    }

    /**
     * Creates the token issuer configuration. The configuration is created in following order,
     * 1. Try create token configuration using configuration OMElement
     * 2. Try create token configuration using a configuration file name
     * 3. Try create token configuration using a parameter name in message context.
     * The issuer configuration would look like as follows,
     *
     * <pre>   &lt;saml-issuer-config&gt;
     *       &lt;issuerName&gt;Test_STS&lt;/issuerName&gt;
     *       &lt;issuerKeyAlias&gt;ip&lt;/issuerKeyAlias&gt;
     *       &lt;issuerKeyPassword&gt;password&lt;/issuerKeyPassword&gt;
     *       &lt;cryptoProperties&gt;
     *          &lt;crypto provider="org.apache.ws.security.components.crypto.Merlin"&gt;
     *               &lt;property name="org.apache.ws.security.crypto.merlin.keystore.type"&gt;JKS&lt;/property&gt;
     *               &lt;property name="org.apache.ws.security.crypto.merlin.file"&gt;META-INF/rahas-sts.jks&lt;/property&gt;
     *               &lt;property name="org.apache.ws.security.crypto.merlin.keystore.password"&gt;password&lt;/property&gt;
     *           &lt;/crypto&gt;
     *       &lt;/cryptoProperties&gt;
     *       &lt;timeToLive&gt;300000&lt;/timeToLive&gt;
     *       &lt;keySize&gt;256&lt;/keySize&gt;
     *       &lt;addRequestedAttachedRef /&gt;
     *       &lt;addRequestedUnattachedRef /&gt;
     *       &lt;keyComputation&gt;2&lt;/keyComputation&gt;
     *       &lt;proofKeyType&gt;BinarySecret&lt;/proofKeyType&gt;
     *       &lt;trusted-services&gt;
     *           &lt;service alias="bob"&gt;http://localhost:8080/axis2/services/STS&lt;/service&gt;
     *       &lt;/trusted-services&gt;
     *   &lt;/saml-issuer-config&gt;</pre>
     *
     * @param configElement Configuration as an OMElement.
     * @param configFile Configuration as a file.
     * @param messageContextParameter Configuration as a message context parameter.
     * @return  Token issuer configuration as a SAMLTokenIssuerConfig object.
     * @throws TrustException If an error occurred while creating SAMLTokenIssuerConfig object.
     */
    public static SAMLTokenIssuerConfig getTokenIssuerConfiguration(OMElement configElement, String configFile,
                                                               Parameter messageContextParameter) throws TrustException {

        // First try using configuration element
        SAMLTokenIssuerConfig tokenIssuerConfiguration = createTokenIssuerConfiguration(configElement);

        if (tokenIssuerConfiguration == null) {

            // Now try file
            tokenIssuerConfiguration = createTokenIssuerConfiguration(configFile);

            if (tokenIssuerConfiguration == null) {

                // Finally try using the parameter
                if (messageContextParameter != null) {
                    tokenIssuerConfiguration = createTokenIssuerConfiguration(messageContextParameter);
                }

                return tokenIssuerConfiguration;
            } else {
                return tokenIssuerConfiguration;
            }

        } else {
            return tokenIssuerConfiguration;
        }
    }

    protected static SAMLTokenIssuerConfig createTokenIssuerConfiguration(OMElement configElement)
            throws TrustException {

        if (configElement != null) {

            log.debug("Creating token issuer configuration using OMElement");

            return new SAMLTokenIssuerConfig(configElement
                    .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
        }

        return null;
    }

    protected static SAMLTokenIssuerConfig createTokenIssuerConfiguration(String configFile) throws TrustException {

        if (configFile != null) {

            if (log.isDebugEnabled()) {
                log.debug("Creating token issuer configuration using file " + configFile);
            }

            return new SAMLTokenIssuerConfig(configFile);
        }

        return null;
    }

    protected static SAMLTokenIssuerConfig createTokenIssuerConfiguration(Parameter messageContextParameter)
            throws TrustException {

        if (messageContextParameter != null && messageContextParameter.getParameterElement() != null) {

            log.debug("Creating token issuer configuration using the config parameter");

            return new SAMLTokenIssuerConfig(messageContextParameter
                    .getParameterElement().getFirstChildWithName(
                            SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
        }

        return null;
    }

    /**
     * Builds the requested XMLObject.
     *
     * @param objectQName name of the XMLObject
     * @return the build XMLObject
     * @throws org.apache.rahas.TrustException If unable to find the appropriate builder.
     */
    public static XMLObject buildXMLObject(QName objectQName) throws TrustException {
        XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(objectQName);
        if (builder == null) {
            log.debug("Unable to find OpenSAML builder for object " + objectQName);
            throw new TrustException("builderNotFound",new Object[]{objectQName});
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }

     /**
     * This method creates KeyInfo element of an assertion. This is a facade, in which it calls
     * to other helper methods to create KeyInfo. The TokenIssuer will call this method to
     * create the KeyInfo.
     * @param doc An Axiom based DOM Document.
     * @param data The ephemeral key which we use here need in encrypting the message also. Therefore
     *              we need to save the ephemeral key in RahasData passed here.
     * @param serviceCert Public key used to encrypt the assertion is extracted from this certificate.
     * @param keySize Size of the key to be used
     * @param crypto The relevant private key
     * @param keyComputation Key computation mechanism.
     * @return OpenSAML KeyInfo representation.
     * @throws WSSecurityException We use WSS4J to generate encrypted key. This exception will trigger if an
     *                      error occurs while generating the encrypted key.
     * @throws TrustException If an error occurred while creating KeyInfo object.
     */
    public static KeyInfo getSymmetricKeyBasedKeyInfo(Document doc,
                                                      RahasData data,
                                                      X509Certificate serviceCert,
                                                      int keySize,
                                                      Crypto crypto,
                                                      int keyComputation) throws WSSecurityException, TrustException {

        byte[] ephemeralKey = TokenIssuerUtil.getSharedSecret(
                data, keyComputation, keySize);

        WSSecEncryptedKey encryptedKey = getSymmetricKeyBasedKeyInfoContent(doc, ephemeralKey, serviceCert, crypto);

        // Extract the base64 encoded secret value
        byte[] tempKey = new byte[keySize / 8];
        System.arraycopy(encryptedKey.getEphemeralKey(), 0, tempKey,
                0, keySize / 8);


        data.setEphmeralKey(tempKey);

        EncryptedKey samlEncryptedKey = SAMLUtils.createEncryptedKey(serviceCert, encryptedKey);
        return SAMLUtils.createKeyInfo(samlEncryptedKey);
    }

    static WSSecEncryptedKey getSymmetricKeyBasedKeyInfoContent(Document doc,
                                                                       byte[] ephemeralKey,
                                                                       X509Certificate serviceCert,
                                                                       Crypto crypto) throws WSSecurityException,
            TrustException {
        // Create the encrypted key
        WSSecEncryptedKey encryptedKeyBuilder = new WSSecEncryptedKey();

        // Use thumbprint id
        encryptedKeyBuilder
                .setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);

        // SEt the encryption cert
        encryptedKeyBuilder.setUseThisCert(serviceCert);

        encryptedKeyBuilder.setEphemeralKey(ephemeralKey);

        // Set key encryption algo
        encryptedKeyBuilder
                .setKeyEncAlgo(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);

        // Build
        encryptedKeyBuilder.prepare(doc, crypto);

        return encryptedKeyBuilder;
    }

    /**
     * Creates the certificate based KeyInfo object.
     * @param certificate The public key certificate used to create the KeyInfo object.
     * @return OpenSAML representation of KeyInfo object.
     * @throws TrustException If an error occurred while creating the KeyInfo
     */
    public static KeyInfo getCertificateBasedKeyInfo(X509Certificate certificate) throws TrustException {
        X509Data x509Data = CommonUtil.createX509Data(certificate);
        return SAMLUtils.createKeyInfo(x509Data);
    }

    /**
     * Creates the X509 data element in a SAML issuer token. Should create an element similar to following,
     * <X509Data xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
     *                         xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
     *   <X509Certificate>
     *       MIICNTCCAZ6gAwIB...
     *   </X509Certificate>
     * </X509Data>
     * @param clientCert Client certificate to be used when generating X509 data
     * @return  SAML X509Data representation.
     * @throws TrustException If an error occurred while creating X509Data and X509Certificate.
     */
    static X509Data createX509Data(X509Certificate clientCert) throws TrustException {

        byte[] clientCertBytes;
        try {
            clientCertBytes = clientCert.getEncoded();
        } catch (CertificateEncodingException e) {
            log.error("An error occurred while encoding certificate.", e);
            throw new TrustException("An error occurred while encoding certificate.", e);
        }
        String base64Cert = Base64.encode(clientCertBytes);

        org.opensaml.xml.signature.X509Certificate x509Certificate
                = (org.opensaml.xml.signature.X509Certificate)CommonUtil.buildXMLObject
                (org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);

        x509Certificate.setValue(base64Cert);

        X509Data x509Data = (X509Data)CommonUtil.buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
        x509Data.getX509Certificates().add(x509Certificate);

        return x509Data;
    }

    /**
     * Gets the SAML callback handler. First checks whether there is a registered callback handler in token
     * issuer configuration. If not this will check whether there is a callback class configured in token issuer
     * configuration. If class name is specified this method will create an object of the class and will return.
     * If class name is also not specified this method will return null.
     * @param tokenIssuerConfiguration The SAML token issuer configuration.
     * @param data The RahasData.
     * @return The SAMLCallbackHandler if configured in token issuer configuration, else null.
     * @throws TrustException If an error occurred while loading class from class loader
     */
    public static SAMLCallbackHandler getSAMLCallbackHandler(SAMLTokenIssuerConfig tokenIssuerConfiguration,
                                                                      RahasData data) throws TrustException {
        if (tokenIssuerConfiguration.getCallbackHandler() != null) {

            return tokenIssuerConfiguration.getCallbackHandler();

        } else if (tokenIssuerConfiguration.getCallbackHandlerName() != null
                && tokenIssuerConfiguration.getCallbackHandlerName().trim().length() > 0) {

            SAMLCallbackHandler handler;
            MessageContext msgContext = data.getInMessageContext();
            ClassLoader classLoader = msgContext.getAxisService().getClassLoader();
            Class cbClass;
            try {
                cbClass = Loader.loadClass(classLoader, tokenIssuerConfiguration.getCallbackHandlerName());
            } catch (ClassNotFoundException e) {
                throw new TrustException("cannotLoadPWCBClass", new String[]{tokenIssuerConfiguration
                        .getCallbackHandlerName()}, e);
            }
            try {
                handler = (SAMLCallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new TrustException("cannotCreatePWCBInstance", new String[]{tokenIssuerConfiguration
                        .getCallbackHandlerName()}, e);
            }

            return handler;
        }

        return null;

    }
}
