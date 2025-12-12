/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.TestConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.crypto.JWEEncryptor;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.identity.common.testng.TestConstants.CARBON_TENANT_DOMAIN;

import static org.wso2.carbon.identity.openidconnect.RequestObjectValidatorImplTest.CLIENT_PUBLIC_CERT_ALIAS;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getRequestObjects;

@PrepareForTest({OAuth2Util.class, IdentityUtil.class, OAuthServerConfiguration.class,
        RequestObjectValidatorImpl.class, LoggerUtils.class, IdentityTenantUtil.class, IdentityEventService.class,
        CentralLogMgtServiceComponentHolder.class})
@PowerMockIgnore({"javax.crypto.*", "sun.security.x509.*", "java.security.cert"})
public class RequestParamRequestObjectBuilderTest extends PowerMockTestCase {

    private RSAPrivateKey rsaPrivateKey;
    private KeyStore clientKeyStore;
    private KeyStore wso2KeyStore;
    public static final String TEST_CLIENT_ID_1 = "wso2test";
    public static final String SOME_SERVER_URL = "some-server-url";

    @Mock
    private CentralLogMgtServiceComponentHolder centralLogMgtServiceComponentHolderMock;

    @BeforeMethod
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(-1234);
        when(OAuth2Util.getPrivateKey(anyString(), anyInt())).thenReturn(rsaPrivateKey);

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
    }

    @DataProvider(name = "TestBuildRequestObjectTest")
    public Object[][] buildRequestObjectData() throws Exception {

        Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        Key privateKey2 = wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
        return getRequestObjects(privateKey, privateKey2, publicKey, TEST_CLIENT_ID_1, SOME_SERVER_URL);
    }

    @Test(dataProvider = "TestBuildRequestObjectTest")
    public void buildRequestObjectTest(String requestObjectString, Map<String, Object> claims, boolean isSigned,
                                       boolean isEncrypted,
                                       boolean exceptionNotExpected,
                                       String errorMsg) throws Exception {

        mockStatic(IdentityUtil.class);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        IdentityEventService eventServiceMock = mock(IdentityEventService.class);
        mockStatic(CentralLogMgtServiceComponentHolder.class);
        when(CentralLogMgtServiceComponentHolder.getInstance()).thenReturn(centralLogMgtServiceComponentHolderMock);
        when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
        PowerMockito.doNothing().when(eventServiceMock).handleEvent(any());
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn("some-server-url");

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain("carbon.super");
        oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        mockStatic(RequestObjectValidatorImpl.class);
        PowerMockito.spy(RequestObjectValidatorImpl.class);

        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
        when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);
        when(OAuth2Util.getX509CertOfOAuthApp(TEST_CLIENT_ID_1, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(clientKeyStore.getCertificate("wso2carbon"));

        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
        when((oauthServerConfigurationMock.getRequestObjectValidator())).thenReturn(requestObjectValidator);

        RequestObject requestObject;
        RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();

        try {
            requestObject = requestParamRequestObjectBuilder.buildRequestObject(requestObjectString, oAuth2Parameters);
            Assert.assertEquals(requestObject.isSigned(), isSigned, errorMsg);
            if (claims != null && !claims.isEmpty()) {
                for (Map.Entry entry : claims.entrySet()) {
                    Assert.assertEquals(requestObject.getClaim(entry.getKey().toString()), entry.getValue(),
                            "Request object claim:" + entry.getKey() + " is not properly set.");
                }
            }
        } catch (RequestObjectException e) {
            Assert.assertFalse(exceptionNotExpected, errorMsg + "Building failed due to " + e.getMessage());
        }
    }

    public String buildEncryptedRequestObject(String jweAlgName) throws Exception {

        HashMap<String, Object> claims = new HashMap<>();
        claims.put(Constants.STATE, "af0ifjsldkj");
        claims.put(Constants.REDIRECT_URI, org.wso2.carbon.identity.oauth2.TestConstants.CALLBACK);
        claims.put(Constants.NONCE, "nonce-value");
        claims.put(Constants.SCOPE, org.wso2.carbon.identity.oauth2.TestConstants.SCOPE_STRING);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(TEST_CLIENT_ID_1)
                .audience(SOME_SERVER_URL)
                .issueTime(new Date())
                .claim(Constants.STATE, claims.get(Constants.STATE))
                .claim(Constants.REDIRECT_URI, claims.get(Constants.REDIRECT_URI))
                .claim(Constants.NONCE, claims.get(Constants.NONCE))
                .claim(Constants.SCOPE, claims.get(Constants.SCOPE))
                .build();

        Payload payload = new Payload(claimsSet.toJSONObject());

        EncryptionMethod encMethod = EncryptionMethod.A256GCM;
        JWEAlgorithm jweAlg;
        if (jweAlgName.equals("RSA-OAEP-384")) {
            jweAlg = org.wso2.carbon.identity.oauth2.crypto.JWEAlgorithm.RSA_OAEP_384;
        } else if (jweAlgName.equals("RSA-OAEP-512")) {
            jweAlg = org.wso2.carbon.identity.oauth2.crypto.JWEAlgorithm.RSA_OAEP_512;
        } else {
            jweAlg = JWEAlgorithm.parse(jweAlgName);
        }

        JWEHeader header = new JWEHeader.Builder(jweAlg, encMethod)
                .contentType("JWT")
                .build();
        JWEObject jweObject = new JWEObject(header, payload);

        // Select key and encrypter based on alg
        JWEEncrypter encrypter = null;
        if (jweAlg.equals(JWEAlgorithm.RSA_OAEP_256) || jweAlg.equals(JWEAlgorithm.RSA1_5)
                || jweAlg.equals(JWEAlgorithm.RSA_OAEP)) {
            // RSA-based nimbus supported algs
            PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
            encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
        } else if (jweAlg.getName().equals(org.wso2.carbon.identity.oauth2.crypto.JWEAlgorithm.RSA_OAEP_512.getName())
                || jweAlg.getName().equals(org.wso2.carbon.identity.oauth2.crypto.JWEAlgorithm.RSA_OAEP_384.getName()))
        {
            PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
            encrypter = new JWEEncryptor((RSAPublicKey) publicKey);
        }
        jweObject.encrypt(encrypter);
        return jweObject.serialize();
    }

    @DataProvider(name = "encryptionAlgProvider")
    public Object[][] encryptionAlgProvider() {
        return new Object[][]{
                {"RSA-OAEP-256"},
                {"RSA-OAEP-384"},
                {"RSA-OAEP-512"}
        };
    }

    @Test(dataProvider = "encryptionAlgProvider")
    public void testEncryptedRequestObjectForSupportedRSAAlgorithms(String algName) throws Exception {

        String jwt = buildEncryptedRequestObject(algName);

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain(CARBON_TENANT_DOMAIN);
        oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);
        oAuth2Parameters.setRedirectURI(TestConstants.CALLBACK);

        mockStatic(IdentityUtil.class);
        mockStatic(IdentityTenantUtil.class);
        IdentityEventService eventServiceMock = mock(IdentityEventService.class);
        mockStatic(CentralLogMgtServiceComponentHolder.class);
        when(CentralLogMgtServiceComponentHolder.getInstance()).thenReturn(centralLogMgtServiceComponentHolderMock);
        when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
        PowerMockito.doNothing().when(eventServiceMock).handleEvent(any());
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn("some-server-url");

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
        when(OAuth2Util.getPrivateKey(anyString(), anyInt())).thenReturn(rsaPrivateKey);

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setRequestObjectEncryptionAlgorithm(algName);
        appDO.setRequestObjectEncryptionMethod(EncryptionMethod.A256GCM.getName());
        when(OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                .thenReturn(appDO);
        when(OAuth2Util.getX509CertOfOAuthApp(TEST_CLIENT_ID_1, SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(clientKeyStore.getCertificate(CLIENT_PUBLIC_CERT_ALIAS));

        RequestObjectValidator requestObjectValidator = new RequestObjectValidatorImpl();
        when((oauthServerConfigurationMock.getRequestObjectValidator())).thenReturn(requestObjectValidator);

        RequestObject requestObject;
        RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();

        requestObject = requestParamRequestObjectBuilder.buildRequestObject(jwt, oAuth2Parameters);

        Assert.assertTrue(requestParamRequestObjectBuilder.isEncrypted(jwt),
                "Payload should be encrypted for alg: " + algName);

        boolean validObject = requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters);
        Assert.assertTrue(validObject, "Request Object should be valid for alg: " + algName);
    }
}
