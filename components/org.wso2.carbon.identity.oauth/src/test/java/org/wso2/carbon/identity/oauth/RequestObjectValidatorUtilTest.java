/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;
import org.testng.annotations.Test;

import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;

public class RequestObjectValidatorUtilTest {

    @Test
    public void testPS256SignatureVerifiedWithRSACert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).build();
        when(mockJwt.getHeader()).thenReturn(header);

        Certificate mockCert = mock(Certificate.class);
        RSAPublicKey mockPk = mock(RSAPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testRS256SignatureVerifiedWithRSACert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        when(mockJwt.getHeader()).thenReturn(header);

        Certificate mockCert = mock(Certificate.class);
        RSAPublicKey mockPk = mock(RSAPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testSignatureVerifiedWithECCert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
        when(mockJwt.getHeader()).thenReturn(header);

        Certificate mockCert = mock(Certificate.class);
        ECPublicKey mockPk = mock(ECPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testSignatureVerifiedWithECMismatchCert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).build();
        when(mockJwt.getHeader()).thenReturn(header);

        Certificate mockCert = mock(Certificate.class);
        ECPublicKey mockPk = mock(ECPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testSignatureVerifiedWithRSAMismatchCert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
        when(mockJwt.getHeader()).thenReturn(header);

        Certificate mockCert = mock(Certificate.class);
        RSAPublicKey mockPk = mock(RSAPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testSignatureVerifiedUnsupportedAlgo() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).build();
        when(mockJwt.getHeader()).thenReturn(header);

        Certificate mockCert = mock(Certificate.class);

        assertFalse(RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert));
    }
}
