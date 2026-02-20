/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.oauth2.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.identity.oauth2.crypto.impl.RSAOAEP384;
import org.wso2.carbon.identity.oauth2.crypto.impl.RSAOAEP512;

import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

/**
 * JWE Encryptor based on Bouncy Castle Implementation
 */
public class JWEEncryptor extends RSAEncrypter {

    /**
     * The externally supplied AES content encryption key (CEK) to use,
     * {@code null} to generate a CEK for each JWE.
     */
    private final SecretKey contentEncryptionKey;

    public Set<com.nimbusds.jose.JWEAlgorithm> supportedJWEAlgorithms() {

        Set<com.nimbusds.jose.JWEAlgorithm> supportedALgo = new HashSet<>(super.supportedJWEAlgorithms());
        supportedALgo.add(JWEAlgorithm.RSA_OAEP_384);
        supportedALgo.add(JWEAlgorithm.RSA_OAEP_512);
        return supportedALgo;
    }

    public JWEEncryptor(RSAPublicKey publicKey) {

        super(publicKey);
        this.contentEncryptionKey = null;
    }

    public JWEEncryptor(final RSAPublicKey publicKey, final SecretKey contentEncryptionKey) {

        super(publicKey, contentEncryptionKey);
        this.contentEncryptionKey = contentEncryptionKey;
    }

    @Override
    public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
            throws JOSEException {

        final com.nimbusds.jose.JWEAlgorithm alg = header.getAlgorithm();
        if (!(alg.equals(JWEAlgorithm.RSA_OAEP_384) || alg.equals(JWEAlgorithm.RSA_OAEP_512))) {
            return super.encrypt(header, clearText);
        }

        final EncryptionMethod enc = header.getEncryptionMethod();

        // Generate and encrypt the CEK according to the enc method
        final SecretKey cek;
        if (contentEncryptionKey != null) {
            // Use externally supplied CEK
            cek = contentEncryptionKey;
        } else {
            // Generate and encrypt the CEK according to the enc method
            cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());
        }

        final Base64URL encryptedKey; // The second JWE part

        if (alg.equals(JWEAlgorithm.RSA_OAEP_384)) {
            encryptedKey = Base64URL.encode(RSAOAEP384.encryptCEK(getPublicKey(),
                    cek, getJCAContext().getKeyEncryptionProvider()));
        } else {
            // Encrypt with RSA_OAEP_512 as these are the only two extended algorithms
            encryptedKey = Base64URL.encode(RSAOAEP512.encryptCEK(getPublicKey(),
                    cek, getJCAContext().getKeyEncryptionProvider()));
        }
        return ContentCryptoProvider.encrypt(header, clearText, cek, encryptedKey, getJCAContext());
    }
}
