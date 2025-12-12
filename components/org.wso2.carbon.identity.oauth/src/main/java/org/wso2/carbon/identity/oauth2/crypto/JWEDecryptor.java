/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.identity.oauth2.crypto.impl.RSA_OAEP_384;
import org.wso2.carbon.identity.oauth2.crypto.impl.RSA_OAEP_512;

import javax.crypto.SecretKey;
import java.security.PrivateKey;

/**
 * JWE Decryptor based on Bouncy Castle Implementation
 */
public class JWEDecryptor extends RSADecrypter {

    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();

    public JWEDecryptor(PrivateKey privateKey) throws JOSEException {

        super(privateKey);
    }

    @Override
    public byte[] decrypt(final JWEHeader header, final Base64URL encryptedKey,
                          final Base64URL iv,
                          final Base64URL cipherText,
                          final Base64URL authTag)
            throws JOSEException {

        // Validate required JWE parts
        if (encryptedKey == null) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (iv == null) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (authTag == null) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        critPolicy.ensureHeaderPasses(header);

        // Derive the content encryption key
        com.nimbusds.jose.JWEAlgorithm alg = header.getAlgorithm();
        SecretKey cek;

        if (alg.equals(JWEAlgorithm.RSA_OAEP_384)) {
            cek = RSA_OAEP_384.decryptCEK(getPrivateKey(), encryptedKey.decode(),
                    getJCAContext().getKeyEncryptionProvider());
        } else if (alg.equals(JWEAlgorithm.RSA_OAEP_512)){
            cek = RSA_OAEP_512.decryptCEK(getPrivateKey(), encryptedKey.decode(),
                    getJCAContext().getKeyEncryptionProvider());
        } else {
            // For previously supported algorithms
            return super.decrypt(header, encryptedKey, iv, cipherText, authTag);
        }
        return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, getJCAContext());
    }
}
