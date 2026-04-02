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
package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Immutable registry mapping JOSE algorithms to cryptographic key requirements.
 */
public final class AlgorithmKeyMapping {

    private static final Map<JWSAlgorithm, KeyRequirementType> SIGNING = buildSigningMap();
    private static final Map<JWEAlgorithm, KeyRequirementType> ENCRYPTION = buildEncryptionMap();

    private AlgorithmKeyMapping() {
        // Prevent instantiation
    }

    /**
     * Return key requirements for the given JWS signing algorithm.
     *
     * @param algorithm JWS signing algorithm.
     * @return Required key type and curve.
     * @throws NullPointerException if the algorithm is null.
     * @throws IllegalArgumentException if the algorithm is not supported.
     */
    public static KeyRequirementType signing(JWSAlgorithm algorithm) {

        KeyRequirementType requirement = SIGNING.get(algorithm);
        if (requirement == null) {
            throw new IllegalArgumentException("Unsupported signing algorithm: " + algorithm);
        }
        return requirement;
    }

    /**
     * Return key requirements for the given JWE encryption algorithm.
     *
     * @param algorithm JWE encryption algorithm.
     * @return Required key type and curve.
     * @throws NullPointerException if the algorithm is null.
     * @throws IllegalArgumentException if the algorithm is not supported.
     */
    public static KeyRequirementType encryption(JWEAlgorithm algorithm) {

        KeyRequirementType requirement = ENCRYPTION.get(algorithm);
        if (requirement == null) {
            throw new IllegalArgumentException("Unsupported encryption algorithm: " + algorithm);
        }
        return requirement;
    }

    /**
     * Build signing algorithm to key requirement mapping.
     *
     * @return Unmodifiable signing algorithm map.
     */
    private static Map<JWSAlgorithm, KeyRequirementType> buildSigningMap() {

        Map<JWSAlgorithm, KeyRequirementType> map = new HashMap<>();

        map.put(JWSAlgorithm.RS256, KeyRequirementType.RSA_NO_CURVE);
        map.put(JWSAlgorithm.PS256, KeyRequirementType.RSA_NO_CURVE);
        map.put(JWSAlgorithm.ES256, KeyRequirementType.EC_P256);

        return Collections.unmodifiableMap(map);
    }

    /**
     * Build encryption algorithm to key requirement mapping.
     *
     * @return Unmodifiable encryption algorithm map.
     */
    private static Map<JWEAlgorithm, KeyRequirementType> buildEncryptionMap() {

        Map<JWEAlgorithm, KeyRequirementType> map = new HashMap<>();

        map.put(JWEAlgorithm.RSA_OAEP, KeyRequirementType.RSA_NO_CURVE);
        map.put(JWEAlgorithm.RSA_OAEP_256, KeyRequirementType.RSA_NO_CURVE);
        map.put(JWEAlgorithm.RSA1_5, KeyRequirementType.RSA_NO_CURVE);

        map.put(org.wso2.carbon.identity.oauth2.crypto.JWEAlgorithm.RSA_OAEP_384,
                KeyRequirementType.RSA_NO_CURVE);
        map.put(org.wso2.carbon.identity.oauth2.crypto.JWEAlgorithm.RSA_OAEP_512,
                KeyRequirementType.RSA_NO_CURVE);

        map.put(JWEAlgorithm.ECDH_ES_A128KW, KeyRequirementType.EC_P256);
        map.put(JWEAlgorithm.ECDH_ES_A192KW, KeyRequirementType.EC_P256);
        map.put(JWEAlgorithm.ECDH_ES_A256KW, KeyRequirementType.EC_P256);

        return Collections.unmodifiableMap(map);
    }
}
