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

import com.nimbusds.jose.Requirement;

public class JWEAlgorithm {

    /**
     * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
     * with the SHA-512 hash function and the MGF1 with SHA-384 mask
     * generation function.
     */
    public static final com.nimbusds.jose.JWEAlgorithm RSA_OAEP_384 = new com.nimbusds.jose.JWEAlgorithm(
            "RSA-OAEP-384", Requirement.OPTIONAL);

    /**
     * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
     * with the SHA-512 hash function and the MGF1 with SHA-512 mask
     * generation function.
     */
    public static final com.nimbusds.jose.JWEAlgorithm RSA_OAEP_512 = new com.nimbusds.jose.JWEAlgorithm(
            "RSA-OAEP-512", Requirement.OPTIONAL);
}
