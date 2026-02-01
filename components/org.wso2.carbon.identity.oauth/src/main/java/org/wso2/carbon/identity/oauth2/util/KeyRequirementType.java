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

import java.util.Objects;

/**
 * Describes the cryptographic key requirements for supported JOSE algorithms.
 */
public final class KeyRequirementType {

    /**
     * Supported cryptographic key types.
     */
    public enum KeyType {
        RSA,
        EC
    }

    /**
     * Elliptic curve requirements for EC based keys.
     */
    public enum CurveRequirement {
        NONE,
        P_256
    }

    /**
     * RSA key without curve requirements.
     */
    public static final KeyRequirementType RSA_NO_CURVE =
            new KeyRequirementType(KeyType.RSA, CurveRequirement.NONE);

    /**
     * EC key requiring P 256 curve.
     */
    public static final KeyRequirementType EC_P256 =
            new KeyRequirementType(KeyType.EC, CurveRequirement.P_256);

    private final KeyType keyType;
    private final CurveRequirement curveRequirement;

    private KeyRequirementType(KeyType keyType, CurveRequirement curveRequirement) {
        this.keyType = Objects.requireNonNull(keyType, "KeyType cannot be null");
        this.curveRequirement = Objects.requireNonNull(curveRequirement,
                "CurveRequirement cannot be null");
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public CurveRequirement getCurveRequirement() {
        return curveRequirement;
    }
}
