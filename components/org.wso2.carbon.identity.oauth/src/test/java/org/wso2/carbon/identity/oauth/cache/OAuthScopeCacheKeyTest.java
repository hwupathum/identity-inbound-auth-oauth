/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class OAuthScopeCacheKeyTest {
    String scopeName = "Scope1";
    Integer scopeTenantHashCode = (scopeName).hashCode();

    @Test
    public void testGetScopeName() throws Exception {
        OAuthScopeCacheKey authScopeCacheKey = new OAuthScopeCacheKey(scopeName);
        assertEquals(authScopeCacheKey.getScopeName(), scopeName
                , "Get Scope name successfully.");
    }

    @DataProvider(name = "TestEqualsAuthorizationGrant")
    public Object[][] testequals() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "TestEqualsAuthorizationGrant")
    public void testEquals(boolean isTrue) throws Exception {
        Object object = new Object();
        OAuthScopeCacheKey oauthScopeCacheKey = new OAuthScopeCacheKey(scopeName);
        OAuthScopeCacheKey oAuthScopeCacheKeySample = new OAuthScopeCacheKey(scopeName);
        if (isTrue) {
            assertEquals(oAuthScopeCacheKeySample, oauthScopeCacheKey);
        }
        assertNotEquals(object, oauthScopeCacheKey);
    }

    @Test
    public void testHashCode() throws Exception {
        OAuthScopeCacheKey authScopeCacheKey = new OAuthScopeCacheKey(scopeName);
        Integer authScopeCacheKeysample = authScopeCacheKey.hashCode();
        assertEquals(authScopeCacheKeysample, scopeTenantHashCode, "Get tenant and scope hash code successfully. ");
    }
}
