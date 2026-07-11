/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.validators.jwt;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.core.util.OutboundRequestFilter;
import org.wso2.carbon.identity.oauth2.cache.JWKSCache;

import java.net.MalformedURLException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Unit tests for {@link JWKSourceDataProvider}, focused on the outbound request filter enforcement
 * at the JWKS fetch sink and its enable flag.
 */
public class JWKSourceDataProviderTest {

    private static final String ENFORCE_XPATH = "JWTValidatorConfigs.JWKSEndpoint.EnforceOutboundRequestFilter";

    /**
     * Enforcement enabled and the filter permits the destination: the sink builds the RemoteJWKSet
     * as before — no exception, non-null result.
     */
    @Test
    public void testFetchProceedsWhenEnabledAndFilterAllows() throws Exception {

        JWKSCache jwksCache = mock(JWKSCache.class);
        when(jwksCache.getValueFromCache(any())).thenReturn(null);

        try (MockedStatic<OutboundRequestFilter> filterStatic = mockStatic(OutboundRequestFilter.class);
             MockedStatic<JWKSCache> cacheStatic = mockStatic(JWKSCache.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            filterStatic.when(() -> OutboundRequestFilter.isAllowed(anyString())).thenReturn(true);
            cacheStatic.when(JWKSCache::getInstance).thenReturn(jwksCache);
            identityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn(null);
            identityUtil.when(() -> IdentityUtil.getProperty(eq(ENFORCE_XPATH))).thenReturn("true");

            String jwksUri = "https://as." + System.nanoTime() + ".external.example.com/oauth2/jwks";
            RemoteJWKSet<SecurityContext> jwkSet = JWKSourceDataProvider.getInstance().getJWKSource(jwksUri);
            assertNotNull(jwkSet, "A RemoteJWKSet should be returned when the filter allows the destination.");
        }
    }

    /**
     * Enforcement enabled and the filter rejects the destination (e.g. jwks_uri points at an internal
     * address): the sink must reject before any network call by throwing a MalformedURLException whose
     * message describes the policy block. (validateSignature upstream rewraps it as an
     * IdentityOAuth2Exception, surfacing as invalid_request_object.)
     */
    @Test
    public void testFetchRejectedWhenEnabledAndFilterBlocks() {

        JWKSCache jwksCache = mock(JWKSCache.class);
        when(jwksCache.getValueFromCache(any())).thenReturn(null);

        try (MockedStatic<OutboundRequestFilter> filterStatic = mockStatic(OutboundRequestFilter.class);
             MockedStatic<JWKSCache> cacheStatic = mockStatic(JWKSCache.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            filterStatic.when(() -> OutboundRequestFilter.isAllowed(anyString())).thenReturn(false);
            cacheStatic.when(JWKSCache::getInstance).thenReturn(jwksCache);
            identityUtil.when(() -> IdentityUtil.getProperty(eq(ENFORCE_XPATH))).thenReturn("true");

            String jwksUri = "http://127.0.0.1:8899/jwks-" + System.nanoTime() + ".json";
            try {
                JWKSourceDataProvider.getInstance().getJWKSource(jwksUri);
                fail("Expected MalformedURLException when the outbound request filter blocks the jwks_uri.");
            } catch (MalformedURLException e) {
                assertTrue(e.getMessage().contains("not permitted"),
                        "Rejection message should describe the policy block. Actual: " + e.getMessage());
            } catch (Exception e) {
                fail("Expected MalformedURLException but got: " + e.getClass().getName() + " - " + e.getMessage());
            }
        }
    }

    /**
     * Enforcement disabled (the shipped default): the sink must NOT consult the filter and must fetch
     * exactly as the unpatched server did — even for a host the filter would otherwise block. This is
     * the default-off regression guard.
     */
    @Test
    public void testFetchProceedsWhenEnforcementDisabled() throws Exception {

        JWKSCache jwksCache = mock(JWKSCache.class);
        when(jwksCache.getValueFromCache(any())).thenReturn(null);

        try (MockedStatic<OutboundRequestFilter> filterStatic = mockStatic(OutboundRequestFilter.class);
             MockedStatic<JWKSCache> cacheStatic = mockStatic(JWKSCache.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            // Filter would block, but enforcement is off, so it must never be consulted.
            filterStatic.when(() -> OutboundRequestFilter.isAllowed(anyString())).thenReturn(false);
            cacheStatic.when(JWKSCache::getInstance).thenReturn(jwksCache);
            identityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn(null);

            String jwksUri = "http://127.0.0.1:8899/jwks-" + System.nanoTime() + ".json";
            RemoteJWKSet<SecurityContext> jwkSet = JWKSourceDataProvider.getInstance().getJWKSource(jwksUri);
            assertNotNull(jwkSet, "With enforcement disabled the fetch must proceed unchanged.");

            filterStatic.verify(() -> OutboundRequestFilter.isAllowed(anyString()), org.mockito.Mockito.never());
        }
    }
}
