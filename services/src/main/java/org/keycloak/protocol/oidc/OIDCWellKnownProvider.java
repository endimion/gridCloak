/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oidc;

import com.google.common.collect.Streams;
import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.ClientAuthenticatorFactory;
import org.keycloak.crypto.CekManagementProvider;
import org.keycloak.crypto.ClientSignatureVerifierProvider;
import org.keycloak.crypto.ContentEncryptionProvider;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.grids.services.KeyStoreService;
import org.keycloak.grids.services.ParameterService;
import org.keycloak.grids.services.impl.KeyStoreServiceImpl;
import org.keycloak.grids.services.impl.NetworkServiceImpl;
import org.keycloak.grids.services.impl.ParameterServiceImpl;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.endpoints.TokenEndpoint;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.IDToken;
import org.keycloak.services.Urls;
import org.keycloak.services.clientregistration.ClientRegistrationService;
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProviderFactory;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.urls.UrlType;
import org.keycloak.wellknown.WellKnownProvider;

import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import java.io.IOException;
import java.net.URI;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class OIDCWellKnownProvider implements WellKnownProvider {

    private static final Logger log = LoggerFactory.getLogger(OIDCWellKnownProvider.class);

    public static final List<String> DEFAULT_GRANT_TYPES_SUPPORTED = list(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.IMPLICIT, OAuth2Constants.REFRESH_TOKEN, OAuth2Constants.PASSWORD, OAuth2Constants.CLIENT_CREDENTIALS);

    public static final List<String> DEFAULT_RESPONSE_TYPES_SUPPORTED = list(OAuth2Constants.CODE, OIDCResponseType.NONE, OIDCResponseType.ID_TOKEN, OIDCResponseType.TOKEN, "id_token token", "code id_token", "code token", "code id_token token");

    public static final List<String> DEFAULT_SUBJECT_TYPES_SUPPORTED = list("public", "pairwise");

    public static final List<String> DEFAULT_RESPONSE_MODES_SUPPORTED = list("query", "fragment", "form_post");

    public static final List<String> DEFAULT_CLIENT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = list(Algorithm.RS256.toString());

    // The exact list depends on protocolMappers
    public static final List<String> DEFAULT_CLAIMS_SUPPORTED= list("aud", "sub", "iss", IDToken.AUTH_TIME, IDToken.NAME, IDToken.GIVEN_NAME, IDToken.FAMILY_NAME, IDToken.PREFERRED_USERNAME, IDToken.EMAIL, IDToken.ACR);

    public static final List<String> DEFAULT_CLAIM_TYPES_SUPPORTED= list("normal");

    // KEYCLOAK-7451 OAuth Authorization Server Metadata for Proof Key for Code Exchange
    public static final List<String> DEFAULT_CODE_CHALLENGE_METHODS_SUPPORTED = list(OAuth2Constants.PKCE_METHOD_PLAIN, OAuth2Constants.PKCE_METHOD_S256);

    private KeycloakSession session;

    public OIDCWellKnownProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getConfig() {
        UriInfo frontendUriInfo = session.getContext().getUri(UrlType.FRONTEND);
        UriInfo backendUriInfo = session.getContext().getUri(UrlType.BACKEND);

        RealmModel realm = session.getContext().getRealm();

        UriBuilder frontendUriBuilder = RealmsResource.protocolUrl(frontendUriInfo);
        UriBuilder backendUriBuilder = RealmsResource.protocolUrl(backendUriInfo);

        OIDCConfigurationRepresentation config = new OIDCConfigurationRepresentation();
        config.setIssuer(Urls.realmIssuer(frontendUriInfo.getBaseUri(), realm.getName()));
        config.setAuthorizationEndpoint(frontendUriBuilder.clone().path(OIDCLoginProtocolService.class, "auth").build(realm.getName(), OIDCLoginProtocol.LOGIN_PROTOCOL).toString());
        config.setTokenEndpoint(backendUriBuilder.clone().path(OIDCLoginProtocolService.class, "token").build(realm.getName(), OIDCLoginProtocol.LOGIN_PROTOCOL).toString());
        config.setIntrospectionEndpoint(backendUriBuilder.clone().path(OIDCLoginProtocolService.class, "token").path(TokenEndpoint.class, "introspect").build(realm.getName(), OIDCLoginProtocol.LOGIN_PROTOCOL).toString());
        config.setUserinfoEndpoint(backendUriBuilder.clone().path(OIDCLoginProtocolService.class, "issueUserInfo").build(realm.getName(), OIDCLoginProtocol.LOGIN_PROTOCOL).toString());
        config.setLogoutEndpoint(frontendUriBuilder.clone().path(OIDCLoginProtocolService.class, "logout").build(realm.getName(), OIDCLoginProtocol.LOGIN_PROTOCOL).toString());
        URI jwksUri = backendUriBuilder.clone().path(OIDCLoginProtocolService.class, "certs").build(realm.getName(),
            OIDCLoginProtocol.LOGIN_PROTOCOL);

        // NOTE: Don't hardcode HTTPS checks here. JWKS URI is exposed just in the development/testing environment. For the production environment, the OIDCWellKnownProvider
        // is not exposed over "http" at all.
        //if (isHttps(jwksUri)) {
        config.setJwksUri(jwksUri.toString());

        config.setCheckSessionIframe(frontendUriBuilder.clone().path(OIDCLoginProtocolService.class, "getLoginStatusIframe").build(realm.getName(), OIDCLoginProtocol.LOGIN_PROTOCOL).toString());
        config.setRegistrationEndpoint(RealmsResource.clientRegistrationUrl(backendUriInfo).path(ClientRegistrationService.class, "provider").build(realm.getName(), OIDCClientRegistrationProviderFactory.ID).toString());

        config.setIdTokenSigningAlgValuesSupported(getSupportedSigningAlgorithms(false));
        config.setIdTokenEncryptionAlgValuesSupported(getSupportedIdTokenEncryptionAlg(false));
        config.setIdTokenEncryptionEncValuesSupported(getSupportedIdTokenEncryptionEnc(false));
        config.setUserInfoSigningAlgValuesSupported(getSupportedSigningAlgorithms(true));
        config.setRequestObjectSigningAlgValuesSupported(getSupportedClientSigningAlgorithms(true));
        config.setResponseTypesSupported(DEFAULT_RESPONSE_TYPES_SUPPORTED);
        config.setSubjectTypesSupported(DEFAULT_SUBJECT_TYPES_SUPPORTED);
        config.setResponseModesSupported(DEFAULT_RESPONSE_MODES_SUPPORTED);
        config.setGrantTypesSupported(DEFAULT_GRANT_TYPES_SUPPORTED);

        config.setTokenEndpointAuthMethodsSupported(getClientAuthMethodsSupported());
        config.setTokenEndpointAuthSigningAlgValuesSupported(getSupportedClientSigningAlgorithms(false));
        config.setIntrospectionEndpointAuthMethodsSupported(getClientAuthMethodsSupported());
        config.setIntrospectionEndpointAuthSigningAlgValuesSupported(getSupportedClientSigningAlgorithms(false));

        config.setClaimsSupported(DEFAULT_CLAIMS_SUPPORTED);
        config.setClaimTypesSupported(DEFAULT_CLAIM_TYPES_SUPPORTED);
        config.setClaimsParameterSupported(true);

        List<String> scopeNames = realm.getClientScopesStream()
                .filter(clientScope -> Objects.equals(OIDCLoginProtocol.LOGIN_PROTOCOL, clientScope.getProtocol()))
                .map(ClientScopeModel::getName)
                .collect(Collectors.toList());
        scopeNames.add(0, OAuth2Constants.SCOPE_OPENID);
        config.setScopesSupported(scopeNames);

        config.setRequestParameterSupported(true);
        config.setRequestUriParameterSupported(true);
        config.setRequireRequestUriRegistration(true);

        // KEYCLOAK-7451 OAuth Authorization Server Metadata for Proof Key for Code Exchange
        config.setCodeChallengeMethodsSupported(DEFAULT_CODE_CHALLENGE_METHODS_SUPPORTED);

        // KEYCLOAK-6771 Certificate Bound Token
        // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-6.2
        config.setTlsClientCertificateBoundAccessTokens(true);

        URI revocationEndpoint = frontendUriBuilder.clone().path(OIDCLoginProtocolService.class, "revoke")
            .build(realm.getName(), OIDCLoginProtocol.LOGIN_PROTOCOL);

        // NOTE: Don't hardcode HTTPS checks here. JWKS URI is exposed just in the development/testing environment. For the production environment, the OIDCWellKnownProvider
        // is not exposed over "http" at all.
        //if (isHttps(jwksUri)) {
        config.setRevocationEndpoint(revocationEndpoint.toString());
        config.setRevocationEndpointAuthMethodsSupported(getClientAuthMethodsSupported());
        config.setRevocationEndpointAuthSigningAlgValuesSupported(getSupportedClientSigningAlgorithms(false));

        config.setBackchannelLogoutSupported(true);
        config.setBackchannelLogoutSessionSupported(true);


//        Map<String, Object> otherClaims = config.getOtherClaims();
        ParameterService paramServ = new ParameterServiceImpl();
        String CONF_MANAGER_URL = StringUtils.isEmpty(paramServ.getParam("CONF_MANAGER_URL"))?"http://localhost:8188":
                paramServ.getParam("CONF_MANAGER_URL");

        try {
            KeyStoreService keyServ = new KeyStoreServiceImpl(paramServ);
            NetworkServiceImpl netServ = new NetworkServiceImpl(keyServ);
            String uri = "/metadata/externalEntities/gridsMetadata";

            List<NameValuePair> getParams = new ArrayList<>();
            String gridsMetadataResponse = netServ.sendGet(CONF_MANAGER_URL, uri, getParams, 1);
//            resp = this.mapper.readValue(
//                    tokenGenResponse, SessionMngrResponse.class);


            config.getOtherClaims().put("entityMetadata",gridsMetadataResponse);


            log.info("HEY!!! Wellknown called here!!!");


        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeySpecException | IOException | CertificateException e) {
//            e.printStackTrace();
            log.error(e.getMessage());
        }


        return config;
    }

    @Override
    public void close() {
    }

    private static List<String> list(String... values) {
        return Arrays.asList(values);
    }

    private List<String> getClientAuthMethodsSupported() {
        return session.getKeycloakSessionFactory().getProviderFactoriesStream(ClientAuthenticator.class)
                .map(ClientAuthenticatorFactory.class::cast)
                .map(caf -> caf.getProtocolAuthenticatorMethods(OIDCLoginProtocol.LOGIN_PROTOCOL))
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }

    private List<String> getSupportedAlgorithms(Class<? extends Provider> clazz, boolean includeNone) {
        Stream<String> supportedAlgorithms = session.getKeycloakSessionFactory().getProviderFactoriesStream(clazz)
                .map(ProviderFactory::getId);

        if (includeNone) {
            supportedAlgorithms = Streams.concat(supportedAlgorithms, Stream.of("none"));
        }
        return supportedAlgorithms.collect(Collectors.toList());
    }

    private List<String> getSupportedSigningAlgorithms(boolean includeNone) {
        return getSupportedAlgorithms(SignatureProvider.class, includeNone);
    }

    private List<String> getSupportedClientSigningAlgorithms(boolean includeNone) {
        return getSupportedAlgorithms(ClientSignatureVerifierProvider.class, includeNone);
    }

    private List<String> getSupportedIdTokenEncryptionAlg(boolean includeNone) {
        return getSupportedAlgorithms(CekManagementProvider.class, includeNone);
    }

    private List<String> getSupportedIdTokenEncryptionEnc(boolean includeNone) {
        return getSupportedAlgorithms(ContentEncryptionProvider.class, includeNone);
    }
}
