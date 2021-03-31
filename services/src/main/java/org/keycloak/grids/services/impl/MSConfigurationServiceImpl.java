/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.grids.services.impl;



import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.NameValuePair;
import org.keycloak.grids.factory.MSConfigurationResponseFactory;
import org.keycloak.grids.model.MSConfigurationResponse;
import org.keycloak.grids.services.KeyStoreService;
import org.keycloak.grids.services.MSConfigurationService;
import org.keycloak.grids.services.NetworkService;
import org.keycloak.grids.services.ParameterService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 *
 * @author nikos
 */

public class MSConfigurationServiceImpl implements MSConfigurationService {

    private final ParameterService paramServ;
    private final KeyStoreService keyServ;
    private final NetworkService netServ;
    private final HttpSignatureServiceImpl sigServ;

    //TODO cache the response for the metadata?
    private final static Logger LOG = LoggerFactory.getLogger(MSConfigurationServiceImpl.class);

    public MSConfigurationServiceImpl( ParameterService paramServ,  NetworkService netServ, KeyStoreService keyServ) throws InvalidKeySpecException, IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        this.paramServ = paramServ;

        this.keyServ = keyServ;
        Key signingKey = this.keyServ.getHttpSigningKey();
//        String fingerPrint = "7a9ba747ab5ac50e640a07d90611ce612b7bde775457f2e57b804517a87c813b";
        String fingerPrint = DigestUtils.sha256Hex(this.keyServ.getHttpSigPublicKey().getEncoded());
        this.sigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
        this.netServ = new NetworkServiceImpl(this.keyServ);
    }

    @Override
    public MSConfigurationResponse.MicroService[] getConfigurationJSON() {
        try {
            String confManager = paramServ.getParam("CONFIGURATION_MANAGER_URL");
            List<NameValuePair> getParams = new ArrayList();
            return MSConfigurationResponseFactory.makeMSConfigResponseFromJSON(netServ.sendGet(confManager, "/cm/metadata/microservices", getParams, 1));
        } catch (IOException | NoSuchAlgorithmException ex) {
            LOG.error(ex.getMessage());
            return null;
        }
    }

    @Override
    public Optional<String> getMsIDfromRSAFingerprint(String rsaFingerPrint) throws IOException {
        Optional<MSConfigurationResponse.MicroService> msMatch = Arrays.stream(getConfigurationJSON()).filter(msConfig -> {
            return DigestUtils.sha256Hex(msConfig.getRsaPublicKeyBinary()).equals(rsaFingerPrint);
        }).findFirst();

        if (msMatch.isPresent()) {
            return Optional.of(msMatch.get().getMsId());
        }

        return Optional.empty();
    }

    @Override
    public Optional<PublicKey> getPublicKeyFromFingerPrint(String rsaFingerPrint) throws InvalidKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Optional<MSConfigurationResponse.MicroService> msMatch = Arrays.stream(getConfigurationJSON()).filter(msConfig -> {
            return DigestUtils.sha256Hex(msConfig.getRsaPublicKeyBinary()).equals(rsaFingerPrint);
        }).findFirst();

        if (msMatch.isPresent()) {
            byte[] decoded = Base64.getDecoder().decode(msMatch.get().getRsaPublicKeyBinary());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return Optional.of(keyFactory.generatePublic(keySpec));
        }
        return Optional.empty();
    }

    @Override
    public String getMsEndpointByIdAndApiCall(String msId, String apiType) {
        Optional<String> pubEndpoint
                = Arrays.stream(getConfigurationJSON())
                        .filter(ms -> ms.getMsId().equals(msId))
                        .map(ms -> {
                            return Arrays.stream(ms.getPublishedAPI())
                                    .filter(apiEntry -> {
                                        return apiEntry.getApiCall().equals(apiType);
                                    }).findFirst();
                        })
                        .filter(publishedApi -> {
                            return publishedApi.isPresent();
                        }).map(api -> api.get().getApiEndpoint()).findFirst();

        if (pubEndpoint.isPresent()) {
            return pubEndpoint.get();
        }
        throw new HttpClientErrorException(HttpStatus.NOT_FOUND, " could not find endpoint for: " + msId + " " + apiType);
    }

}
