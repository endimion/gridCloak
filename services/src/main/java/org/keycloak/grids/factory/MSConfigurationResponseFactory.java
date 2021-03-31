/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.grids.factory;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.grids.model.MSConfigurationResponse;

import java.io.IOException;

/**
 *
 * @author nikos
 */
public class MSConfigurationResponseFactory {

    public static MSConfigurationResponse.MicroService[] makeMSConfigResponseFromJSON(String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
//        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper.readValue(json, MSConfigurationResponse.MicroService[].class);
    }

}
