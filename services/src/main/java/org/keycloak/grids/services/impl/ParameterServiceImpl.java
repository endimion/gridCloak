/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.grids.services.impl;

import org.apache.commons.lang.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.grids.services.ParameterService;
import org.keycloak.protocol.oidc.OIDCWellKnownProvider;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;


import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 *
 * @author nikos
 */
public class ParameterServiceImpl implements ParameterService {

//    private final Logger log = LoggerFactory.getLogger(ParameterServiceImpl.class);
private static final Logger log = Logger.getLogger(OIDCWellKnownProvider.class);

    private final Map<String, String> properties;

    public ParameterServiceImpl() {
        properties = getConfigProperties();
    }

    @Override
    public String getParam(String paramName) {
        if (StringUtils.isEmpty(System.getenv(paramName))) {
//            return properties.get(paramName);
            // CLIENT_ID=test-ssi;
            // CLIENT_SECRET=5da95a22-1eb9-4026-9e5a-2367fa02f8e8;
            // ISSUER_URI=https://dss1.aegean.gr/auth/realms/SSI;
            // KEYSTORE_PATH=/home/ni/code/java/seal-ssi-idp-ms/src/test/resources/testKeys/keystore.jks;
            // KEY_PASS=selfsignedpass;
            // STORE_PASS=keystorepass;
            // JWT_CERT_ALIAS=selfsigned;
            // HTTPSIG_CERT_ALIAS=1;
            // ASYNC_SIGNATURE=true;
            // SESSION_MANAGER_URL=http://vm.project-seal.grnet.gr:9090;MSTOKEN_SENDER_ID=eIDAS-IdP;ACM_ID=ACM_ID
            switch (paramName){
                case "KEYSTORE_PATH": return "/home/ni/code/java/seal-ssi-idp-ms/src/test/resources/testKeys/keystore.jks";
                case "KEY_PASS": return "selfsignedpass";
                case "STORE_PASS": return "keystorepass";
                case "JWT_CERT_ALIAS": return "selfsigned";
                case "HTTPSIG_CERT_ALIAS": return "1";
                case "ASYNC_SIGNATURE": return "true";
                default: return "";

            }
        }
        return System.getenv(paramName);
    }

    private Map<String, String> getConfigProperties() {
        Properties prop = new Properties();
        InputStream input = null;
        HashMap<String, String> map = new HashMap();
        try {
            input = new FileInputStream("/webappConfig/config.properties");
            prop.load(input);
            prop.forEach((key, value) -> {
                map.put((String) key, (String) value);
            });
        } catch (IOException ex) {
//            log.debug("Properties file not found in /webappConfig/config.properties", ex);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    log.debug(e.getLocalizedMessage());
                }
            }
        }
        return map;
    }

}
