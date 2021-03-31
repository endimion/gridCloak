/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.grids.model;

import com.fasterxml.jackson.annotation.JsonAlias;

/**
 *
 * @author nikos
 */
public class MSConfigurationResponse {

    private MicroService[] ms;

    public MSConfigurationResponse() {
    }

    public MSConfigurationResponse(MicroService[] ms) {
        this.ms = ms;
    }

    public MicroService[] getMs() {
        return ms;
    }

    public void setMs(MicroService[] ms) {
        this.ms = ms;
    }

    //static is needed for jackson
    public static class MicroService {

        @JsonAlias({"msId", "msID"})
        private String msId;
        private String[] authorisedMicroservices; // List of ms identifiers that will be authorised to contact this microservice (will be used by the SM when validating a token).
        private String msType;
        private String rsaPublicKeyBinary;
        private PublishedAPI[] publishedAPI;

        public MicroService(String msID, String msType, String rsaPublicKeyBinary, PublishedAPI[] publishedAPI, String[] authorizedMicroservices) {
            this.msId = msID;
            this.msType = msType;
            this.rsaPublicKeyBinary = rsaPublicKeyBinary;
            this.publishedAPI = publishedAPI;
            this.authorisedMicroservices= authorizedMicroservices;
        }

        public String[] getAuthorisedMicroservices() {
            return authorisedMicroservices;
        }

        public void setAuthorisedMicroservices(String[] authorisedMicroservices) {
            this.authorisedMicroservices = authorisedMicroservices;
        }

        
        public MicroService() {
        }

        public String getMsId() {
            return msId;
        }

        public void setMsId(String msId) {
            this.msId = msId;
        }

        public String getMsType() {
            return msType;
        }

        public void setMsType(String msType) {
            this.msType = msType;
        }

        public String getRsaPublicKeyBinary() {
            return rsaPublicKeyBinary;
        }

        public void setRsaPublicKeyBinary(String rsaPublicKeyBinary) {
            this.rsaPublicKeyBinary = rsaPublicKeyBinary;
        }

        public PublishedAPI[] getPublishedAPI() {
            return publishedAPI;
        }

        public void setPublishedAPI(PublishedAPI[] publishedAPI) {
            this.publishedAPI = publishedAPI;
        }

    }

    //static is needed for jackson
    public static class PublishedAPI {

        private String apiClass;
        private String apiCall;
        private String apiConnectionType;
        private String apiEndpoint;

        public PublishedAPI() {
        }

        public PublishedAPI(String apiClass, String apiCall, String apiConnectionType, String url) {
            this.apiClass = apiClass;
            this.apiCall = apiCall;
            this.apiConnectionType = apiConnectionType;
            this.apiEndpoint = url;
        }

        public String getApiClass() {
            return apiClass;
        }

        public void setApiClass(String apiClass) {
            this.apiClass = apiClass;
        }

        public String getApiCall() {
            return apiCall;
        }

        public void setApiCall(String apiCall) {
            this.apiCall = apiCall;
        }

        public String getApiConnectionType() {
            return apiConnectionType;
        }

        public void setApiConnectionType(String apiConnectionType) {
            this.apiConnectionType = apiConnectionType;
        }

        public String getApiEndpoint() {
            return apiEndpoint;
        }

        public void setApiEndpoint(String apiEndpoint) {
            this.apiEndpoint = apiEndpoint;
        }

    }

}
