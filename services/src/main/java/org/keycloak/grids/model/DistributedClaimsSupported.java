package org.keycloak.grids.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DistributedClaimsSupported {

    @JsonProperty("distributedClaimsIssuer")
    private String distributeClaimsIssuer;
    @JsonProperty("trust_frameworks_supported")
    private String[] trustFrameworksSupported;
    @JsonProperty("evidence_supported")
    private String[] evidenceSupported;
    @JsonProperty("id_documents_verification_methods_supported")
    private String[] idDocumentsVerificationMethodsSupported;
    @JsonProperty("claims_in_verified_claims_supported")
    private String claimsInVerificedClaimsSupported;
    @JsonProperty("successfullyQueried")
    private String succesfullyQueried;

}
