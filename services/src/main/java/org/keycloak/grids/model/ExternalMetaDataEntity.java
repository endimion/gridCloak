package org.keycloak.grids.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ExternalMetaDataEntity {

    private String entityId;
    @JsonProperty("verified_claims_supported")
    private boolean verifierClaimsSupported;
    @JsonProperty("verified_claims_trusted_issuers")
    private String[] verifiedClaimsTrustedIssuers;
    @JsonProperty("trust_frameworks_supported")
    private String[] trustFramworksSupported;
    @JsonProperty("evidence_supported")
    private String[] evidenceSupported;
    @JsonProperty("id_documents_supported")
    private String[] idDocumentsSupported;
    @JsonProperty("id_documents_supported")
    private String[] idDocumentsVerificationMethodsSupported;
    @JsonProperty("claims_in_verified_claims_supported")
    private String[] claimsInVerifiedClaimsSupported;
    @JsonProperty("distributedClaimsIssuer")
    private String[] distributedClaimsIssuer;
    @JsonProperty("distributedClaimsSupported")
    private DistributedClaimsSupported[] distributedClaimsSupported;




}
