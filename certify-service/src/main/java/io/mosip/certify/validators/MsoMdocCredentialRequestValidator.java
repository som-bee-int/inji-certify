package io.mosip.certify.validators;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialRequestNew;

public class MsoMdocCredentialRequestValidator {
    public static boolean isValidCheck(CredentialRequest credentialRequest) {
        if (credentialRequest.getDoctype() == null || credentialRequest.getDoctype().isBlank()) {
            return false;
        }
        return credentialRequest.getClaims() != null && !credentialRequest.getClaims().isEmpty();
    }
    public static boolean isValidCheck(CredentialRequestNew credentialRequest) {
        if (credentialRequest.getDoctype() == null || credentialRequest.getDoctype().isBlank()) {
            return false;
        }
        return credentialRequest.getClaims() != null && !credentialRequest.getClaims().isEmpty();
    }
}
