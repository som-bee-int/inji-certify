package io.mosip.certify.validators;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialRequestNew;

public class LdpVcCredentialRequestValidator {
    public static boolean isValidCheck(CredentialRequest credentialRequest) {
        return credentialRequest.getCredential_definition() != null;
    }
    public static boolean isValidCheck(CredentialRequestNew credentialRequest) {
        return credentialRequest.getCredential_definition() != null;
    }
}
