/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialRequestNew;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.exception.InvalidNonceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.Locale;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/issuance")
public class VCIssuanceController {

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    MessageSource messageSource;

    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/credential",produces = "application/json")
    public CredentialResponse getCredential(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        log.info("in certify /credential");
        log.info("credential requets: {}",credentialRequest);
        return vcIssuanceService.getCredential(credentialRequest);
    }

    // @PostMapping(value = "/VC",produces = "application/json")
    // public CredentialResponse getCredentialSingpass( @RequestBody CredentialRequestNew credentialRequest) throws CertifyException {
    //     log.info("in certify /credentialSingpass");
    //     log.info("credential requets: {}",credentialRequest);
    //     //return new CredentialResponse<>();
    //     return vcIssuanceService.getCredentialNew(credentialRequest);
    //     //return vcIssuanceService.getCredential(credentialRequest);
    // }

    @PostMapping(value = "/new/credential",produces = "application/json")
    public CredentialResponse getCredentialSingpass( @RequestBody CredentialRequestNew credentialRequest) throws CertifyException {
        log.info("in certify /credentialSingpass");
        log.info("credential requets: {}",credentialRequest);
        //return new CredentialResponse<>();
        return vcIssuanceService.getCredentialNew(credentialRequest);
        //return vcIssuanceService.getCredential(credentialRequest);
    }

    @PostMapping(value = "/echo", consumes = "text/plain", produces = "text/plain")
    public String echo(@RequestBody String input) {
        log.info("Echo endpoint received input: {}", input);
        return input;
    }


    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/vd12/credential",produces = "application/json")
    public CredentialResponse getCredentialV12Draft(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        CredentialResponse credentialResponse = vcIssuanceService.getCredential(credentialRequest);
        credentialResponse.setFormat(credentialRequest.getFormat());
        return credentialResponse;
    }


    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/vd11/credential",produces = "application/json")
    public CredentialResponse getCredentialV11Draft(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        CredentialResponse credentialResponse = vcIssuanceService.getCredential(credentialRequest);
        credentialResponse.setFormat(credentialRequest.getFormat());
        return credentialResponse;
    }
    /**
     * Open endpoint to provide VC issuer's metadata
     * @return
     */
    @GetMapping(value = "/.well-known/openid-credential-issuer",produces = "application/json")
    public Map<String, Object> getMetadata(
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
                log.info("vc version {}", version);
        return vcIssuanceService.getCredentialIssuerMetadata(version);
    }

    @GetMapping(value = "/.well-known/did.json")
    public Map<String, Object> getDIDDocument() {
       return vcIssuanceService.getDIDDocument();
    }


    @ResponseBody
    @ExceptionHandler(InvalidNonceException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public VCError invalidNonceExceptionHandler(InvalidNonceException ex) {
        VCError vcError = new VCError();
        vcError.setError(ex.getErrorCode());
        vcError.setError_description(messageSource.getMessage(ex.getErrorCode(), null, ex.getErrorCode(), Locale.getDefault()));
        vcError.setC_nonce(ex.getClientNonce());
        vcError.setC_nonce_expires_in(ex.getClientNonceExpireSeconds());
        return vcError;
    }
}
