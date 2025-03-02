package io.mosip.certify.proof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialProof;
import io.mosip.certify.core.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;

@Slf4j
@Component
public class JwtProofValidator implements ProofValidator {

    private static final String HEADER_TYP = "openid4vci-proof+jwt";
    private static final String DID_JWK_PREFIX = "did:jwk:";

    @Value("#{${mosip.certify.supported.jwt-proof-alg}}")
    private List<String> supportedAlgorithms;

    @Value("${mosip.certify.identifier}")
    private String credentialIdentifier;

    @Override
    public String getProofType() {
        return "jwt";
    }

    private static final Set<JWSAlgorithm> allowedSignatureAlgorithms;

    private static Set<String> REQUIRED_CLAIMS;

    static {
        allowedSignatureAlgorithms = new HashSet<>();
        allowedSignatureAlgorithms.addAll(List.of(JWSAlgorithm.Family.SIGNATURE.toArray(new JWSAlgorithm[0])));

        REQUIRED_CLAIMS = new HashSet<>();
        REQUIRED_CLAIMS.add("aud");
        REQUIRED_CLAIMS.add("exp");
        REQUIRED_CLAIMS.add("iss");
        REQUIRED_CLAIMS.add("iat");
    }

    @Override
    public boolean validate(String clientId, String cNonce, CredentialProof credentialProof) {
        if(credentialProof.getJwt() == null || credentialProof.getJwt().isBlank()) {
            log.error("Found invalid jwt in the credential proof");
            return false;
        }

        try {
            SignedJWT jwt = (SignedJWT) JWTParser.parse(credentialProof.getJwt());
            validateHeaderClaims(jwt.getHeader());

            JWK jwk = getKeyFromHeader(jwt.getHeader());
            if(jwk.isPrivate()) {
                log.error("Provided key material contains private key! Rejecting proof.");
                throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
            }

            // Get the audience from the server config or extract from request context if needed
            String audience = credentialIdentifier;
            
            // Handle case where audience might be a URL
            if (!audience.startsWith("http")) {
                // If not a URL, try to match with the format in the JWT
                if (jwt.getJWTClaimsSet().getAudience() != null && 
                    !jwt.getJWTClaimsSet().getAudience().isEmpty() &&
                    jwt.getJWTClaimsSet().getAudience().get(0).startsWith("http")) {
                    audience = jwt.getJWTClaimsSet().getAudience().get(0);
                    log.debug("Using audience from JWT: {}", audience);
                }
            }

            DefaultJWTClaimsVerifier claimsSetVerifier = new DefaultJWTClaimsVerifier(
                    new JWTClaimsSet.Builder()
                        .audience(audience)
                        .issuer(clientId)
                        .claim("nonce", cNonce)
                        .build(), 
                    REQUIRED_CLAIMS);
            
            claimsSetVerifier.setMaxClockSkew(60); // Allow 60 seconds of clock skew
            
            // Handle different algorithm types
            if (JWSAlgorithm.ES256K.equals(jwt.getHeader().getAlgorithm())) {
                ECDSAVerifier verifier = new ECDSAVerifier((com.nimbusds.jose.jwk.ECKey) jwk);
                verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                boolean verified = jwt.verify(verifier);
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else if (JWSAlgorithm.Ed25519.equals(jwt.getHeader().getAlgorithm())) {
                Ed25519Verifier verifier = new Ed25519Verifier(jwk.toOctetKeyPair());
                boolean verified = jwt.verify(verifier);
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else if (JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm()) ||
                      JWSAlgorithm.RS384.equals(jwt.getHeader().getAlgorithm()) ||
                      JWSAlgorithm.RS512.equals(jwt.getHeader().getAlgorithm())) {
                RSASSAVerifier verifier = new RSASSAVerifier((RSAKey) jwk);
                boolean verified = jwt.verify(verifier);
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else {
                // General case for other algorithms
                JWSKeySelector keySelector = new JWSVerificationKeySelector(allowedSignatureAlgorithms,
                        new ImmutableJWKSet(new JWKSet(jwk)));
                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(keySelector);
                jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier(new JOSEObjectType(HEADER_TYP)));
                jwtProcessor.setJWTClaimsSetVerifier(claimsSetVerifier);
                jwtProcessor.process(credentialProof.getJwt(), null);
                return true;
            }
        } catch (InvalidRequestException e) {
            log.error("Invalid proof : {}", e.getErrorCode());
        } catch (ParseException e) {
            log.error("Failed to parse jwt in the credential proof", e);
        } catch (BadJOSEException | JOSEException e) {
            log.error("JWT proof verification failed", e);
        }
        return false;
    }

    @Override
    public String getKeyMaterial(CredentialProof credentialProof) {
        try {
            SignedJWT jwt = (SignedJWT) JWTParser.parse(credentialProof.getJwt());
            JWK jwk = getKeyFromHeader(jwt.getHeader());
            byte[] keyBytes = jwk.toJSONString().getBytes(StandardCharsets.UTF_8);
            return DID_JWK_PREFIX.concat(Base64.getUrlEncoder().encodeToString(keyBytes));
        } catch (ParseException e) {
            log.error("Failed to parse jwt in the credential proof", e);
        }
        throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
    }

    public String getKeyMaterialNew(CredentialProof credentialProof) {
        log.info("Starting key material extraction process.");
    
        try {
            
            SignedJWT jwt = (SignedJWT) JWTParser.parse(credentialProof.getJwt());
            log.info("Parsing JWT from credential proof. {}",jwt);


            
            JWK jwk = getKeyFromHeader(jwt.getHeader());
            log.info("Extracting key from JWT header. {}",jwk);
    
            log.info("Converting JWK to byte array.");
            byte[] keyBytes = jwk.toJSONString().getBytes(StandardCharsets.UTF_8);
    
            String encodedKey = Base64.getUrlEncoder().encodeToString(keyBytes);
            log.info("Successfully encoded key material.");
    
            return DID_JWK_PREFIX.concat(encodedKey);
        } catch (ParseException e) {
            log.error("Failed to parse JWT in the credential proof", e);
        }
    
        log.error("Key material extraction failed: Invalid proof header key.");
        throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
    }
    

    private void validateHeaderClaims(JWSHeader jwsHeader) {
        if(Objects.isNull(jwsHeader.getType()) || !HEADER_TYP.equals(jwsHeader.getType().getType())) {
            log.error("Invalid JWT header type: {}", jwsHeader.getType());
            //throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_TYP);
        }

        if(Objects.isNull(jwsHeader.getAlgorithm()) || !supportedAlgorithms.contains(jwsHeader.getAlgorithm().getName())) {
            log.error("Unsupported algorithm: {}", jwsHeader.getAlgorithm());
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_ALG);
        }

        // Check for presence of key material
        if(Objects.isNull(jwsHeader.getJWK()) && Objects.isNull(jwsHeader.getKeyID())) {
            log.error("No key material found in JWT header");
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
        }

        // In openid4vci-proof+jwt, both kid and jwk may be present, but we should prefer jwk
        // So we don't throw the PROOF_HEADER_AMBIGUOUS_KEY error as in the original implementation
    }

    private JWK getKeyFromHeader(JWSHeader jwsHeader) {
        // Prefer embedded JWK if available
        if(Objects.nonNull(jwsHeader.getJWK())) {
            log.debug("Using JWK from header");
            return jwsHeader.getJWK();
        }

        // Fall back to resolving DID
        log.debug("Using kid from header: {}", jwsHeader.getKeyID());
        return resolveDID(jwsHeader.getKeyID());
    }

    /**
     * Currently only handles did:jwk, Need to handle other methods
     * @param did The DID identifier
     * @return Resolved JWK
     */
    private JWK resolveDID(String did) {
        if(did.startsWith(DID_JWK_PREFIX)) {
            try {
                //Ignoring fragment part as did:jwk only contains single key, the DID URL fragment identifier is always
                //a fixed #0 value. If the JWK contains a kid value it is not used as the reference, #0 is the only valid value.
                did = did.split("#")[0];
                byte[] jwkBytes = Base64.getUrlDecoder().decode(did.substring(DID_JWK_PREFIX.length()));
                org.json.JSONObject jsonKey = new org.json.JSONObject(new String(jwkBytes));
                jsonKey.put("kid", did);
                return JWK.parse(jsonKey.toString());
            } catch (IllegalArgumentException e) {
                log.error("Invalid base64 encoded ID : {}", did, e);
            } catch (ParseException | JSONException e) {
                log.error("Invalid jwk : {}", did, e);
            }
        } else {
            log.error("Unsupported DID method: {}", did);
        }
        throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
    }
}