package io.mosip.certify.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

@Slf4j
public class JwtUtils {

    private static final String JWKS_URL = "https://stg-id.singpass.gov.sg/.well-known/keys";
    
    // Don't use static for RestTemplate and don't use @Autowired on a utility class
    private static RestTemplate restTemplate = new RestTemplate();  // Initialize directly

    /**
     * Loads the JWKS from the Singpass endpoint and finds the EC public key
     * matching the JWT's kid.
     *
     * @param signedJWT The parsed JWT.
     * @return The matching ECKey.
     * @throws Exception if no matching key is found or if there is an error loading
     *                   the keys.
     */
    public static ECKey getECKeyForToken(SignedJWT signedJWT) throws Exception {
        String tokenKid = signedJWT.getHeader().getKeyID();
        // Load the JWKS from the endpoint
        JWKSet jwkSet = JWKSet.load(new URL(JWKS_URL));
        List<JWK> keys = jwkSet.getKeys();
        for (JWK key : keys) {
            // Ensure the key is for signature and matches the kid in the token
            if (KeyUse.SIGNATURE.equals(key.getKeyUse()) && tokenKid.equals(key.getKeyID())) {
                if (key instanceof ECKey) {
                    return (ECKey) key;
                } else {
                    throw new Exception("Key with kid " + tokenKid + " is not an EC key.");
                }
            }
        }
        throw new Exception("No matching key found in JWKS for kid: " + tokenKid);
    }

    /**
     * Validates the signature of the provided JWT using the public key from the
     * JWKS.
     *
     * @param token The JWT string.
     * @return The claims set if the token is valid.
     * @throws Exception if the token is invalid.
     */
    public static JWTClaimsSet validateToken(String token) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(token);
        ECKey ecKey = getECKeyForToken(signedJWT);

        // Create a verifier using the EC public key
        JWSVerifier verifier = new ECDSAVerifier(ecKey);
        if (!signedJWT.verify(verifier)) {
            throw new JOSEException("JWT signature verification failed");
        }
        return signedJWT.getJWTClaimsSet();
    }

    // New helper method to fetch user info and extract the "sub" from uinfin.value
    public static String getSubFromUserInfo(String accessToken) {
        log.info("Fetching user info using access token.");
        String userInfoResponse = fetchUserInfoAsString(accessToken);
        try {
            // Private encryption key in JWK format (could be externalized via config)
            String privateEncKeyJson = "{\n" +
                    "  \"alg\": \"ECDH-ES+A256KW\",\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"x\": \"_TSrfW3arG1Ebc8pCyT-r5lAFvCh_rJvC5HD5-y8yvs\",\n" +
                    "  \"y\": \"Sr2vpuU6gzdUiXddGnRJIroXCfdameaR1mgU49H5h9A\",\n" +
                    "  \"crv\": \"P-256\",\n" +
                    "  \"d\": \"AEabUwi3VjOOfiyoOtSGrqpl8cfhcUhNtj-xh1l-UYE\",\n" +
                    "  \"kid\": \"my-enc-key\"\n" +
                    "}";
            ECKey privateEncKey = ECKey.parse(privateEncKeyJson);
            JSONObject decodedUserInfo = decodeUserInfo(userInfoResponse, privateEncKey);
            String subValue = decodedUserInfo.getJSONObject("uinfin").getString("value");
            log.info("Extracted sub value from user info: {}", subValue);
            return subValue;
        } catch (Exception e) {
            log.error("Failed to decode user info or extract sub value.", e);
            throw new RuntimeException("Unable to extract sub value from user info", e);
        }
    }

    public static String fetchUserInfoAsString(String accessToken) {
        log.info("[mimoto] Starting fetchUserInfoAsString");
        String userInfoEndpoint = "https://stg-id.singpass.gov.sg/userinfo"; // Consider externalizing this URL
        log.info("[mimoto] UserInfo Endpoint: {}", userInfoEndpoint);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);

        HttpEntity<String> entity = new HttpEntity<>(headers);
        log.info("[mimoto] Sending GET request to UserInfo endpoint");

        // Use the directly instantiated RestTemplate
        ResponseEntity<String> responseEntity = restTemplate.exchange(
                userInfoEndpoint,
                HttpMethod.GET,
                entity,
                String.class);

        log.info("[mimoto] Received response status: {}", responseEntity.getStatusCode());
        String responseBody = responseEntity.getBody();
        log.info("[mimoto] UserInfo response: {}", responseBody);

        return responseBody;
    }

    public static JSONObject decodeUserInfo(String jweToken, ECKey privateEncKey) throws Exception {
        // Parse the JWE token
        JWEObject jweObject = JWEObject.parse(jweToken);
        log.debug("Parsed JWE Object: {}", jweObject);

        // Decrypt the JWE token using your EC private key
        ECDHDecrypter decrypter = new ECDHDecrypter(privateEncKey.toECPrivateKey());
        jweObject.decrypt(decrypter);
        log.debug("JWE Decryption successful.");

        // The payload of the JWE is a JWS token (as a string)
        String jwsString = jweObject.getPayload().toString();
        log.debug("Extracted JWS Token: {}", jwsString);

        // Parse the inner JWS token
        SignedJWT signedJWT = SignedJWT.parse(jwsString);
        // Optionally, verify the signature here with your public key.

        // Get the payload as a structured Map
        Map<String, Object> claimsMap = signedJWT.getJWTClaimsSet().toJSONObject();
        // Convert the Map to a JSONObject (using org.json.JSONObject)
        JSONObject claims = new JSONObject(claimsMap);
        log.debug("Decoded UserInfo (claims): {}", claims.toString(2));

        return claims;
    }
}