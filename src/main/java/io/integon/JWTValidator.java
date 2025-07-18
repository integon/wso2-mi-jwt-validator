package io.integon;

import java.io.IOException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

/**
 * This class validates the JWT token using the provided JWKS endpoint
 */
public class JWTValidator {
    private static final Log log = LogFactory.getLog(JWTValidator.class);

    private ArrayList<JWKSet> allKeySets = new ArrayList<>();

    private long cachedTimeJWKSet = 0;
    private JWK jwk = null;
    private long ttl = 60 * 60 * 1000; // 1 hour
    private long refreshTimeout = 30 * 60 * 1000; // 30 minutes
    private RSAPublicKey publicKey = null;

    private static final Set<String> STANDARD_CLAIMS = Set.of("iat", "iss", "sub", "aud", "jti");


    private HashMap<String, Boolean> jtiMap;
    // 8 hour
    private long jtiMapTimeout = 8 * 60 * 60 * 1000;
    private long jtiMapLastCleaned = 0;

    /**
     * Validates the JWT token using the provided JWKS endpoint The JWKS endpoint is
     * cached after the first call The kid is extracted from the JWT token and used
     * to get the JWK from the JWKS The JWK is converted to a public key The JWT
     * token is validated using the public key
     * 
     * @param jwtToken
     *                 The JWT token to validate
     * @param jwksUrls
     *                 The JWKS endpoint to use for validation
     * @return true if the JWT token is valid
     * @throws Exception If any error occurs during token validation.
     */
    public SignedJWT validateToken(String jwtToken, ArrayList<URL> jwksUrls) throws Exception {
        SignedJWT parsedJWT;
        // Parse the JWT token
        try {
            parsedJWT = SignedJWT.parse(jwtToken);
            log.debug("JWT token parsed successfully");
        } catch (ParseException e) {
            log.error("Failed to parse JWT token: " + e.getMessage());
            throw new Exception("Invalid JWT token");
        }
        loadAndCacheJWKSet(jwksUrls);
        getAndVerifyJWKByKid(parsedJWT);
        convertJWKToPublicKey(jwk);

        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        log.debug("Verifier created successfully");

        // Create a verifier using the public RSA key
        if (!parsedJWT.verify(verifier)) {
            log.debug("Failed to validate JWT using the provided JWKS");
            throw new Exception("Failed to validate JWT using the provided JWKS");
        }
        log.debug("JWT token validated successfully");
        return parsedJWT;
    }

    /**
     * Checks if the JWT token is expired This method only gets called if the JWT
     * token is valid
     * 
     * @param parsedJWT
     *                 The JWT token to check
     * @return true if the JWT token is expired
     * @throws Exception If any error occurs during token validation.
     */
    public boolean isTokenExpired(SignedJWT parsedJWT) throws Exception {
        // Check if token is expired
        if (parsedJWT.getJWTClaimsSet().getExpirationTime().before(new java.util.Date())) {
            log.debug("JWT token is expired");
            return true;
        }
        log.debug("JWT token is not expired");
        return false;
    }

    /**
     * Checks if the claims in the JWT token are valid or have the expected values
     * This method only gets called if the JWT token is valid and not expired and
     * there are claims to validate
     * 
     * @param parsedJWT
     *                 The parsed JWT token to check
     * @param claims
     *                 The claims to validate
     * @return true if the claims are valid
     * @throws Exception If any error occurs during token validation.
     */
    public boolean areClaimsValid(SignedJWT parsedJWT, HashMap<String, String> claims) throws Exception {
        // Claim validation
        if (claims.get("iat") != null) {
            // Todo: Get long or null --> Try and Catch with ignore Exception with info log
            if (isLongParseable(claims.get("iat").toString())) {
                Long iatClaimValueLong = Long.parseLong(claims.get("iat").toString()) * 1000;
                if (parsedJWT.getJWTClaimsSet().getIssueTime()
                        .before(new Date(System.currentTimeMillis() - iatClaimValueLong))) {
                    log.debug("JWT token issue time claim is too old");
                    throw new Exception("JWT token issue time claim is too old");
                }
            } else {
                log.debug("JWT token issue time claim is not a valid long value, this claim will be ignored");
            }
            log.debug("JWT token issue time claim is not too old");
        }

        if (claims.get("iss") != null) {
            if (!parsedJWT.getJWTClaimsSet().getIssuer().matches(claims.get("iss").toString())) {
                log.debug("JWT token issuer claim does not match the expected value: " + claims.get("iss").toString());
                throw new Exception("JWT token issuer claim does not match the expected value");
            }
            log.debug("JWT token issuer claim matches the expected value");
        }
        if (claims.get("sub") != null) {
            if (!parsedJWT.getJWTClaimsSet().getSubject().matches(claims.get("sub").toString())) {
                log.debug("JWT token subject claim does not match the expected value: " + claims.get("sub").toString());
                throw new Exception("JWT token subject claim does not match the expected value");
            }
            log.debug("JWT token subject claim matches the expected value");
        }
        if (claims.get("aud") != null) {
            boolean audMatch = false;
            for (String audience : parsedJWT.getJWTClaimsSet().getAudience()) {
                if (audience.matches(claims.get("aud").toString())) {
                    audMatch = true;
                }

            }
            if (!audMatch) {
                log.debug(
                        "JWT token audience claim does not match the expected value: " + claims.get("aud").toString());
                throw new Exception("JWT token audience claim does not match the expected value");
            }
            log.debug("JWT token audience claim matches the expected value");
        }
        if (claims.get("jti") == "enabled") {
            if (jtiMap == null || System.currentTimeMillis() - jtiMapLastCleaned > jtiMapTimeout) {
                jtiMap = new HashMap<String, Boolean>();
                jtiMapLastCleaned = System.currentTimeMillis();
                log.debug("Created a new JTI map");
            }
            if (jtiMap.containsKey(parsedJWT.getJWTClaimsSet().getJWTID())) {
                log.debug("JWT with this JWT ID has already been used: " + parsedJWT.getJWTClaimsSet().getJWTID());
                throw new Exception("JWT with this JWT ID has already been used");
            } else {
                jtiMap.put(parsedJWT.getJWTClaimsSet().getJWTID(), true);
                log.debug("Added JWT ID to the JTI map");
            }
            log.debug("JWT token JTI claim is valid");
        }

        // Dynamic custom claims validation
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            String claimKey = entry.getKey();
            String expectedPattern = entry.getValue();

            if (STANDARD_CLAIMS.contains(claimKey)) {
                continue; // Skip standard claims, already validated
            }

            Object actualValueObj = parsedJWT.getJWTClaimsSet().getClaim(claimKey);
            if (actualValueObj == null) {
                log.debug("JWT does not contain expected custom claim: " + claimKey);
                throw new Exception("Missing expected custom claim: " + claimKey);
            }

            String actualValue = actualValueObj.toString();
            if (!actualValue.matches(expectedPattern)) {
                log.debug("JWT claim '" + claimKey + "' value '" + actualValue + "' does not match pattern: " + expectedPattern);
                throw new Exception("JWT custom claim '" + claimKey + "' did not match expected pattern");
            }

            log.debug("JWT custom claim '" + claimKey + "' matches expected pattern");
        }

        log.debug("JWT token claims are valid");
        return true;
    }

    /**
     * Resets the cached values for the JWK set and JWK. This method can be used to
     * clear the cache if the cached values are no longer valid or to refresh the
     * cache with updated values.
     */
    private void clearCache() {
        allKeySets.clear();
        jwk = null;
        publicKey = null;
        cachedTimeJWKSet = 0;
        log.debug("Cleared the cached values");
    }

    /**
     * Converts a JWK to a RSA public key Conversion to a RSA public key is done
     * only once and the result is cached for future use The RSA public key is used
     * to verify the signature of the JWT token
     * 
     * @param jwk
     *            the JWK to be converted
     * @throws Exception
     *                   if the JWK could not be converted to a RSA public key
     */

    private void convertJWKToPublicKey(JWK jwk) throws Exception {
        try {
            publicKey = ((RSAKey) jwk).toRSAPublicKey();
            log.debug("Converted JWK to RSA public key");
        } catch (JOSEException e) {
            clearCache();
            log.error("Failed to convert JWK to RSA public key: " + e.getMessage());
            throw new Exception("Failed to convert JWK to RSA public key");
        }
    }

    /**
     * This method retrieves the JWK by matching the key id (kid) present in the JWT
     * header.
     * 
     * @param parsedJWT
     *                  the signed JWT token
     * @return the JWK object that corresponds to the given key id in the JWT
     *         header.
     * @throws Exception
     *                   if the JWT token is invalid or if there is no corresponding
     *                   JWK
     *                   found in the JWKS set.
     */
    private void getAndVerifyJWKByKid(SignedJWT parsedJWT) throws Exception {
        JWSHeader header = parsedJWT.getHeader();
        String kid = header.getKeyID();
        if (header == null || kid == null) {
            log.debug("Invalid JWT token: JWT header or key id is null");
            throw new Exception("Invalid JWT token");
        }
        for (JWKSet keySet : allKeySets) {
            jwk = keySet.getKeyByKeyId(kid);
            if (jwk != null) {
                break; // Stop once a matching key is found
            }
        }

        if (jwk == null) {
            log.debug(kid + " not found in allKeySets");
            throw new Exception("Failed to validate JWT using the provided JWKS");
        }
    }

    /**
     * Loads and caches the JwkSet from the provided JWKS endpoint.
     * 
     * If the JwkSet is null or if the time since the JwkSet was last cached plus
     * the time-to-live (ttl) is less than the current time or if the cached JWKS
     * endpoint is not equal to the provided JWKS endpoint, the JWK set is loaded
     * from the endpoint.
     * 
     * If the time since the JWKSet was last cached plus the refresh timeout is less
     * than the current time, the JwkSet is reloaded from the endpoint.
     * 
     * If there is a parse exception while loading the JwkSet, an exception is
     * thrown indicating that the JWKS could not be loaded from the provided
     * endpoint.
     * 
     * @param jwksEndpoint
     *                     The JWKS endpoint to retrieve the JwkSet from.
     * @throws Exception
     *                   If there is a parse exception while loading the JwkSet.
     */
    private synchronized void loadAndCacheJWKSet(ArrayList<URL> jwksUrls) throws Exception {
        if (allKeySets.isEmpty() || cachedTimeJWKSet + ttl < System.currentTimeMillis()) {
            clearCache();
            for (URL jwksUrl : jwksUrls) {
                try {
                    JWKSet keySet = JWKSet.load(jwksUrl);
                    allKeySets.add(keySet);
                    log.debug("JWK set loaded from the provided endpoint: " + jwksUrl);
                } catch (IOException e) {
                    log.error("Unable to load JWK set from the provided endpoint: " + jwksUrl);
                    throw new Exception("Failed to load JWKs: " + jwksUrl);
                }
            }
            cachedTimeJWKSet = System.currentTimeMillis();
        } else if (cachedTimeJWKSet + refreshTimeout < System.currentTimeMillis()) {
            for (URL jwksUrl : jwksUrls) {
                try {
                    JWKSet keySet = JWKSet.load(jwksUrl);
                    allKeySets.add(keySet);
                    log.debug("JWK set loaded from the provided endpoint: " + jwksUrl);
                } catch (IOException e) {
                    log.error("Unable to load JWK set from the provided endpoint: " + jwksUrl);
                    throw new Exception("Failed to load JWKs: " + jwksUrl);
                }
            }
            cachedTimeJWKSet = System.currentTimeMillis();
        }
    }

    /**
     * Set the cache timeouts for the JWK set.
     * 
     * @param jwksTimeout
     *                        the time to live for the cached JWK set
     * @param jwksRefreshTime
     *                        the refresh time for the cached JWK set
     */
    public void setCacheTimeouts(String jwksTimeout, String jwksRefreshTime) {
        if (isLongParseable(jwksTimeout)) {
            ttl = Long.parseLong(jwksTimeout) * 1000;
            log.debug("Set the JWK timeout to " + jwksTimeout + " seconds");
        } else {
            log.debug(jwksTimeout + " is not a valid value for the JWK timeout. Defaulting to 1 hour.");
        }

        if (isLongParseable(jwksRefreshTime)) {
            refreshTimeout = Long.parseLong(jwksRefreshTime) * 1000;
            log.debug("Set the JWK refresh timeout to " + jwksRefreshTime + " seconds");
        } else {
            log.debug(jwksRefreshTime + " is not a valid value for the JWK refresh timeout. Defaulting to 30 minutes.");
        }
    }

    /**
     * Checks if the given string is parseable as a long.
     * 
     * @param s
     *          the string to be checked
     * @return true if the string is parseable as a long, false otherwise
     */
    private boolean isLongParseable(String s) {
        try {
            Long.parseLong(s);
            log.debug(s + " is a valid long value");
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public long getTtl() {
        return ttl;
    }
    
    public long getRefreshTimeout() {
        return refreshTimeout;
    }
}
