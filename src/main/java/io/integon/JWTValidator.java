package io.integon;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
/**
 * This class validates the JWT token using the provided JWKS endpoint
 */
public class JWTValidator {
    private static final Log log = LogFactory.getLog(JWTValidator.class);

    private JWKSet jwkSet = null;
    private String cachedJwksEndpoint = null;
    private long cachedTimeJWKSet = 0;
    private JWK jwk = null;
    private long ttl = 60 * 60 * 1000; // 1 hour
    private long refreshTimeout = 30 * 60 * 1000; // 30 minutes
    private RSAPublicKey publicKey = null;

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
     *            The JWT token to validate
     * @param jwksEndpoint
     *            The JWKS endpoint to use for validation
     * @return true if the JWT token is valid
     * @throws Exception
     */
    public boolean validateToken(String jwtToken, String jwksEndpoint) throws Exception {
        SignedJWT signedJWT;
        // Parse the JWT token
        try {
            signedJWT = SignedJWT.parse(jwtToken);
            log.debug("JWT token parsed successfully");
        } catch (ParseException e) {
            log.error("Failed to parse JWT token: " + e.getMessage());
            throw new Exception("Invalid JWT token");
        }

        loadAndCacheJWKSet(jwksEndpoint);
        getAndVerifyJWKByKid(signedJWT);
        convertJWKToPublicKey(jwk);

        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        log.debug("Verifier created successfully");

        // Create a verifier using the public RSA key
        if (!signedJWT.verify(verifier)) {
            log.debug("Failed to validate JWT using the provided JWKS");
            throw new Exception("Failed to validate JWT using the provided JWKS");
        }
        log.debug("JWT token validated successfully");
        return true;
    }

    /**
     * Checks if the JWT token is expired This method only gets called if the JWT
     * token is valid
     * 
     * @param jwtToken
     *            The JWT token to check
     * @return true if the JWT token is expired
     * @throws Exception
     */
    public boolean isTokenExpired(String jwtToken) throws Exception {
        SignedJWT signedJWT;
        // Parse the JWT token
        try {
            signedJWT = SignedJWT.parse(jwtToken);
        } catch (ParseException e) {
            log.error("Failed to parse JWT token: " + e.getMessage());
            throw new Exception("Invalid JWT token");
        }

        // Check if token is expired
        if (signedJWT.getJWTClaimsSet().getExpirationTime().before(new java.util.Date())) {
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
     * @param jwtToken
     *            The JWT token to check
     * @param claims
     *            The claims to validate
     * @return true if the claims are valid
     * @throws Exception
     */
    public boolean areClaimsValid(String jwtToken, HashMap<String, String> claims) throws Exception {
        SignedJWT signedJWT;
        // Parse the JWT token
        try {
            signedJWT = SignedJWT.parse(jwtToken);
        } catch (ParseException e) {
            log.error("Failed to parse JWT token: " + e.getMessage());
            throw new Exception("Invalid JWT token");
        }

        // Claim validation
        if (claims.get("iat") != null) {
            // Todo: Get long or null --> Try and Catch with ignore Exception with info log
            if (isLongParseable(claims.get("iat").toString())) {
                Long iatClaimValueLong = Long.parseLong(claims.get("iat").toString()) * 1000;
                if (signedJWT.getJWTClaimsSet().getIssueTime()
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
            if (!signedJWT.getJWTClaimsSet().getIssuer().equals(claims.get("iss").toString())) {
                log.debug("JWT token issuer claim does not match the expected value: " + claims.get("iss").toString());
                throw new Exception("JWT token issuer claim does not match the expected value");
            }
            log.debug("JWT token issuer claim matches the expected value");
        }
        if (claims.get("sub") != null) {
            if (!signedJWT.getJWTClaimsSet().getSubject().equals(claims.get("sub").toString())) {
                log.debug("JWT token subject claim does not match the expected value: " + claims.get("sub").toString());
                throw new Exception("JWT token subject claim does not match the expected value");
            }
            log.debug("JWT token subject claim matches the expected value");
        }
        if (claims.get("aud") != null) {
            if (!signedJWT.getJWTClaimsSet().getAudience().contains(claims.get("aud").toString())) {
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
            if (jtiMap.containsKey(signedJWT.getJWTClaimsSet().getJWTID())) {
                log.debug("JWT with this JWT ID has already been used: " + signedJWT.getJWTClaimsSet().getJWTID());
                throw new Exception("JWT with this JWT ID has already been used");
            } else {
                jtiMap.put(signedJWT.getJWTClaimsSet().getJWTID(), true);
                log.debug("Added JWT ID to the JTI map");
            }
            log.debug("JWT token JTI claim is valid");
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
        jwkSet = null;
        jwk = null;
        cachedJwksEndpoint = null;
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
     *             if the JWK could not be converted to a RSA public key
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
     * @param signedJWT
     *            the signed JWT token
     * @return the JWK object that corresponds to the given key id in the JWT
     *         header.
     * @throws Exception
     *             if the JWT token is invalid or if there is no corresponding JWK
     *             found in the JWKS set.
     */
    private void getAndVerifyJWKByKid(SignedJWT signedJWT) throws Exception {
        JWSHeader header = signedJWT.getHeader();
        String kid = header.getKeyID();
        if (header == null || kid == null) {
            log.debug("Invalid JWT token: JWT header or key id is null");
            throw new Exception("Invalid JWT token");
        }
        // Get the JWK with the matching "kid"
        jwk = jwkSet.getKeyByKeyId(kid);
        if (jwk == null) {
            log.debug(kid + " not found in JWKS Endpoint: " + cachedJwksEndpoint);
            throw new Exception("Failed to validate JWT using the provided JWKS");
        }
        log.debug(kid + " found in JWKS Endpoint: " + cachedJwksEndpoint);
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
     *            The JWKS endpoint to retrieve the JwkSet from.
     * @throws Exception
     *             If there is a parse exception while loading the JwkSet.
     */
    private void loadAndCacheJWKSet(String jwksEndpoint) throws Exception {

        if (jwkSet == null || cachedTimeJWKSet + ttl < System.currentTimeMillis()
                || !cachedJwksEndpoint.equals(jwksEndpoint)) {
            try {
                clearCache();
                jwkSet = JWKSet.load(new URL(jwksEndpoint));
                log.debug("JWK set loaded from the provided endpoint: " + jwksEndpoint);
                cachedTimeJWKSet = System.currentTimeMillis();
                cachedJwksEndpoint = jwksEndpoint;
            } catch (ParseException | IOException e) {
                log.error("Failed to load JWKS from the provided endpoint: " + jwksEndpoint + " because "
                        + e.getMessage());
                throw new Exception("Failed to load JWKS from the provided endpoint");
            }
        } else if (cachedTimeJWKSet + refreshTimeout < System.currentTimeMillis()) {
            try {
                jwkSet = JWKSet.load(new URL(jwksEndpoint));
                log.debug("JWK set loaded from the provided endpoint (refresh): " + jwksEndpoint);
                cachedTimeJWKSet = System.currentTimeMillis();
                cachedJwksEndpoint = jwksEndpoint;
            } catch (Exception ignored) {
            }
            // Ignore any exceptions while refreshing the cache
        }
    }

    /**
     * Set the cache timeouts for the JWK set.
     * 
     * @param jwksTimeout
     *            the time to live for the cached JWK set
     * @param jwksRefreshTime
     *            the refresh time for the cached JWK set
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
     *            the string to be checked
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
}