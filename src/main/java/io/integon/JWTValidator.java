package io.integon;

import java.io.IOException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

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

import java.util.Date;
import java.util.HashMap;

public class JWTValidator {
    private static final Log log = LogFactory.getLog(JWTValidator.class);
    

    private JWKSet jwkSet = null;
    private String cachedJwksEndpoint = null;
    private long cachedTimeJWKSet = 0;    
    private JWK jwk = null;
    private long ttl = 60*60*1000; // 1 hour
    private long refreshTimeout = 30*60*1000; // 30 minutes
    private JWSVerifier verifier = null;
    private RSAPublicKey publicKey = null;

    private HashMap<String, Boolean> jtiMap;
    // 8 hour
    private long jtiMapTimeout = 8*60*60*1000;
    private long jtiMapLastCleaned = 0;

    /**
     * @param jwtToken
     * @param jwksEndpoint
     * @param subClaimString
     * @return
     * @throws Exception
     */
    public boolean validateToken (String jwtToken, String jwksEndpoint, HashMap claims) throws Exception {
        SignedJWT signedJWT;
        // Parse the JWT token
        try {
            signedJWT = SignedJWT.parse(jwtToken);
        } catch (ParseException e) {
            throw new Exception("Invalid JWT token");
        }


        loadAndCacheJWKSet(jwksEndpoint);
        getAndVerifyJWKByKid(signedJWT);
        convertJWKToPublicKey(jwk);

        if (verifier == null) {
            verifier = new RSASSAVerifier(publicKey);
        }

        // Create a verifier using the public RSA key
        if (!signedJWT.verify(verifier)) {
            throw new Exception("Failed to validate JWT using the provided JWKS");
        }

        // Check if token is expired
        if (signedJWT.getJWTClaimsSet().getExpirationTime().before(new java.util.Date())) {
            throw new Exception("JWT token is expired");
        }
    
        // Claim validation
        if (claims.get("iat") != null ) {
            Long iatClaimValueLong = Long.parseLong(claims.get("iat").toString())*1000;
            if (signedJWT.getJWTClaimsSet().getIssueTime().before(new Date(System.currentTimeMillis()-iatClaimValueLong))) {
                throw new Exception("JWT token issue time claim is too old");
            }
        }
        if (claims.get("iss") != null) {
            if (!signedJWT.getJWTClaimsSet().getIssuer().equals(claims.get("iss").toString())) {
                throw new Exception("JWT token issuer claim does not match the expected value");
            }
        }
        if (claims.get("sub") != null) {
            if (!signedJWT.getJWTClaimsSet().getSubject().equals(claims.get("sub").toString())) {
                throw new Exception("JWT token subject claim does not match the expected value");
            }
        }
        if (claims.get("aud") != null) {
            if (!signedJWT.getJWTClaimsSet().getAudience().contains(claims.get("aud").toString())) {
                throw new Exception("JWT token audience claim does not match the expected value");
            }
        }
        if (claims.get("jti") == "enabled") {
            if (jtiMap == null || System.currentTimeMillis() - jtiMapLastCleaned > jtiMapTimeout) {
                jtiMap = new HashMap<String, Boolean>();
                jtiMapLastCleaned = System.currentTimeMillis();
            }
            if (jtiMap.containsKey(signedJWT.getJWTClaimsSet().getJWTID())) {
                throw new Exception("JWT with this JWT ID has already been used");
            } else {
                jtiMap.put(signedJWT.getJWTClaimsSet().getJWTID(), true);
            }
        }
        return true;    
    }
    
    /**
     * Resets the cached values for the JWK set and JWK.
     * 
     * This method can be used to clear the cache if the cached values are no longer valid or to refresh the cache with updated values.
     */
    private void clearCache() {
        jwkSet = null;
        jwk = null;
        cachedJwksEndpoint = null;
        publicKey = null;
        cachedTimeJWKSet = 0;
    }

    /**
     * Converts a JWK to a RSA public key
     * 
     * @param jwk the JWK to be converted
     * @return the RSA public key obtained from the conversion
     * @throws Exception if the JWK could not be converted to a RSA public key
     */

    private RSAPublicKey convertJWKToPublicKey(JWK jwk) throws Exception {
        try {
            if (publicKey == null) {
                publicKey = ((RSAKey) jwk).toRSAPublicKey();
            }
            return publicKey;
        } catch (JOSEException e) {
            clearCache();
            throw new Exception("Failed to convert JWK to RSA public key");
        }
    }


    /**
     * This method retrieves the JWK by matching the key id (kid) present in the JWT header. 
     * 
     * @param signedJWT the signed JWT token
     * @return the JWK object that corresponds to the given key id in the JWT header.
     * @throws Exception if the JWT token is invalid or if there is no corresponding JWK found in the JWKS set.
     */
    private JWK getAndVerifyJWKByKid(SignedJWT signedJWT) throws Exception{
        JWSHeader header = signedJWT.getHeader();
        String kid = header.getKeyID();
        if (header == null || kid == null) {
            throw new Exception("Invalid JWT token");
        }
        // Get the JWK with the matching "kid"
        if (jwk == null) {
            jwk = jwkSet.getKeyByKeyId(kid);
            if (jwk == null) {
                throw new Exception("Failed to validate JWT using the provided JWKS");
            }
        }
        return jwk;
    }


    /**
     * Loads and caches the JwkSet from the provided JWKS endpoint.
     * 
     * If the JwkSet is null or if the time since the JwkSet was last cached
     * plus the time-to-live (ttl) is less than the current time or if the
     * cached JWKS endpoint is not equal to the provided JWKS endpoint, the JWK
     * set is loaded from the endpoint.
     * 
     * If the time since the JWKSet was last cached plus the refresh timeout is
     * less than the current time, the JwkSet is reloaded from the endpoint.
     * 
     * If there is a parse exception while loading the JwkSet, an exception is
     * thrown indicating that the JWKS could not be loaded from the provided endpoint.
     * 
     * @param jwksEndpoint The JWKS endpoint to retrieve the JwkSet from.
     * @throws Exception If there is a parse exception while loading the JwkSet.
     */
    private void loadAndCacheJWKSet(String jwksEndpoint) throws Exception {
       
        if (jwkSet == null || cachedTimeJWKSet + ttl < System.currentTimeMillis() || !cachedJwksEndpoint.equals(jwksEndpoint)) {
            try {
                clearCache();
                jwkSet = JWKSet.load(new URL(jwksEndpoint));
                cachedTimeJWKSet = System.currentTimeMillis();
                cachedJwksEndpoint = jwksEndpoint;
            } catch (ParseException | IOException e) {
                throw new Exception("Failed to load JWKS from the provided endpoint");
            }
        } else if (cachedTimeJWKSet + refreshTimeout < System.currentTimeMillis()) {
            try {
                jwkSet = JWKSet.load(new URL(jwksEndpoint));
                cachedTimeJWKSet = System.currentTimeMillis();
                cachedJwksEndpoint = jwksEndpoint;
            } catch (Exception ignored) {}
            // Ignore any exceptions while refreshing the cache
        }
    }



    /**
     * Set the cache timeouts for the JWK set.
     * 
     * @param jwksTimeout the time to live for the cached JWK set
     * @param jwksRefreshTime the refresh time for the cached JWK set
     */
    public void setCacheTimeouts(String jwksTimeout, String jwksRefreshTime) {
        if (!jwksTimeout.isEmpty()) {
            ttl = Long.parseLong(jwksTimeout)*1000;
        }
        if (!jwksTimeout.isEmpty()) {
            refreshTimeout = Long.parseLong(jwksRefreshTime)*1000;
        }
    }

}