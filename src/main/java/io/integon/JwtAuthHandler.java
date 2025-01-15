package io.integon;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;

import java.net.URL;
import java.net.MalformedURLException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.Handler;
import org.json.JSONObject;

/**
 * This class is used to validate the JWT token Implements the Handler interface
 * from the Synapse REST API to be used in a Micro Integrator API
 */
public class JwtAuthHandler implements Handler {
    private static final Log log = LogFactory.getLog(JwtAuthHandler.class);

    private String jwtHeader;
    private String jwksEndpoint;
    private String jwksEnvVariable;
    private String iatClaim;
    private String issClaim;
    private String issEnvVariable;
    private String subClaim;
    private String audClaim;
    private String audEnvVariable;
    private String jtiClaim;
    private String jwksTimeout;
    private String jwksRefreshTime;

    private String claimName;

    private String claimValueEnvVariable;
    private String claimValue;

    private long cachedTimeValidator = 0;
    protected final long CACHED_TIME_VALIDATOR_RESET = 86400000; // 24 hours

    private JWTValidator validator = null;

    private String forwardToken;

    @Override
    public void addProperty(String s, Object o) {
        // To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public Map getProperties() {
        return null; // To change body of implemented methods use File | Settings | File Templates.
    }

    /**
     * This method is called when the request is received Initialize the
     * JWTValidator and retrieve the JWT token from the transport headers Check if
     * the JWT token is expired Validate the JWT token and check if the claims are
     * valid
     * 
     * @param messageContext
     *                       Synapse message context
     * @return true if the request is valid, false if the request is invalid
     */
    @Override
    public boolean handleRequest(MessageContext messageContext) {
        // initialize the JWTValidator
        if (validator == null || cachedTimeValidator + CACHED_TIME_VALIDATOR_RESET < System.currentTimeMillis()) {
            validator = new JWTValidator();
            cachedTimeValidator = System.currentTimeMillis();
            log.debug("JWTValidator initialized: " + validator);
        }

        // Get Transport Headers from the message context
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        // retrieve the JWT token from transport headers
        String authHeader = null;
        if (headers instanceof Map) {
            Map headersMap = (Map) headers;
            authHeader = (String) headersMap.get(jwtHeader);
        }

        // Check if the token is null or empty
        if (authHeader == null || authHeader.isEmpty()) {
            log.debug("JWT token not found in the message");
            handleException("JWT token not found in the message", messageContext);
            return false;
        }
        // Check if the token starts with "Bearer "
        if (!authHeader.trim().startsWith("Bearer")) {
            log.debug("Invalid JWT token format: " + authHeader);
            handleException("Invalid JWT token format", messageContext);
            return false;
        }
        // Remove "Bearer " from the token
        String jwtToken = authHeader.substring(7).trim();
        if (jwtToken.isEmpty()) {
            log.debug("JWT token not found in the message");
            handleException("JWT token not found in the message", messageContext);
            return false;
        }

        // If jwksEnvVariable is set, check if the environment variable contains a valid
        // URL
        jwksEndpoint = CommonUtils.getDefaultValueOrValueFromEnv("jwksEndpoint", jwksEndpoint, jwksEnvVariable);
        if (jwksEndpoint == null || jwksEndpoint.isEmpty()) {
            handleException("JWKS endpoint not found in the message", messageContext);
            return false;
        }

        ArrayList<URL> jwksUrls = new ArrayList<>();

        String[] jwksUrlsSplit = jwksEndpoint.split(",");
        for (String jkwsUrlString : jwksUrlsSplit) {
            try {
                // Trim any spaces and attempt to create a URL
                URL url = new URL(jkwsUrlString.trim());
                // If successful, add the valid URL to the list
                jwksUrls.add(url);
                log.debug("Added valid URL: " + url);
            } catch (MalformedURLException e) {
                log.error("JWKS URL invalid: " + jkwsUrlString.trim());
                handleException("JWKS URL invalid: " + jkwsUrlString.trim(), messageContext);
                return false;
            }
        }
        // Set the cache timeouts
        validator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);

        // validate the JWT token
        boolean isValidJWT;
        try {
            isValidJWT = validator.validateToken(jwtToken, jwksUrls);
            log.debug("isValidJWT: " + isValidJWT);
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
            return false;
        }
        // Check if the token is expired
        boolean isTokenExpired;
        try {
            isTokenExpired = validator.isTokenExpired(jwtToken);
            if (isTokenExpired) {
                handleException("JWT token is expired", messageContext);
                return false;
            }
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
            return false;
        }
        // Check if the claims are valid
        HashMap<String, String> claims = new HashMap<String, String>();
        claims.put("iat", CommonUtils.getDefaultValueOrValueFromEnv("iat", iatClaim, null));
        claims.put("iss", CommonUtils.getDefaultValueOrValueFromEnv("iss", issClaim, issEnvVariable));
        claims.put("sub", CommonUtils.getDefaultValueOrValueFromEnv("sub", subClaim, null));
        claims.put("aud", CommonUtils.getDefaultValueOrValueFromEnv("aud", audClaim, audEnvVariable));
        claims.put("jti", CommonUtils.getDefaultValueOrValueFromEnv("jti", jtiClaim, null));
        claims.put("genericClaimName", CommonUtils.getDefaultValueOrValueFromEnv("genericClaimName", claimName, null));
        claims.put("genericClaimValue", CommonUtils.getDefaultValueOrValueFromEnv("genericClaimValue", claimValue, claimValueEnvVariable));
        // check if all values are null
        boolean allValuesAreNull = true;
        for (String value : claims.values()) {
            if (value != null) {
                allValuesAreNull = false;
                break;
            }
        }
        if (!allValuesAreNull) {
            try {
                validator.areClaimsValid(jwtToken, claims);
            } catch (Exception e) {
                handleException(e.getMessage(), messageContext);
                return false;
            }
        }

        if (forwardToken != null && forwardToken.equals("true")) {
            log.debug("Set JWT token in the message context");
            // Decode the JWT payload and add it to the transport headers
            String decodedToken = new String(Base64.getDecoder().decode(jwtToken.split("\\.")[1]));

            JSONObject jsonObject = new JSONObject(decodedToken);

            messageContext.setProperty("X-JWT", jsonObject.toString());
        }
        return true;
    }

    /**
     * This method is called when the response is sent back to the client
     * 
     * @param messageContext
     *                       Synapse message context
     * @return true if the response is valid, false if the response is invalid
     */
    @Override
    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

    /**
     * This method handles the exceptions thrown by the JWTValidator
     * 
     * @param message
     *                       the error message
     * @param messageContext
     *                       Synapse message context
     */
    protected void handleException(String message, MessageContext messageContext) {
        // Create a SOAPFactory and an XML payload
        CommonUtils.setJsonEnvelopMessageContext(messageContext, message);

        // Get Transport Headers from the message context
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        // Clear the transport headers
        Map headersMap = (Map) headers;
        headersMap.clear();

        // Set the response status code
        axis2MessageContext.setProperty("HTTP_SC", HttpStatus.SC_UNAUTHORIZED);

        // Set the "NO_ENTITY_BODY" property to false -- this is required to send a
        // response
        axis2MessageContext.setProperty("NO_ENTITY_BODY", Boolean.FALSE);

        // Set the response to true
        messageContext.setProperty("RESPONSE", "true");

        // Set the response content type
        axis2MessageContext.setProperty("messageType", "application/json");
        axis2MessageContext.setProperty("ContentType", "application/json");

        // Set the "to" property to null
        messageContext.setTo(null);

        Axis2Sender.sendBack(messageContext);
    }

    // Interface handler injection
    public String getJwksEndpoint() {
        return jwksEndpoint;
    }

    // Interface handler injection
    public void setJwksEndpoint(String jwks) {
        this.jwksEndpoint = jwks;
    }

    // Interface handler injection
    public String getJwksEnvVariable() {
        return jwksEnvVariable;
    }

    // Interface handler injection
    public void setJwksEnvVariable(String jwksEnv) {
        jwksEnvVariable = jwksEnv;
    }

    // Interface handler injection
    public String getJwtHeader() {
        return jwtHeader;
    }

    // Interface handler injection
    public void setJwtHeader(String header) {
        this.jwtHeader = header;
    }

    // Interface handler injection
    public String getIatClaim() {
        return iatClaim;
    }

    // Interface handler injection
    public void setIatClaim(String iat) {
        iatClaim = iat;
    }

    // Interface handler injection
    public String getIssClaim() {
        return issClaim;
    }

    // Interface handler injection
    public void setIssClaim(String iss) {
        issClaim = iss;
    }

    // Interface handler injection
    public String getAudEnvVariable() {
        return audEnvVariable;
    }

    // Interface handler injection
    public void setAudEnvVariable(String audEnvVariable) {
        this.audEnvVariable = audEnvVariable;
    }
    // Interface handler injection
    public String getAudClaim() {
        return audClaim;
    }

    // Interface handler injection
    public void setAudClaim(String aud) {
        audClaim = aud;
    }

    // Interface handler injection
    public String getSubClaim() {
        return subClaim;
    }

    // Interface handler injection
    public void setSubClaim(String sub) {
        this.subClaim = sub;
    }

    // Interface handler injection
    public String getJtiClaim() {
        return jtiClaim;
    }

    // Interface handler injection
    public void setJtiClaim(String jti) {
        jtiClaim = jti;
    }

    // Interface handler injection
    public String getJwksTimeout() {
        return jwksTimeout;
    }

    // Interface handler injection
    public void setJwksTimeout(String timeout) {
        this.jwksTimeout = timeout;
    }

    // Interface handler injection
    public String getJwksRefreshTime() {
        return jwksRefreshTime;
    }

    // Interface handler injection
    public void setJwksRefreshTime(String refresh) {
        this.jwksRefreshTime = refresh;
    }

    public void setForwardToken(String forwardToken) {
        this.forwardToken = forwardToken;
    }

    // Interface handler injection
    public String getClaimName() {
        return claimName;
    }

    // Interface handler injection
    public void setClaimName(String claimName) {
        this.claimName = claimName;
    }

    // Interface handler injection
    public String getClaimValue() {
        return claimValue;
    }

    // Interface handler injection
    public void setClaimValue(String claimValue) {
        this.claimValue = claimValue;
    }

    public String getIssEnvVariable() {
        return issEnvVariable;
    }

    public void setIssEnvVariable(String issEnvVariable) {
        this.issEnvVariable = issEnvVariable;
    }

    public String getClaimValueEnvVariable() {
        return claimValueEnvVariable;
    }

    public void setClaimValueEnvVariable(String claimValueEnvVariable) {
        this.claimValueEnvVariable = claimValueEnvVariable;
    }
}
