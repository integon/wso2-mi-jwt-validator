package io.integon;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
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
    private static final Log log = LogFactory.getLog(JwtAuthMediator.class);

    private String jwtHeader;
    private String jwksEndpoint;
    private String jwksEnvVariable;
    private String iatClaim;
    private String issClaim;
    private String subClaim;
    private String audClaim;
    private String jtiClaim;
    private String jwksTimeout;
    private String jwksRefreshTime;

    private long cachedTimeValidator = 0;
    private long cachedTimeValidatorReset = 86400000; // 24 hours

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
        if (validator == null || cachedTimeValidator + cachedTimeValidatorReset < System.currentTimeMillis()) {
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
        if (headers != null && headers instanceof Map) {
            Map headersMap = (Map) headers;
            authHeader = (String) headersMap.get(jwtHeader);
        }

        // Check if the token is null or empty
        if (authHeader == null || authHeader.isEmpty()) {
            log.debug("JWT token not found in the message");
            handleException("JWT token not found in the message", messageContext);
            return false;
        }
        log.debug(jwtHeader + ": has the following value: " + authHeader);
        // Check if the token starts with "Bearer "
        if (!authHeader.trim().startsWith("Bearer")) {
            log.debug("Invalid JWT token format: " + authHeader);
            handleException("Invalid JWT token format", messageContext);
            return false;
        }
        // Remove "Bearer " from the token
        String jwtToken = authHeader.substring(7);
        if (jwtToken == null || jwtToken.isEmpty()) {
            log.debug("JWT token not found in the message");
            handleException("JWT token not found in the message", messageContext);
            return false;
        }
        // If jwksEnvVariable is set, check if the environment variable contains a valid
        // URL
        if (jwksEnvVariable != null && System.getenv().get(jwksEnvVariable) != null
                && CommonUtils.containsUrl(System.getenv().get(jwksEnvVariable))) {
            jwksEndpoint = System.getenv().get(jwksEnvVariable);
        } else {
            // Check if the JWKS endpoint
            if (jwksEndpoint == null || jwksEndpoint.isEmpty()) {
                handleException("JWKS endpoint not found", messageContext);
                return false;
            }
        }
        // Set the cache timeouts
        validator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);

        // validate the JWT token
        boolean isValidJWT;
        try {
            isValidJWT = validator.validateToken(jwtToken, jwksEndpoint);
            log.debug("isValidJWT: " + isValidJWT);
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
        }
        // Check if the token is expired
        boolean isTokenExpired;
        try {
            isTokenExpired = validator.isTokenExpired(jwtToken);
            if (isTokenExpired) {
                handleException("JWT token is expired", messageContext);
            }
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
        }
        // Check if the claims are valid
        HashMap<String, String> claims = new HashMap<String, String>();
        if (iatClaim != null && iatClaim.isEmpty()) {
            iatClaim = null;
        }
        claims.put("iat", iatClaim);
        if (issClaim != null && issClaim.isEmpty()) {
            issClaim = null;
        }
        claims.put("iss", issClaim);
        if (subClaim != null && subClaim.isEmpty()) {
            subClaim = null;
        }
        claims.put("sub", subClaim);
        if (audClaim != null && audClaim.isEmpty()) {
            audClaim = null;
        }
        claims.put("aud", audClaim);
        if (jtiClaim != null && jtiClaim.isEmpty()) {
            jtiClaim = null;
        }
        claims.put("jti", jtiClaim);
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
            }
        }

        if (forwardToken != null && forwardToken.equals("true")) {
            log.debug("Set JWT token in the message context");
            messageContext.setProperty("X-JWT", jwtToken);
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
}
