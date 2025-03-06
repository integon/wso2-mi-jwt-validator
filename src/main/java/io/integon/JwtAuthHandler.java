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

import com.nimbusds.jwt.SignedJWT;

/**
 * This class is used to validate the JWT token Implements the Handler interface
 * from the Synapse REST API to be used in a Micro Integrator API
 */
public class JwtAuthHandler implements Handler {
    private static final Log log = LogFactory.getLog(JwtAuthHandler.class);

    private String JWKS_ENDPOINT_PARAMETER_NAME = "jwksEndpoint";
    private String JWKS_TIMEOUT_PARAMETER_NAME = "jwksTimeout";
    private String JWKS_REFRESH_TIME_PARAMETER_NAME = "jwksRefreshTime";
    private String JWT_HEADER_PARAMETER_NAME = "jwtHeader";
    private String IAT_CLAIM_PARAMETER_NAME = "iatClaim";
    private String ISS_CLAIM_PARAMETER_NAME = "issClaim";
    private String SUB_CLAIM_PARAMETER_NAME = "subClaim";
    private String AUD_CLAIM_PARAMETER_NAME = "audClaim";
    private String JTI_CLAIM_PARAMETER_NAME = "jtiClaim";
    private String FORWARD_TOKEN_PARAMETER_NAME = "forwardToken";

    private long CACHED_TIME_VALIDATOR = 0;
    private long CACHED_TIME_VALIDATOR_RESET = 86400000; // 24 hours

    private JWTValidator validator = null;

    @Override
    public void addProperty(String s, Object o) {
        // To change body of implemented methods use File | Settings | File Templates.
    }

    @SuppressWarnings("rawtypes")
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
        if (validator == null || CACHED_TIME_VALIDATOR + CACHED_TIME_VALIDATOR_RESET < System.currentTimeMillis()) {
            validator = new JWTValidator();
            CACHED_TIME_VALIDATOR = System.currentTimeMillis();
            log.debug("JWTValidator initialized: " + validator);
        }

        // Get Transport Headers from the message context
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        // retrieve the JWT token from transport headers
        String authHeader = null;
        if (headers instanceof Map) {
            @SuppressWarnings("rawtypes")
            Map headersMap = (Map) headers;
            authHeader = (String) headersMap.get(JWT_HEADER_PARAMETER_NAME);
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
        String jwtToken;   
        try {
            jwtToken = authHeader.substring(7).trim();
        } catch (IndexOutOfBoundsException e) {
            log.debug("Invalid JWT token format: " + authHeader);
            handleException("Invalid Authorization header format", messageContext);
            return false;
        }
        
        if (jwtToken.isEmpty()) {
            log.debug("JWT token not found in the message");
            handleException("JWT token not found in the message", messageContext);
            return false;
        }

        String resolvedJwksEndpoint = CommonUtils.resolveConfigValue(JWKS_ENDPOINT_PARAMETER_NAME);
        if (resolvedJwksEndpoint == null) {
            handleException("JWKS endpoint not found", messageContext);
            return false;
        }

        ArrayList<URL> jwksUrls = new ArrayList<>();
        String[] jwksUrlsSplit = resolvedJwksEndpoint.split(",");
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
        validator.setCacheTimeouts(JWKS_TIMEOUT_PARAMETER_NAME, JWKS_REFRESH_TIME_PARAMETER_NAME);

        // validate the JWT token
        SignedJWT parsedJWT;
        try {
            parsedJWT = validator.validateToken(jwtToken, jwksUrls);
            log.debug("JWT is valid");
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
            return false;
        }
        // Check if the token is expired
        boolean isTokenExpired;
        try {
            isTokenExpired = validator.isTokenExpired(parsedJWT);
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
        if (IAT_CLAIM_PARAMETER_NAME != null && IAT_CLAIM_PARAMETER_NAME.isEmpty()) {
            IAT_CLAIM_PARAMETER_NAME = null;
        }
        claims.put("iat", IAT_CLAIM_PARAMETER_NAME);
        if (ISS_CLAIM_PARAMETER_NAME != null && ISS_CLAIM_PARAMETER_NAME.isEmpty()) {
            ISS_CLAIM_PARAMETER_NAME = null;
        }
        claims.put("iss", ISS_CLAIM_PARAMETER_NAME);
        if (SUB_CLAIM_PARAMETER_NAME != null && SUB_CLAIM_PARAMETER_NAME.isEmpty()) {
            SUB_CLAIM_PARAMETER_NAME = null;
        }
        claims.put("sub", SUB_CLAIM_PARAMETER_NAME);
        if (AUD_CLAIM_PARAMETER_NAME != null && AUD_CLAIM_PARAMETER_NAME.isEmpty()) {
            AUD_CLAIM_PARAMETER_NAME = null;
        }
        claims.put("aud", AUD_CLAIM_PARAMETER_NAME);
        if (JTI_CLAIM_PARAMETER_NAME != null && JTI_CLAIM_PARAMETER_NAME.isEmpty()) {
            JTI_CLAIM_PARAMETER_NAME = null;
        }
        claims.put("jti", JTI_CLAIM_PARAMETER_NAME);
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
                validator.areClaimsValid(parsedJWT, claims);
            } catch (Exception e) {
                handleException(e.getMessage(), messageContext);
                return false;
            }
        }

        if (FORWARD_TOKEN_PARAMETER_NAME != null && FORWARD_TOKEN_PARAMETER_NAME.equals("true")) {
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
        @SuppressWarnings("rawtypes")
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
        return JWKS_ENDPOINT_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setJwksEndpoint(String jwks) {
        this.JWKS_ENDPOINT_PARAMETER_NAME = jwks;
    }

    // Interface handler injection
    public String getJwtHeader() {
        return JWT_HEADER_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setJwtHeader(String header) {
        this.JWT_HEADER_PARAMETER_NAME = header;
    }

    // Interface handler injection
    public String getIatClaim() {
        return IAT_CLAIM_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setIatClaim(String iat) {
        IAT_CLAIM_PARAMETER_NAME = iat;
    }

    // Interface handler injection
    public String getIssClaim() {
        return ISS_CLAIM_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setIssClaim(String iss) {
        ISS_CLAIM_PARAMETER_NAME = iss;
    }

    // Interface handler injection
    public String getAudClaim() {
        return AUD_CLAIM_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setAudClaim(String aud) {
        AUD_CLAIM_PARAMETER_NAME = aud;
    }

    // Interface handler injection
    public String getSubClaim() {
        return SUB_CLAIM_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setSubClaim(String sub) {
        this.SUB_CLAIM_PARAMETER_NAME = sub;
    }

    // Interface handler injection
    public String getJtiClaim() {
        return JTI_CLAIM_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setJtiClaim(String jti) {
        JTI_CLAIM_PARAMETER_NAME = jti;
    }

    // Interface handler injection
    public String getJwksTimeout() {
        return JWKS_TIMEOUT_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setJwksTimeout(String timeout) {
        this.JWKS_TIMEOUT_PARAMETER_NAME = timeout;
    }

    // Interface handler injection
    public String getJwksRefreshTime() {
        return JWKS_REFRESH_TIME_PARAMETER_NAME;
    }

    // Interface handler injection
    public void setJwksRefreshTime(String refresh) {
        this.JWKS_REFRESH_TIME_PARAMETER_NAME = refresh;
    }

    public String getForwardToken() {
        return FORWARD_TOKEN_PARAMETER_NAME;
    }

    public void setForwardToken(String forwardToken) {
        this.FORWARD_TOKEN_PARAMETER_NAME = forwardToken;
    }
}
