package io.integon;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.Handler;

public class JWTValidationHandler implements Handler {
    private static final Log log = LogFactory.getLog(JWTValidationMediator.class);
    
    private String JWT_HEADER;
    private String JWKS_ENDPOINT;
    private String JWKS_ENV_VARIABLE;
    private String IAT_CLAIM;
    private String ISS_CLAIM;
    private String SUB_CLAIM;
    private String AUD_CLAIM;
    private String JTI_CLAIM;
    private String JWKS_TIMEOUT;
    private String JWKS_REFRESH_TIME;

    private long cachedTimeValidator = 0;
    private long cachedTimeValidatorReset = 86400000;  // 24 hours

    private JWTValidator validator = null;

    public void addProperty(String s, Object o) {
        //To change body of implemented methods use File | Settings | File Templates.
    }
    public Map getProperties() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public boolean handleRequest(MessageContext messageContext) {
        // initialize the JWTValidator
        if (validator == null || cachedTimeValidator + cachedTimeValidatorReset < System.currentTimeMillis()) {
            validator = new JWTValidator();
            cachedTimeValidator = System.currentTimeMillis();
        }

        // Get Transport Headers from the message context
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        // retrieve the JWT token from transport headers
        String authHeader= null;
        if (headers != null && headers instanceof Map) {
            Map headersMap = (Map) headers;
            authHeader = (String) headersMap.get(JWT_HEADER);
        }

        // Check if the token is null or empty
        if (authHeader == null || authHeader.isEmpty() ) {
            handleException("JWT token not found in the message", messageContext);
            return false;
        }
        // Check if the token starts with "Bearer "
        if (!authHeader.startsWith("Bearer ")) {
            handleException("Invalid JWT token format", messageContext);
            return false;
        }
        // Remove "Bearer " from the token
        String jwtToken = authHeader.substring(7);
        if (jwtToken == null || jwtToken.isEmpty()) {
            handleException("JWT token not found in the message", messageContext);
            return false;
        }
        String jwksEnvVariable = JWKS_ENV_VARIABLE;
        String jwksEndpoint = JWKS_ENDPOINT;
        // If jwksEnvVariable is set, check if the environment variable contains a valid URL
        if (jwksEnvVariable != null && System.getenv().get(jwksEnvVariable) != null) {
            if (CommonUtils.containsUrl(System.getenv().get(jwksEnvVariable))){
                jwksEndpoint = System.getenv().get(jwksEnvVariable);
            }
        } else {
            // Check if the JWKS endpoint
            if (jwksEndpoint == null || jwksEndpoint.isEmpty()) {
                handleException("JWKS endpoint not found", messageContext);
                return false;
            }
        }

        // retrieve JWKS_TIMEOUT & JWKS_REFRESH_TIME from the message context
        String jwksTimeout = JWKS_TIMEOUT;
        String jwksRefreshTime = JWKS_REFRESH_TIME;
        validator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);

        HashMap<String, String> claims = new HashMap<>();
        if (IAT_CLAIM != null && IAT_CLAIM.isEmpty()) {
            IAT_CLAIM = null;
        }
        claims.put("iat", IAT_CLAIM);
        if (ISS_CLAIM != null && ISS_CLAIM.isEmpty()) {
            ISS_CLAIM = null;
        }
        claims.put("iss", ISS_CLAIM);
        if (SUB_CLAIM != null && SUB_CLAIM.isEmpty()) {
            SUB_CLAIM = null;
        }
        claims.put("sub", SUB_CLAIM);
        if (AUD_CLAIM != null && AUD_CLAIM.isEmpty()) {
            AUD_CLAIM = null;
        }
        claims.put("aud", AUD_CLAIM);
        if (JTI_CLAIM != null && JTI_CLAIM.isEmpty()) {
            JTI_CLAIM = null;
        }
        claims.put("jti", JTI_CLAIM);

        //validate the JWT token
        boolean isValidJWT;
        try {
            isValidJWT = validator.validateToken(jwtToken, jwksEndpoint, claims);
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
            return false;
        }
        return true;
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

    protected void handleException(String message, MessageContext messageContext) {
        // Create a SOAPFactory and an XML payload
        CommonUtils.setJsonEnvolopMessageContext(messageContext, message);

        // Get Transport Headers from the message context
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        // Clear the transport headers
        Map headersMap = (Map) headers;
        headersMap.clear();

        // Set the response status code
        axis2MessageContext.setProperty("HTTP_SC", HttpStatus.SC_UNAUTHORIZED);

        // Set the "NO_ENTITY_BODY" property to false -- this is required to send a response
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

    public String getJWKS_ENDPOINT() {
        return JWKS_ENDPOINT;
    }

    public void setJWKS_ENDPOINT(String jwks) {
        this.JWKS_ENDPOINT = jwks;
    }

    public String getJWKS_ENV_VARIABLE() {
        return JWKS_ENV_VARIABLE;
    }
    public void setJWKS_ENV_VARIABLE(String jWKS_ENV_VARIABLE) {
        JWKS_ENV_VARIABLE = jWKS_ENV_VARIABLE;
    }

    public String getJWT_HEADER() {
        return JWT_HEADER;
    }

    public void setJWT_HEADER(String header) {
        this.JWT_HEADER = header;
    }
    public String getIAT_CLAIM() {
        return IAT_CLAIM;
    }
    public void setIAT_CLAIM(String iat) {
        IAT_CLAIM = iat;
    }

    public String getISS_CLAIM() {
        return ISS_CLAIM;
    }
    public void setISS_CLAIM(String iss) {
        ISS_CLAIM = iss;
    }

    public String getAUD_CLAIM() {
        return AUD_CLAIM;
    }
    public void setAUD_CLAIM(String aud) {
        AUD_CLAIM = aud;
    }

    public String getSUB_CLAIM() {
        return SUB_CLAIM;
    }

    public void setSUB_CLAIM(String sub) {
        this.SUB_CLAIM = sub;
    }

    public String getJTI_CLAIM() {
        return JTI_CLAIM;
    }
    public void setJTI_CLAIM(String jti) {
        JTI_CLAIM = jti;
    }

    public String getJWKS_TIMEOUT() {
        return JWKS_TIMEOUT;
    }

    public void setJWKS_TIMEOUT(String timeout) {
        this.JWKS_TIMEOUT = timeout;
    }

    public String getJWKS_REFRESH_TIME() {
        return JWKS_REFRESH_TIME;
    }

    public void setJWKS_REFRESH_TIME(String refresh) {
        this.JWKS_REFRESH_TIME = refresh;
    }
}

