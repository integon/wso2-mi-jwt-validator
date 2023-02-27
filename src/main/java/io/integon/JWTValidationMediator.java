package io.integon;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

public class JWTValidationMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(JWTValidationMediator.class);

    private String jwtToken;
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
    private long cachedTimeValidatorReset = 86400000;  // 24 hours

    private JWTValidator validator = null;

    @Override
    public boolean mediate(MessageContext messageContext) {
        try {
            applyProperties (messageContext);
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
            return false;
        }
        // initialize the JWTValidator
        if (validator == null || cachedTimeValidator + cachedTimeValidatorReset < System.currentTimeMillis()) {
            validator = new JWTValidator();
            cachedTimeValidator = System.currentTimeMillis();
        }

        // Check if the token starts with "Bearer "
        if (!jwtToken.startsWith("Bearer ")) {
            handleException("Invalid JWT format", messageContext);
            return false;
        } else {
            // Remove "Bearer " from the token
            jwtToken = jwtToken.substring(7);
            if (jwtToken == null || jwtToken.isEmpty()) {
                handleException("JWT token not found in the message", messageContext);
                return false;
            }
        }
        // If jwksEnvVariable is set, check if the environment variable contains a valid URL
        if (jwksEnvVariable != null && CommonUtils.containsUrl(System.getenv().get(jwksEnvVariable))  ) {
            jwksEndpoint = System.getenv().get(jwksEnvVariable);
        } else {
            // Check if the JWKS endpoint
            if (jwksEndpoint == null || jwksEndpoint.isEmpty()) {
                handleException("JWKS endpoint not found", messageContext);
                return false;
            }
        }

        // retrieve JWKS_TIMEOUT & JWKS_REFRESH_TIME from the message context
        validator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);

        // retrieve the sub claim from the message context
        HashMap<String, String> claims = new HashMap<>();
        claims.put("iat", iatClaim);
        claims.put("iss", issClaim);
        claims.put("sub", subClaim);
        claims.put("aud", audClaim);
        claims.put("jti", jtiClaim);

        // validate the JWT token
        boolean isValidJWT;
        try {
            isValidJWT = validator.validateToken(jwtToken, jwksEndpoint, claims);
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
        }
        return true;
    }

    private void applyProperties(MessageContext messageContext) throws Exception {
        clearProperties();
        jwtToken = (String) messageContext.getProperty("JWT_TOKEN");
        if (jwtToken == null || jwtToken.isEmpty()) {
            throw new Exception("JWT not found in the message");
        }
        jwksEndpoint = (String) messageContext.getProperty("JWKS_ENDPOINT");
        jwksEnvVariable = (String) messageContext.getProperty("JWKS_ENV_VARIABLE");
        if ((jwksEndpoint == null || jwksEndpoint.isEmpty()) && (jwksEnvVariable == null || jwksEnvVariable.isEmpty())) {
            throw new Exception("JWKS endpoint not found in the message");
        }
        iatClaim = (String) messageContext.getProperty("IAT_CLAIM");
        if (iatClaim != null && iatClaim.isEmpty()) {
            iatClaim = null;
        }
        issClaim = (String) messageContext.getProperty("ISS_CLAIM");
        if (issClaim != null && issClaim.isEmpty()) {
            issClaim = null;
        }
        subClaim = (String) messageContext.getProperty("SUB_CLAIM");
        if (subClaim != null && subClaim.isEmpty()) {
            subClaim = null;
        }
        audClaim = (String) messageContext.getProperty("AUD_CLAIM");
        if (audClaim != null && audClaim.isEmpty()) {
            audClaim = null;
        }
        jtiClaim = (String) messageContext.getProperty("JTI_CLAIM");
        if (jtiClaim != null && jtiClaim.isEmpty()) {
            jtiClaim = null;
        }
        jwksTimeout = (String) messageContext.getProperty("JWKS_TIMEOUT");
        jwksRefreshTime = (String) messageContext.getProperty("JWKS_REFRESH_TIME");
    }

    private void clearProperties() {
        jwtToken = null;
        jwksEndpoint = null;
        jwksEnvVariable = null;
        iatClaim = null;
        issClaim = null;
        subClaim = null;
        audClaim = null;
        jtiClaim = null;
        jwksTimeout = null;
        jwksRefreshTime = null;
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

        // Set a property in the message context to indicate an error
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, message);
        messageContext.setProperty(SynapseConstants.ERROR_CODE, "401");

        // Remove the entity body from the response
        axis2MessageContext.setProperty("NO_ENTITY_BODY", Boolean.FALSE);

        // Set the response content type
        axis2MessageContext.setProperty("messageType", "application/json");
        axis2MessageContext.setProperty("ContentType", "application/json");
        
        // Throw a SynapseException to signal an error
        throw new SynapseException(message);
    }
}