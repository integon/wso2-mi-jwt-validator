package io.integon;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONObject;

public class JwtAuthMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(JwtAuthMediator.class);

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
    private long cachedTimeValidatorReset = 86400000; // 24 hours

    private JWTValidator validator = null;

    private String forwardToken;

    /**
     * This method is called when the request is received by the API Get properties
     * from the message context and set them to the class variables Initialize the
     * JWTValidator Isolate the JWT token from the Authorization header Validate the
     * JWT token with the JWTValidator Check if the JWT token is expired Check
     * claims if they are set
     * 
     * @param messageContext
     *                       Synapse message context
     * @return true if the JWT token is valid
     * @throws SynapseException
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        try {
            applyProperties(messageContext);
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
        }
        // initialize the JWTValidator
        if (validator == null || cachedTimeValidator + cachedTimeValidatorReset < System.currentTimeMillis()) {
            validator = new JWTValidator();
            cachedTimeValidator = System.currentTimeMillis();
        }
        // Check if the token starts with "Bearer "
        if (!jwtToken.trim().startsWith("Bearer")) {
            log.debug("Invalid JWT format: " + jwtToken);
            handleException("Invalid JWT format", messageContext);
        } else {
            // Remove "Bearer " from the token
            jwtToken = jwtToken.substring(7);
            if (jwtToken == null || jwtToken.isEmpty()) {
                log.debug("JWT token not found in the message");
                handleException("JWT token not found in the message", messageContext);
            }
        }
        // If jwksEnvVariable is set, check if the environment variable contains a valid
        // URL
        if (jwksEnvVariable != null && CommonUtils.containsUrl(System.getenv().get(jwksEnvVariable))) {
            jwksEndpoint = System.getenv().get(jwksEnvVariable);
            log.debug("JWKS endpoint from Env Variable " + jwksEnvVariable + ": " + jwksEndpoint);
        } else {
            // Check if the JWKS endpoint
            if (jwksEndpoint == null || jwksEndpoint.isEmpty()) {
                log.debug("JWKS endpoint not found in the message context or environment variable");
                handleException("JWKS endpoint not found", messageContext);
            }
        }

        // retrieve JWKS_TIMEOUT & JWKS_REFRESH_TIME from the message context
        validator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);

        // validate the JWT token
        boolean isValidJWT;
        try {
            isValidJWT = validator.validateToken(jwtToken, jwksEndpoint);
            log.debug("isValidJWT: " + isValidJWT);
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
        }
        boolean isTokenExpired;
        try {
            isTokenExpired = validator.isTokenExpired(jwtToken);
            if (isTokenExpired) {
                handleException("JWT token is expired", messageContext);
            }
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
        }

        // retrieve the sub claim from the message context
        HashMap<String, String> claims = new HashMap<String, String>();
        claims.put("iat", iatClaim);
        claims.put("iss", issClaim);
        claims.put("sub", subClaim);
        claims.put("aud", audClaim);
        claims.put("jti", jtiClaim);
        log.debug("JWT claims Map set: " + claims);
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
        log.debug("JWT validation successful");

        log.debug("Forward token: " + forwardToken);
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
     * Retrieve the properties from the message context Check if the required
     * properties are set If not, throw an exception
     * 
     * @param messageContext
     *                       Synapse message context
     * @throws Exception
     *                   if a required property is not set
     */
    private void applyProperties(MessageContext messageContext) throws Exception {
        clearProperties();
        jwtToken = (String) messageContext.getProperty("jwtToken");
        if (jwtToken == null || jwtToken.isEmpty()) {
            throw new Exception("JWT not found in the message");
        }
        jwksEndpoint = (String) messageContext.getProperty("jwksEndpoint");
        jwksEnvVariable = (String) messageContext.getProperty("jwksEnvVariable");
        if ((jwksEndpoint == null || jwksEndpoint.isEmpty())
                && (jwksEnvVariable == null || jwksEnvVariable.isEmpty())) {
            throw new Exception("JWKS endpoint not found in the message");
        }
        iatClaim = (String) messageContext.getProperty("iatClaim");
        if (iatClaim != null && iatClaim.isEmpty()) {
            iatClaim = null;
        }
        issClaim = (String) messageContext.getProperty("issClaim");
        if (issClaim != null && issClaim.isEmpty()) {
            issClaim = null;
        }
        subClaim = (String) messageContext.getProperty("subClaim");
        if (subClaim != null && subClaim.isEmpty()) {
            subClaim = null;
        }
        audClaim = (String) messageContext.getProperty("audClaim");
        if (audClaim != null && audClaim.isEmpty()) {
            audClaim = null;
        }
        jtiClaim = (String) messageContext.getProperty("jtiClaim");
        if (jtiClaim != null && jtiClaim.isEmpty()) {
            jtiClaim = null;
        }
        jwksTimeout = (String) messageContext.getProperty("jwksTimeout");
        jwksRefreshTime = (String) messageContext.getProperty("jwksRefreshTime");
        forwardToken = (String) messageContext.getProperty("forwardToken");

        log.debug("Properties set");
    }

    /**
     * This method is used to clear the properties
     */
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
        log.debug("Properties cleared");
    }

    /**
     * This method is used to handle the exceptions
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
