package io.integon;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import java.net.URL;
import java.net.MalformedURLException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONObject;

public class JwtAuthMediator extends AbstractMediator {

    public static final String JWKS_ENDPOINT_PARAMETER_NAME = "jwksEndpoint";
    public static final String JWKS_ENV_VARIABLE_PARAMETER_NAME = "jwksEnvVariable";
    public static final String JWKS_TIMEOUT_PARAMETER_NAME = "jwksTimeout";
    public static final String JWKS_REFRESH_TIME_PARAMETER_NAME = "jwksRefreshTime";
    public static final String JWT_TOKEN_PARAMETER_NAME = "jwtToken";
    public static final String IAT_CLAIM_PARAMETER_NAME = "iatClaim";
    public static final String ISS_CLAIM_PARAMETER_NAME = "issClaim";
    public static final String ISS_ENV_VARIABLE_PARAMETER_NAME = "issEnvVariable";
    public static final String SUB_CLAIM_PARAMETER_NAME = "subClaim";
    public static final String AUD_CLAIM_PARAMETER_NAME = "audClaim";
    public static final String AUD_ENV_VARIABLE_PARAMETER_NAME = "audEnvVariable";
    public static final String CLAIM_NAME_PARAMETER_NAME = "claimName";
    public static final String CLAIM_VALUE_ENV_VARIABLE_PARAMETER_NAME = "claimValueEnvVariable";
    public static final String CLAIM_VALUE_PARAMETER_NAME = "claimValue";
    public static final String JTI_CLAIM_PARAMETER_NAME = "jtiClaim";
    public static final String FORWARD_TOKEN_PARAMETER_NAME = "forwardToken";

    private static final Log log = LogFactory.getLog(JwtAuthMediator.class);

    private long cachedTimeValidator = 0;
    private long cachedTimeValidatorReset = 86400000; // 24 hours

    private JWTValidator validator = null;

    // Static counter for instances
    private static AtomicLong instanceCount = new AtomicLong();

    // Constructor
    public JwtAuthMediator() {
        synchronized (JwtAuthMediator.class) {
            instanceCount.incrementAndGet();
            log.info("JwtAuthMediator instance created. Current instance count: " + instanceCount);
        }
    }

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
        // initialize the JWTValidator
        if (validator == null || cachedTimeValidator + cachedTimeValidatorReset < System.currentTimeMillis()) {
            validator = new JWTValidator();
            log.debug("JWTValidator: " + validator);
            cachedTimeValidator = System.currentTimeMillis();
        }

        String jwksEndpoint = CommonUtils.getValueFromParameterOrEnv(messageContext, JWKS_ENDPOINT_PARAMETER_NAME, JWKS_ENV_VARIABLE_PARAMETER_NAME);
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
         
        // retrieve JWKS_TIMEOUT & JWKS_REFRESH_TIME from the message context
        String jwksTimeout = CommonUtils.getValueFromParameterOrEnv(messageContext, JWKS_TIMEOUT_PARAMETER_NAME, null);
        String jwksRefreshTime = CommonUtils.getValueFromParameterOrEnv(messageContext, JWKS_REFRESH_TIME_PARAMETER_NAME, null);
        validator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);

        String jwtToken = CommonUtils.getValueFromParameterOrEnv(messageContext, JWT_TOKEN_PARAMETER_NAME, null);
        if (jwtToken == null || jwtToken.isEmpty()) {
            log.debug("JWT not found in the message");
            handleException("JWT not found in the message", messageContext);
            return false;
        }

        // Check if the token starts with "Bearer "
        if (!jwtToken.trim().startsWith("Bearer")) {
            log.debug("Invalid JWT format: " + jwtToken);
            handleException("Invalid JWT format", messageContext);
            return false;
        } else {
            // Remove "Bearer " from the token
            jwtToken = jwtToken.substring(7);
            if (jwtToken == null || jwtToken.isEmpty()) {
                log.debug("JWT token not found in the message");
                handleException("JWT token not found in the message", messageContext);
                return false;
            }
        }

        // validate the JWT token
        boolean isValidJWT;
        try {
            isValidJWT = validator.validateToken(jwtToken, jwksUrls);
            log.debug("isValidJWT: " + isValidJWT);
        } catch (Exception e) {
            handleException(e.getMessage(), messageContext);
            return false;
        }
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

        // retrieve the sub claim from the message context
        String iatClaim = CommonUtils.getValueFromParameterOrEnv(messageContext, IAT_CLAIM_PARAMETER_NAME, null);
        String issClaim = CommonUtils.getValueFromParameterOrEnv(messageContext, ISS_CLAIM_PARAMETER_NAME, ISS_ENV_VARIABLE_PARAMETER_NAME);

        String subClaim = CommonUtils.getValueFromParameterOrEnv(messageContext, SUB_CLAIM_PARAMETER_NAME, null);
        String audClaim = CommonUtils.getValueFromParameterOrEnv(messageContext, AUD_CLAIM_PARAMETER_NAME, AUD_ENV_VARIABLE_PARAMETER_NAME);

        String claimName = CommonUtils.getValueFromParameterOrEnv(messageContext, CLAIM_NAME_PARAMETER_NAME, null);
        String claimValue = CommonUtils.getValueFromParameterOrEnv(messageContext, CLAIM_VALUE_PARAMETER_NAME, CLAIM_VALUE_ENV_VARIABLE_PARAMETER_NAME);

        String jtiClaim = CommonUtils.getValueFromParameterOrEnv(messageContext, JTI_CLAIM_PARAMETER_NAME, null);

        HashMap<String, String> claims = new HashMap<String, String>();
        claims.put("iat", iatClaim);
        claims.put("iss", issClaim);
        claims.put("sub", subClaim);
        claims.put("aud", audClaim);
        claims.put("genericClaimName", claimName);
        claims.put("genericClaimValue", claimValue);
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
                return false;
            }
        }
        log.debug("JWT validation successful");

        String forwardToken = (String) messageContext.getProperty(FORWARD_TOKEN_PARAMETER_NAME);
        log.debug("Forward token: " + forwardToken);
        if ("true".equals(forwardToken)) {
            log.debug("Set JWT token in the message context");
            // Decode the JWT payload and add it to the transport headers
            String decodedToken = new String(Base64.getDecoder().decode(jwtToken.split("\\.")[1]));

            JSONObject jsonObject = new JSONObject(decodedToken);

            messageContext.setProperty("X-JWT", jsonObject.toString());

            log.debug("Forward token set to X-JWT Header");
        }
        return true;
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
        Object transportHeaders = axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (transportHeaders != null) {
            // Clear the transport headers
            Map transportHeadersMap = (Map) transportHeaders;
            transportHeadersMap.clear();
        }

        // Set a property in the message context to indicate an error
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, message);
        messageContext.setProperty(SynapseConstants.ERROR_CODE, HttpStatus.SC_UNAUTHORIZED);

        // Set the response status code
        axis2MessageContext.setProperty(SynapseConstants.HTTP_SC, HttpStatus.SC_UNAUTHORIZED);

        // Remove the entity body from the response
        axis2MessageContext.setProperty("NO_ENTITY_BODY", Boolean.FALSE);

        // Set the response content type
        axis2MessageContext.setProperty("messageType", "application/json");
        axis2MessageContext.setProperty("ContentType", "application/json");

        // Respond from mediator if respond is 'true' else throw SynapseException
        String respond = (String) messageContext.getProperty("respond");
        if (respond != null && respond.equals("true")) {
            log.debug("Respond from Mediator");
            // Set the "to" property to null
            messageContext.setTo(null);
            messageContext.setResponse(true);

            axis2MessageContext.getOperationContext().setProperty(org.apache.axis2.Constants.RESPONSE_WRITTEN, "SKIP");

            Axis2Sender.sendBack(messageContext);

        } else {
            // Throw a SynapseException to signal an error
            log.debug("Throw a SynapseException to trigger faultSequence");
            throw new SynapseException(message);
        }
    }
}
