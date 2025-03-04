package io.integon;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.synapse.MessageContext;

/**
 * This class contains common methods used by the other classes
 */
public class CommonUtils {

    private static final Log log = LogFactory.getLog(JwtAuthMediator.class);

    // Regex to validate URLs
    public static final String URL_REGEX = "(?i)\\b((?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’]))";

    /**
     * Checks if the provided JWKS (JSON Web Key Set) URL is valid.
     *
     * @param jwksUrl The JWKS URL string to be validated.
     * @return {@code true} if the URL matches the expected format, {@code false}
     *         otherwise.
     */
    public static boolean containsUrl(String jwksUrl) {
        Pattern pattern = Pattern.compile(URL_REGEX);
        Matcher matcher = pattern.matcher(jwksUrl);
        boolean result = matcher.find();
        log.debug("The URL is valid: " + result);
        return result;
    }

    /**
     * Sets an error message in the provided message context by constructing a SOAP
     * response with JSON-like structure.
     *
     * @param messageContext The Synapse message context to which the error message
     *                       should be set.
     * @param message        The error message text that will be included in the
     *                       response payload.
     * @return The updated {@link MessageContext} with the error message set.
     */
    public static MessageContext setJsonEnvelopMessageContext(MessageContext messageContext, String message) {
        // Create a SOAPFactory and an XML payload
        SOAPFactory soapFactory = OMAbstractFactory.getSOAP11Factory();
        OMElement payload = soapFactory.createOMElement("jsonObject", null);
        OMElement codeElement = soapFactory.createOMElement(new QName("status"));
        codeElement.setText(String.valueOf(HttpStatus.SC_UNAUTHORIZED));
        OMElement messageElement = soapFactory.createOMElement(new QName("message"));
        messageElement.setText(message);
        payload.addChild(codeElement);
        payload.addChild(messageElement);

        // Create a SOAPEnvelope and add the XML payload to its body
        SOAPEnvelope envelope = soapFactory.getDefaultEnvelope();
        envelope.getBody().addChild(payload);

        try {
            // Set the response envelope to the message context
            messageContext.setEnvelope(envelope);
            log.debug("The error message is set in the message context");
        } catch (AxisFault e) {
            log.error("Failed to set error message in the message context", e);
        }
        return messageContext;
    }
}