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

    // Regex to validate the url
    public static final String URL_REGEX = "(?i)\\b((?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’]))";
    
    /**
     * This method checks if the jwks url is valid
     * @param jwksUrl
     * @return true if the url is valid, false otherwise
     */
    public static boolean containsUrl(String jwksUrl) {
        Pattern pattern = Pattern.compile(URL_REGEX);
        Matcher matcher = pattern.matcher(jwksUrl);
        log.debug("The url is valid: " + matcher.find());
        return matcher.find();
    }

    /**
     * This method sets the error message to the message context
     * @param messageContext
     * @param message
     * @return MessageContext
     */
    public static MessageContext setJsonEnvelopMessageContext (MessageContext messageContext, String message) {
        // Create a SOAPFactory and an XML payload
        SOAPFactory soapFactory = OMAbstractFactory.getSOAP11Factory();
        OMElement payload = soapFactory.createOMElement("jsonObject", null);
        OMElement codeElement = soapFactory.createOMElement(new QName("status"));
        codeElement.setText(String.valueOf(HttpStatus.SC_UNAUTHORIZED));
        OMElement messagElement = soapFactory.createOMElement(new QName("message"));
        messagElement.setText(String.valueOf(message));
        payload.addChild(codeElement);
        payload.addChild(messagElement);

        // Create a SOAPEnvelope and add the XML payload to its body
        SOAPEnvelope envelope = soapFactory.getDefaultEnvelope();
        envelope.getBody().addChild(payload);

        try {
            // Set the response envelope to the message context
            messageContext.setEnvelope(envelope);
            log.debug("The error message is set to the message context");
        } catch (AxisFault e) {
            e.printStackTrace();
        }
        return messageContext;
    }

}
