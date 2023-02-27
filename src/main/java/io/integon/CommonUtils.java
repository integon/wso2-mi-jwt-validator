package io.integon;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axis2.AxisFault;


import org.apache.http.HttpStatus;

import org.apache.synapse.MessageContext;

public class CommonUtils {

    public static boolean containsUrl(String jwksUrl) {
        String regex = "(?i)\\b((?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’]))";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(jwksUrl);
        return matcher.find();
    }

    public static MessageContext setJsonEnvolopMessageContext (MessageContext messageContext, String message) {
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
        } catch (AxisFault e) {
            e.printStackTrace();
        }
        return messageContext;
    }

}
