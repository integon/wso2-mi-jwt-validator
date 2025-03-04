package io.integon;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.*;
import java.net.URL;
import java.lang.reflect.Field;

import org.apache.http.HttpStatus;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import com.nimbusds.jwt.SignedJWT;

class JwtAuthHandlerTest {

    private JwtAuthHandler handler;

    @Mock
    private MessageContext messageContext;

    @Mock
    private org.apache.axis2.context.MessageContext axis2MessageContext;

    @Mock
    private Axis2MessageContext axis2MC;

    @Mock
    private JWTValidator jwtValidator;

    private Map<String, String> headers;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        handler = new JwtAuthHandler();

        // Set required properties
        handler.setJwtHeader("Authorization");
        handler.setJwksEndpoint("https://example.com/.well-known/jwks.json");
        handler.setJwksTimeout("3600");
        handler.setJwksRefreshTime("180");

        // Mock Axis2MessageContext behavior
        when(axis2MC.getAxis2MessageContext()).thenReturn(axis2MessageContext);
        messageContext = axis2MC;

        // Create headers map
        headers = new HashMap<>();
        when(axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .thenReturn(headers);

        // Use reflection to inject the mock validator
        Field validatorField = JwtAuthHandler.class.getDeclaredField("validator");
        validatorField.setAccessible(true);
        validatorField.set(handler, jwtValidator);

        // Set the cached time to a recent value to prevent re-initialization
        Field cachedTimeValidatorField = JwtAuthHandler.class.getDeclaredField("cachedTimeValidator");
        cachedTimeValidatorField.setAccessible(true);
        cachedTimeValidatorField.set(handler, System.currentTimeMillis());
    }

    @Test
    void testHandleRequest_WithValidToken() throws Exception {
        // Setup
        String validToken = "validJwtToken";
        headers.put("Authorization", "Bearer " + validToken);

        SignedJWT mockJwt = mock(SignedJWT.class);

        // Mock successful validation
        when(jwtValidator.validateToken(eq(validToken), any())).thenReturn(mockJwt);
        when(jwtValidator.isTokenExpired(mockJwt)).thenReturn(false);

        // Execute
        boolean result = handler.handleRequest(messageContext);

        // Verify
        assertTrue(result, "Handle request should return true for valid token");
        verify(jwtValidator).validateToken(eq(validToken), any());
        verify(jwtValidator).isTokenExpired(mockJwt);
    }

    @Test
    void testHandleRequest_MissingToken() {
        // Setup - no Authorization header
        mockCommonUtilsAndAxis2Sender(() -> {
            // Execute
            boolean result = handler.handleRequest(messageContext);
    
            // Verify
            assertFalse(result, "Handle request should return false for missing token");

    
            // Verify that the response properties are set correctly
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(messageContext).setTo(null);
        }, "JWT token not found in the message");
    }

    @Test
    void testHandleRequest_InvalidTokenFormat() {
        // Setup
        headers.put("Authorization", "InvalidFormat");

        mockCommonUtilsAndAxis2Sender(() -> {
            // Execute
            boolean result = handler.handleRequest(messageContext);
    
            // Verify
            assertFalse(result, "Handle request should return false for inviald Auth Header");
    
            // Verify that the response properties are set correctly
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(messageContext).setTo(null);
        }, "Invalid JWT token format");
    }

    @Test
    void testHandleRequest_MissingJwtAfterBearerPrefix() {
        // Setup
        headers.put("Authorization", "Bearer");

        mockCommonUtilsAndAxis2Sender(() -> {
            // Execute
            boolean result = handler.handleRequest(messageContext);
    
            // Verify
            assertFalse(result, "Handle request should return false for missing JWT after Bearer Prefix");
    
            // Verify that the response properties are set correctly
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(messageContext).setTo(null);
        }, "Invalid Authorization header format");
    }

    @Test
    void testHandleRequest_MissingJwksEndpoint() {
        // Setup
        headers.put("Authorization", "Bearer validToken");
        handler.setJwksEndpoint(null);
        handler.setJwksEnvVariable(null);

        mockCommonUtilsAndAxis2Sender(() -> {
            // Execute
            boolean result = handler.handleRequest(messageContext);
    
            // Verify
            assertFalse(result, "Handle request should return false for missing JWKS URL");
    
            // Verify that the response properties are set correctly
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(messageContext).setTo(null);
        }, "JWKS endpoint not found");
    }

    @Test
    void testHandleRequest_InvalidJwksUrl() {
        // Setup
        headers.put("Authorization", "Bearer validToken");
        handler.setJwksEndpoint("invalid-url");

        mockCommonUtilsAndAxis2Sender(() -> {
            // Execute
            boolean result = handler.handleRequest(messageContext);
    
            // Verify
            assertFalse(result, "Handle request should return false for invalid JWKS URL");
    
            // Verify that the response properties are set correctly
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(messageContext).setTo(null);
        }, "JWKS URL invalid");
    }

    @Test
    void testHandleRequest_ExpiredToken() throws Exception {
        // Setup
        String validToken = "validJwtToken";
        headers.put("Authorization", "Bearer " + validToken);

        SignedJWT mockJwt = mock(SignedJWT.class);

        // Mock validation and expired token
        when(jwtValidator.validateToken(eq(validToken), any())).thenReturn(mockJwt);
        when(jwtValidator.isTokenExpired(mockJwt)).thenReturn(true);
        mockCommonUtilsAndAxis2Sender(() -> {
            // Execute
            boolean result = handler.handleRequest(messageContext);
    
            // Verify
            assertFalse(result, "Handle request should return false for expired token");

    
            // Verify that the response properties are set correctly
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(messageContext).setTo(null);
        }, "JWT token is expired");
    }

    @Test
    void testHandleRequest_TokenValidationFails() throws Exception {
        // Setup
        String validToken = "validJwtToken";
        headers.put("Authorization", "Bearer " + validToken);

        // Mock validation failure
        when(jwtValidator.validateToken(eq(validToken), any())).thenThrow(new Exception("Invalid token"));

        mockCommonUtilsAndAxis2Sender(() -> {
            // Execute
            boolean result = handler.handleRequest(messageContext);
    
            // Verify
            assertFalse(result, "Handle request should return false for invalid token");
    
            // Verify that the response properties are set correctly
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(messageContext).setTo(null);
        }, "Invalid token");
    }

    @Test
    void testHandleRequest_InvalidClaims() throws Exception {
        // Setup
        String validToken = "validJwtToken";
        headers.put("Authorization", "Bearer " + validToken);

        SignedJWT mockJwt = mock(SignedJWT.class);

        // Set claims
        handler.setIssClaim("expected-issuer");

        // Mock validation but invalid claims
        when(jwtValidator.validateToken(eq(validToken), any())).thenReturn(mockJwt);
        when(jwtValidator.isTokenExpired(mockJwt)).thenReturn(false);
        doThrow(new Exception("Invalid claims")).when(jwtValidator).areClaimsValid(eq(mockJwt), any());
        mockCommonUtilsAndAxis2Sender(() -> {
            // Execute
            boolean result = handler.handleRequest(messageContext);
    
            // Verify
            assertFalse(result, "Handle request should return false for invalid claims");
    
            // Verify that the response properties are set correctly
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(messageContext).setTo(null);
        }, "Invalid claims");
    }

    @Test
    void testHandleRequest_ForwardToken() throws Exception {
        // Setup
        String jwtToken = "header.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature";
        headers.put("Authorization", "Bearer " + jwtToken);

        handler.setForwardToken("true");

        SignedJWT mockJwt = mock(SignedJWT.class);

        // Mock successful validation
        when(jwtValidator.validateToken(eq(jwtToken), any())).thenReturn(mockJwt);
        when(jwtValidator.isTokenExpired(mockJwt)).thenReturn(false);

        // Execute
        boolean result = handler.handleRequest(messageContext);

        // Verify
        assertTrue(result, "Handle request should return true for valid token");
        verify(messageContext).setProperty(eq("X-JWT"), anyString());
    }

    @Test
    void testHandleRequest_MultipleJwksEndpoints() throws Exception {
        // Setup
        String validToken = "validJwtToken";
        headers.put("Authorization", "Bearer " + validToken);

        // Set multiple JWKS endpoints
        handler.setJwksEndpoint(
                "https://example1.com/.well-known/jwks.json, https://example2.com/.well-known/jwks.json");

        SignedJWT mockJwt = mock(SignedJWT.class);

        // Mock successful validation
        when(jwtValidator.validateToken(eq(validToken), any())).thenReturn(mockJwt);
        when(jwtValidator.isTokenExpired(mockJwt)).thenReturn(false);

        // Capture the URLs passed to validateToken
        ArgumentCaptor<ArrayList<URL>> urlCaptor = ArgumentCaptor.forClass(ArrayList.class);

        // Execute
        boolean result = handler.handleRequest(messageContext);

        // Verify
        assertTrue(result, "Handle request should return true for valid token");
        verify(jwtValidator).validateToken(eq(validToken), urlCaptor.capture());

        // Verify that both URLs were passed
        ArrayList<URL> capturedUrls = urlCaptor.getValue();
        assertEquals(2, capturedUrls.size(), "Should have 2 JWKS URLs");
        assertEquals("https://example1.com/.well-known/jwks.json", capturedUrls.get(0).toString(),
                "First URL should match");
        assertEquals("https://example2.com/.well-known/jwks.json", capturedUrls.get(1).toString(),
                "Second URL should match");
    }

    @Test
    void testHandleResponse() {
        // The handleResponse method just returns true
        assertTrue(handler.handleResponse(messageContext));
    }

    @Test
    void testHandleException() {
        // Setup
        String errorMessage = "Test error message";

        // Mock static method calls
        try (MockedStatic<Axis2Sender> mockedSender = mockStatic(Axis2Sender.class);
                MockedStatic<CommonUtils> mockedUtils = mockStatic(CommonUtils.class)) {

            // Execute
            handler.handleException(errorMessage, messageContext);

            // Verify CommonUtils.setJsonEnvelopMessageContext was called
            mockedUtils.verify(() -> CommonUtils.setJsonEnvelopMessageContext(eq(messageContext), eq(errorMessage)));

            // Verify message context properties were set
            verify(axis2MessageContext).setProperty("HTTP_SC", HttpStatus.SC_UNAUTHORIZED);
            verify(axis2MessageContext).setProperty("NO_ENTITY_BODY", Boolean.FALSE);
            verify(messageContext).setProperty("RESPONSE", "true");
            verify(axis2MessageContext).setProperty("messageType", "application/json");
            verify(axis2MessageContext).setProperty("ContentType", "application/json");
            verify(messageContext).setTo(null);

            // Verify Axis2Sender.sendBack was called
            mockedSender.verify(() -> Axis2Sender.sendBack(messageContext));
        }
    }

    private void mockCommonUtilsAndAxis2Sender(Runnable testLogic, String exceptionMessage) {
        try (
                MockedStatic<CommonUtils> mockedUtils = mockStatic(CommonUtils.class);
                MockedStatic<Axis2Sender> mockedSender = mockStatic(Axis2Sender.class)) {
    
            // Mock the CommonUtils.setJsonEnvelopMessageContext call
            mockedUtils.when(() -> CommonUtils.setJsonEnvelopMessageContext(any(), any()))
                    .thenAnswer(invocation -> null);
    
            // Mock the Axis2Sender.sendBack to do nothing
            mockedSender.when(() -> Axis2Sender.sendBack(any())).thenAnswer(invocation -> null);
    
            // Execute the test logic
            testLogic.run();
    
            // Verify the static methods were called with the expected parameters
            mockedUtils.verify(
                    () -> CommonUtils.setJsonEnvelopMessageContext(eq(messageContext), contains(exceptionMessage)));
            mockedSender.verify(() -> Axis2Sender.sendBack(messageContext));
        }
    }
    
}