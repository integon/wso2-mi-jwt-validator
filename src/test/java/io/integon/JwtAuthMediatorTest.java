package io.integon;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.lang.reflect.Field;

import org.apache.synapse.MessageContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.nimbusds.jwt.SignedJWT;

import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

@ExtendWith(SystemStubsExtension.class)
class JwtAuthMediatorTest {
    private JwtAuthMediator mediator;

    @Mock
    private MessageContext messageContext;

    @Mock
    private JWTValidator jwtValidator;

    @SystemStub
    private EnvironmentVariables environmentVariables;

    @BeforeEach
    void setUp() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        MockitoAnnotations.openMocks(this);
        mediator = new JwtAuthMediator();

        // Use reflection to inject our mock validator
        Field validatorField = JwtAuthMediator.class.getDeclaredField("validator");
        validatorField.setAccessible(true);
        validatorField.set(mediator, jwtValidator);

        // Also set the cached time to a recent value to prevent re-initialization
        Field cachedTimeValidatorField = JwtAuthMediator.class.getDeclaredField("cachedTimeValidator");
        cachedTimeValidatorField.setAccessible(true);
        cachedTimeValidatorField.set(mediator, System.currentTimeMillis());

    }

    @Test
    void testMediate_MissingJwksEndpoint_ShouldThrowException() {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn(null);

        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));

    }

    @Test
    void testMediate_InvalidJwksUrlFromJwksEndpoint_ShouldThrowException() {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("invalid-url");

        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_InvalidJwksUrlFromJwksEndpointFromEnv_ShouldThrowException() {
        environmentVariables.set("JWKS_ENDPOINT", "invalid-url");
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("env:JWKS_ENDPOINT");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwksUrlFromJwksEndpointFromEnv_ShouldThrowException() {
        environmentVariables.set("JWKS_ENDPOINT", "");
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("env:JWKS_ENDPOINT");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ValidJwt_ShouldPass() throws Exception {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("https://valid-url-1.com,https://valid-url-2.com");
        when(messageContext.getProperty("jwtToken")).thenReturn("Bearer valid.jwt.token");

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);

        assertTrue(mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ValidJwtWithJwksEndpointFromEnvVar_ShouldPass() throws Exception {
        environmentVariables.set("JWKS_ENDPOINT", "https://valid-url-1.com,https://valid-url-2.com");
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("env:JWKS_ENDPOINT");
        when(messageContext.getProperty("jwtToken")).thenReturn("Bearer valid.jwt.token");

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);

        assertTrue(mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ExpiredJwt_ShouldThrowException() throws Exception {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("https://valid-url.com");
        when(messageContext.getProperty("jwtToken")).thenReturn("Bearer valid.jwt.token");

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mockJwt);
        when(jwtValidator.isTokenExpired(mockJwt)).thenReturn(true);

        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwt_ShouldThrowException() throws Exception {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("https://valid-url.com");
        when(messageContext.getProperty("jwtToken")).thenReturn(null);
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwtBearerPrefix_ShouldThrowException() throws Exception {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("https://valid-url.com");
        when(messageContext.getProperty("jwtToken")).thenReturn("valid.jwt.token");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwtAfterBearerPrefix_ShouldThrowException() throws Exception {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("https://valid-url.com");
        when(messageContext.getProperty("jwtToken")).thenReturn("Bearer");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwtAfterBearerPrefixWithSpace_ShouldThrowException() throws Exception {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("https://valid-url.com");
        when(messageContext.getProperty("jwtToken")).thenReturn("Bearers");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ForwardTokenEnabled_ShouldSetHeader() throws Exception {
        when(messageContext.getProperty("jwksEndpoint")).thenReturn("https://valid-url.com");
        when(messageContext.getProperty("jwtToken")).thenReturn("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30");
        when(messageContext.getProperty("forwardToken")).thenReturn("true");

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);

        mediator.mediate(messageContext);

        assertTrue(mediator.mediate(messageContext));
    }

}