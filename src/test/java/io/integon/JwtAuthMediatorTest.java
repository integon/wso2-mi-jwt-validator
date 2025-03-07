package io.integon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.lang.reflect.Field;

import org.apache.synapse.MessageContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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

    private static final String JWKS_ENDPOINT_PARAMETER_NAME = "jwksEndpoint";
    private static final String JWKS_TIMEOUT_PARAMETER_NAME = "jwksTimeout";
    private static final String JWKS_REFRESH_TIME_PARAMETER_NAME = "jwksRefreshTime";
    private static final String JWT_TOKEN_PARAMETER_NAME = "jwtToken";
    private static final String FORWARD_TOKEN_PARAMETER_NAME = "forwardToken";
    private static final String IAT_CLAIM_PARAMETER_NAME = "iatClaim";
    private static final String ISS_CLAIM_PARAMETER_NAME = "issClaim";
    private static final String SUB_CLAIM_PARAMETER_NAME = "subClaim";
    private static final String AUD_CLAIM_PARAMETER_NAME = "audClaim";
    private static final String JTI_CLAIM_PARAMETER_NAME = "jtiClaim";


    @BeforeEach
    void setUp() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        MockitoAnnotations.openMocks(this);
        mediator = new JwtAuthMediator();

        // Use reflection to inject our mock validator
        Field validatorField = JwtAuthMediator.class.getDeclaredField("validator");
        validatorField.setAccessible(true);
        validatorField.set(mediator, jwtValidator);

        // Also set the cached time to a recent value to prevent re-initialization
        Field CACHED_TIME_VALIDATORField = JwtAuthMediator.class.getDeclaredField("CACHED_TIME_VALIDATOR");
        CACHED_TIME_VALIDATORField.setAccessible(true);
        CACHED_TIME_VALIDATORField.set(mediator, System.currentTimeMillis());

    }

    @Test
    void testMediate_MissingJwksEndpoint_ShouldThrowException() {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn(null);

        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));

    }

    @Test
    void testMediate_InvalidJwksUrlFromJwksEndpoint_ShouldThrowException() {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("invalid-url");

        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_InvalidJwksUrlFromJwksEndpointFromEnv_ShouldThrowException() {
        environmentVariables.set("JWKS_ENDPOINT", "invalid-url");
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("env:JWKS_ENDPOINT");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwksUrlFromJwksEndpointFromEnv_ShouldThrowException() {
        environmentVariables.set("JWKS_ENDPOINT", "");
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("env:JWKS_ENDPOINT");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ValidJwt_ShouldPass() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url-1.com,https://valid-url-2.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearer valid.jwt.token");

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);

        assertTrue(mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ValidJwtWithJwksTimeoutAndRefreshFromValue_ShouldPass() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url-1.com,https://valid-url-2.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearer valid.jwt.token");
        when(messageContext.getProperty(JWKS_TIMEOUT_PARAMETER_NAME)).thenReturn("30");
        when(messageContext.getProperty(JWKS_REFRESH_TIME_PARAMETER_NAME)).thenReturn("10");

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);

        assertTrue(mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ValidJwtWithJwksTimeoutAndRefreshFromEnv_ShouldPass() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url-1.com,https://valid-url-2.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearer valid.jwt.token");
        
        environmentVariables.set("JWKS_TIMEOUT", "60");
        environmentVariables.set("JWKS_REFRESH_TIME", "30");
        when(messageContext.getProperty(JWKS_TIMEOUT_PARAMETER_NAME)).thenReturn("env:JWKS_TIMEOUT");
        when(messageContext.getProperty(JWKS_REFRESH_TIME_PARAMETER_NAME)).thenReturn("env:JWKS_REFRESH_TIME");

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);

        assertTrue(mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ValidJwtWithJwksEndpointFromEnvVar_ShouldPass() throws Exception {
        environmentVariables.set("JWKS_ENDPOINT", "https://valid-url-1.com,https://valid-url-2.com");
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("env:JWKS_ENDPOINT");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearer valid.jwt.token");

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);

        assertTrue(mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ValidJwtWithClaimsFromValue_ShouldPass() throws Exception {

        // Set expected claims
        String expectedIat = "1600";
        String expectedIss = "expected-iss";
        String expectedSub = "expected-sub";
        String expectedAud = "expected-aud";
        String expectedJti = "true";

        // Capture the actual claims map passed to areClaimsValid
        ArgumentCaptor<HashMap<String, String>> claimsCaptor = ArgumentCaptor.forClass(HashMap.class);

        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url-1.com,https://valid-url-2.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearer valid.jwt.token");
        when(messageContext.getProperty(IAT_CLAIM_PARAMETER_NAME)).thenReturn(expectedIat);
        when(messageContext.getProperty(ISS_CLAIM_PARAMETER_NAME)).thenReturn(expectedIss);
        when(messageContext.getProperty(SUB_CLAIM_PARAMETER_NAME)).thenReturn(expectedSub);
        when(messageContext.getProperty(AUD_CLAIM_PARAMETER_NAME)).thenReturn(expectedAud);
        when(messageContext.getProperty(JTI_CLAIM_PARAMETER_NAME)).thenReturn(expectedJti);

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);
        when(jwtValidator.areClaimsValid(any(),claimsCaptor.capture())).thenReturn(true);

        assertTrue(mediator.mediate(messageContext));
        // Verify the claims map contains the expected values
        HashMap<String, String> capturedClaims = claimsCaptor.getValue();
        assertEquals(expectedIat, capturedClaims.get("iat"), "Expected 'iat' claim does not match");
        assertEquals(expectedIss, capturedClaims.get("iss"), "Expected 'iss' claim does not match");
        assertEquals(expectedSub, capturedClaims.get("sub"), "Expected 'sub' claim does not match");
        assertEquals(expectedAud, capturedClaims.get("aud"), "Expected 'aud' claim does not match");
        assertEquals(expectedJti, capturedClaims.get("jti"), "Expected 'jti' claim does not match");
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ExpiredJwt_ShouldThrowException() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearer valid.jwt.token");

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mockJwt);
        when(jwtValidator.isTokenExpired(mockJwt)).thenReturn(true);

        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwt_ShouldThrowException() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn(null);
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwtBearerPrefix_ShouldThrowException() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("valid.jwt.token");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwtAfterBearerPrefix_ShouldThrowException() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearer");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @Test
    void testMediate_MissingJwtAfterBearerPrefixWithSpace_ShouldThrowException() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearers");
        assertThrows(RuntimeException.class, () -> mediator.mediate(messageContext));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testMediate_ForwardTokenEnabled_ShouldSetHeader() throws Exception {
        when(messageContext.getProperty(JWKS_ENDPOINT_PARAMETER_NAME)).thenReturn("https://valid-url.com");
        when(messageContext.getProperty(JWT_TOKEN_PARAMETER_NAME)).thenReturn("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30");
        when(messageContext.getProperty(FORWARD_TOKEN_PARAMETER_NAME)).thenReturn("true");

        when(jwtValidator.validateToken(anyString(), any(ArrayList.class))).thenReturn(mock(SignedJWT.class));
        when(jwtValidator.isTokenExpired(any())).thenReturn(false);

        mediator.mediate(messageContext);

        assertTrue(mediator.mediate(messageContext));
    }

}