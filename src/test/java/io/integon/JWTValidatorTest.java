package io.integon;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

@ExtendWith(MockitoExtension.class)
class JwtValidatorTest {

        @InjectMocks
        private JWTValidator jwtValidator;

        private static PublicKey publicKey1;
        private static PrivateKey privateKey1;

        private static PublicKey publicKey2;
        private static PrivateKey privateKey2;

        private static Integer JWKS_PORT_1 = 8098;
        private static Integer JWKS_PORT_2 = 8099;

        private static WireMockServer wireMockServer1;
        private static WireMockServer wireMockServer2;

        @BeforeAll
        static void setUp() throws Exception {
                // Generate an RSA key pair
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);

                KeyPair keyPair1 = keyGen.generateKeyPair();
                privateKey1 = keyPair1.getPrivate();
                publicKey1 = keyPair1.getPublic();

                KeyPair keyPair2 = keyGen.generateKeyPair();
                privateKey2 = keyPair2.getPrivate();
                publicKey2 = keyPair2.getPublic();

                // Create a JWK from the public key
                // jwk = new RSAKey.Builder((java.security.interfaces.RSAPublicKey)
                // realPublicKey)
                // .privateKey(privateKey1) // Only used for signing
                // .keyID("test-key")
                // .algorithm(JWSAlgorithm.RS256)
                // .build();

                wireMockServer1 = new WireMockServer(WireMockConfiguration.options().port(JWKS_PORT_1));
                RSAKey rsaKey1 = new RSAKey.Builder((RSAPublicKey) publicKey1)
                                .keyID("mock1")
                                .build();

                wireMockServer2 = new WireMockServer(WireMockConfiguration.options().port(JWKS_PORT_2));
                RSAKey rsaKey2 = new RSAKey.Builder((RSAPublicKey) publicKey2)
                                .keyID("mock2")
                                .build();

                // Create the JWKS JSON with the "keys" array
                String jwksJson1 = "{\"keys\": [" + rsaKey1.toJSONString() + "]}";
                String jwksJson2 = "{\"keys\": [" + rsaKey2.toJSONString() + "]}";
                // Stub the JWKS URL response
                wireMockServer1.stubFor(get("/jwks")
                                .willReturn(aResponse()
                                                .withStatus(200)
                                                .withHeader("Content-Type", "application/json")
                                                .withBody(jwksJson1)));

                // Stub the JWKS URL response
                wireMockServer2.stubFor(get("/jwks")
                                .willReturn(aResponse()
                                                .withStatus(200)
                                                .withHeader("Content-Type", "application/json")
                                                .withBody(jwksJson2)));
                wireMockServer1.start();
                wireMockServer2.start();
        }

        @AfterAll
        static void tearDown() {
                // Stop WireMock manually after the test
                if (wireMockServer1 != null) {
                        wireMockServer1.stop();
                }
                if (wireMockServer2 != null) {
                        wireMockServer2.stop();
                }
        }

        @Test
        void validateToken_WithValidJwtAndMockedJWKS_ShouldReturnTrue() throws Exception {
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();
                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder().build());
                signedJWT.sign(new RSASSASigner(privateKey1));

                ArrayList<URL> jwksUrls = new ArrayList<>();
                jwksUrls.add(new URL("http://localhost:" + JWKS_PORT_1 + "/jwks"));

                SignedJWT result = jwtValidator.validateToken(signedJWT.serialize(), jwksUrls);

                // Assert
                assertThat(result).isNotNull(); // Assert that the returned JWT is not null
                assertThat(result).isInstanceOf(SignedJWT.class);

        }

        @Test
        void validateToken_WithValidJwtAndMultipleMockedJWKS_ShouldReturnTrue() throws Exception {
                JWSHeader header1 = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();
                JWSHeader header2 = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock2") // Matches the JWKS key ID
                                .build();
                SignedJWT signedJWT1 = new SignedJWT(header1,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder().build());
                signedJWT1.sign(new RSASSASigner(privateKey1));

                SignedJWT signedJWT2 = new SignedJWT(header2,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder().build());
                signedJWT2.sign(new RSASSASigner(privateKey2));

                ArrayList<URL> jwksUrls = new ArrayList<>();
                jwksUrls.add(new URL("http://localhost:" + JWKS_PORT_1 + "/jwks"));
                jwksUrls.add(new URL("http://localhost:" + JWKS_PORT_2 + "/jwks"));

                SignedJWT result1 = jwtValidator.validateToken(signedJWT1.serialize(), jwksUrls);
                SignedJWT result2 = jwtValidator.validateToken(signedJWT2.serialize(), jwksUrls);

                // Assert
                assertThat(result1).isNotNull(); // Assert that the returned JWT is not null
                assertThat(result1).isInstanceOf(SignedJWT.class);
                assertThat(result2).isNotNull(); // Assert that the returned JWT is not null
                assertThat(result2).isInstanceOf(SignedJWT.class);

        }

        @Test
        void validateToken_WithInvalidJwtFormat_ShouldThrowException() throws MalformedURLException {
                ArrayList<URL> jwksUrls = new ArrayList<>();
                jwksUrls.add(new URL("http://localhost:" + JWKS_PORT_1 + "/jwks"));
                String invalidJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

                Throwable thrown = catchThrowable(() -> jwtValidator.validateToken(invalidJwt, jwksUrls));

                assertThat(thrown).isInstanceOf(Exception.class)
                                .hasMessageContaining("Invalid JWT token");
        }

        @Test
        void validateToken_WithInvalidJwtKeyId_ShouldThrowException() throws Exception {
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("invalid") // Matches the JWKS key ID
                                .build();
                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder().build());
                signedJWT.sign(new RSASSASigner(privateKey1));

                ArrayList<URL> jwksUrls = new ArrayList<>();
                jwksUrls.add(new URL("http://localhost:" + JWKS_PORT_1 + "/jwks"));

                Throwable thrown = catchThrowable(() -> jwtValidator.validateToken(signedJWT.serialize(), jwksUrls));

                assertThat(thrown).isInstanceOf(Exception.class)
                                .hasMessageContaining("Failed to validate JWT using the provided JWKS");
        }

        @Test
        void isExpired_WithActiveJwt_ShouldReturnFalse() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .subject("test-user")
                                                .expirationTime(new Date(System.currentTimeMillis() + 5 * 60 * 1000))
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                Boolean isExpired = jwtValidator.isTokenExpired(signedJWT);

                assertThat(isExpired).isFalse();
        }

        @Test
        void isExpired_WithExpiredJwt_ShouldReturnTrue() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .subject("test-user")
                                                .expirationTime(new Date(System.currentTimeMillis() - 5 * 60 * 1000))
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                Boolean isExpired = jwtValidator.isTokenExpired(signedJWT);

                assertThat(isExpired).isTrue();
        }

        @Test
        void areClaimsValid_WithValidClaimIat_ShouldReturnTrue() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .issueTime(new Date(System.currentTimeMillis() - 5 * 60 * 1000))
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("iat", String.valueOf(301)); // Issued at

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WithInvalidClaimIat_ShouldThrowException() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .issueTime(new Date(System.currentTimeMillis() - 5 * 60 * 1000))
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("iat", String.valueOf(299)); // Issued at

                Throwable thrown = catchThrowable(() -> jwtValidator.areClaimsValid(signedJWT, claims));

                assertThat(thrown).isInstanceOf(Exception.class)
                                .hasMessageContaining("JWT token issue time claim is too old");
        }

        @Test
        void areClaimsValid_WithValidClaimIss_ShouldReturnTrue() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .issuer("https://api.example.com/auth")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("iss", "https://api.example.com/auth"); // Issued at

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WithValidClaimIssMultipleValidIss_ShouldReturnTrue() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .issuer("https://api1.example.com/auth")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("iss",
                                "https://api1.example.com/auth|https://api2.example.com/auth|https://api3.example.com/auth");
                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WithInvalidClaimIss_ShouldThrowException() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1") // Matches the JWKS key ID
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .issuer("https://api.example.com/auth")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("iss", "https://api.example.com/invalid");

                Throwable thrown = catchThrowable(() -> jwtValidator.areClaimsValid(signedJWT, claims));

                assertThat(thrown).isInstanceOf(Exception.class)
                                .hasMessageContaining("JWT token issuer claim does not match the expected value");
        }

        @Test
        void areClaimsValid_WithValidClaimSub_ShouldReturnTrue() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .subject("user1")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("sub", "user1");

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WithValidClaimAudMultipleValidSub_ShouldReturnTrue() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .subject("user1")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("sub", "user1|user2|user3");

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WithInvalidClaimSub_ShouldThrowException() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .subject("user2")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("sub", "user1");

                Throwable thrown = catchThrowable(() -> jwtValidator.areClaimsValid(signedJWT, claims));

                assertThat(thrown).isInstanceOf(Exception.class)
                                .hasMessageContaining("JWT token subject claim does not match the expected value");
        }

        @Test
        void areClaimsValid_WithValidClaimAud_ShouldReturnTrue() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .audience("https://myapp.example.com")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("aud", "https://myapp.example.com");

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WithValidClaimAudMultipleValidAud_ShouldReturnTrue()
                        throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .audience("https://myapp1.example.com")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("aud",
                                "https://myapp1.example.com|https://myapp2.example.com|https://myapp3.example.com");

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WithInvalidClaimAud_ShouldThrowException() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .audience("https://myapp2.example.com")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("aud", "https://myapp1.example.com");

                Throwable thrown = catchThrowable(() -> jwtValidator.areClaimsValid(signedJWT, claims));

                assertThat(thrown).isInstanceOf(Exception.class)
                                .hasMessageContaining("JWT token audience claim does not match the expected value");
        }

        @Test
        void areClaimsValid_WhenJtiCheckDisabled_ShouldPass() throws Exception {
                // Mock JWT claims without JTI checking enabled
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                String jtiString = UUID.randomUUID().toString();
                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .jwtID(jtiString)
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("jti", "false");

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WhenJtiCheckEnabled_ShouldPass() throws Exception {
                // Mock JWT claims without JTI checking enabled
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                String jtiString = UUID.randomUUID().toString();
                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .jwtID(jtiString)
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("jti", "enabled");

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WhenJtiCheckEnabledAndTokenUsedTwice_ShouldThrowException() throws Exception {
                // Mock JWT claims without JTI checking enabled
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                String jtiString = UUID.randomUUID().toString();
                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .jwtID(jtiString)
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("jti", "enabled");

                jwtValidator.areClaimsValid(signedJWT, claims);
                Throwable thrown = catchThrowable(() -> jwtValidator.areClaimsValid(signedJWT, claims));

                assertThat(thrown).isInstanceOf(Exception.class)
                                .hasMessageContaining("JWT with this JWT ID has already been used");
        }

        @Test
        void areClaimsValid_WithValidCustomClaims_ShouldReturnTrue() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .claim("role", "user")
                                                .claim("location", "Bern")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("role", "user|admin");
                claims.put("location", "Bern|Zurich");

                Boolean areClaimsValid = jwtValidator.areClaimsValid(signedJWT, claims);

                assertThat(areClaimsValid).isTrue();
        }

        @Test
        void areClaimsValid_WithInvalidCustomClaims_ShouldThrowException() throws Exception {
                // Generate an expired JWT
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID("mock1")
                                .build();

                SignedJWT signedJWT = new SignedJWT(header,
                                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                                                .claim("role", "user")
                                                .claim("location", "Bern")
                                                .build());

                signedJWT.sign(new RSASSASigner(privateKey1));

                HashMap<String, String> claims = new HashMap<>();
                claims.put("role", "customer|admin");
                claims.put("location", "Bern|Zurich");

                Throwable thrown = catchThrowable(() -> jwtValidator.areClaimsValid(signedJWT, claims));
                
                assertThat(thrown).isInstanceOf(Exception.class)
                                .hasMessageContaining("JWT custom claim 'role' did not match expected pattern");
        }

        @Test
        void setCacheTimeouts_WhenJwksTimeoutAndjwksRefreshTimeAreNull_ShouldSetDefaultValues(){
                String jwksTimeout = null;
                String jwksRefreshTime = null;
                jwtValidator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);
                assertEquals(60 * 60 * 1000, jwtValidator.getTtl());
                assertEquals(30 * 60 * 1000, jwtValidator.getRefreshTimeout());
        }

        @Test
        void setCacheTimeouts_WhenJwksTimeoutAndjwksRefreshTimeAreNotLong_ShouldSetDefaultValues(){
                String jwksTimeout = "1.1";
                String jwksRefreshTime = "1.1";
                jwtValidator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);
                assertEquals(60 * 60 * 1000, jwtValidator.getTtl());
                assertEquals(30 * 60 * 1000, jwtValidator.getRefreshTimeout());
        }

        @Test
        void setCacheTimeouts_WhenJwksTimeoutAndjwksRefreshTimeAreLong_ShouldSetValues(){
                String jwksTimeout = "1800";
                String jwksRefreshTime = "900";
                jwtValidator.setCacheTimeouts(jwksTimeout, jwksRefreshTime);
                assertEquals(30 * 60 * 1000, jwtValidator.getTtl());
                assertEquals(15 * 60 * 1000, jwtValidator.getRefreshTimeout());
        }

}