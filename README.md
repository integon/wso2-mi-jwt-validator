# wso2-mi-jwt-validator
The wso2-mi-jwt-validator is a custom handler and mediator for the WSO2 Micro Integrator. This class validates JWT tokens against one or more JWKS endpoints and can be used as either a custom handler or a custom mediator.

Latest version: [1.3.1 on Maven Central Repository](https://s01.oss.sonatype.org/service/local/repositories/releases/content/io/integon/wso2mi/jwt/wso2-mi-jwt-validator/1.3.1)

## Table of Contents
- [wso2-mi-jwt-validator](#wso2-mi-jwt-validator)
  - [Table of Contents](#table-of-contents)
  - [Setup](#setup)
    - [With pom.xml](#with-pomxml)
    - [Without pom.xml](#without-pomxml)
  - [Usage](#usage)
    - [Available Properties (Custom Handler)](#available-properties-custom-handler)
    - [Available Properties (Custom Mediator)](#available-properties-custom-mediator)
  - [Examples](#examples)
    - [Engage JWT Handler for MI APIs](#engage-jwt-handler-for-mi-apis)
      - [Basic JWKS URL Configuration](#basic-jwks-url-configuration)
      - [Environment Variable Configuration](#environment-variable-configuration)
      - [With Cache Configuration](#with-cache-configuration)
      - [With Claim Validation](#with-claim-validation)
      - [With Claim Validation Using Environment Variables](#with-claim-validation-using-environment-variables)
      - [Multiple JWKS Endpoints](#multiple-jwks-endpoints)
    - [Engage JWT Mediator for Micro Integrator](#engage-jwt-mediator-for-micro-integrator)
      - [Basic Configuration](#basic-configuration)
      - [With Environment Variables](#with-environment-variables)
      - [With Cache Configuration](#with-cache-configuration-1)
      - [With Claim Validation](#with-claim-validation-1)
      - [Multiple JWKS Endpoints](#multiple-jwks-endpoints-1)
  - [Enable Debug Logs](#enable-debug-logs)

## Setup

### With pom.xml
Add the following dependencies to your pom.xml file:
```xml
<dependency>
  <groupId>io.integon.wso2mi.jwt</groupId>
  <artifactId>wso2-mi-jwt-validator</artifactId>
  <version>1.3.1</version>
</dependency>
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>10.0.1</version>
</dependency>
```

The wso2-mi-jwt-validator relies on the nimbus-jose-jwt library for JWT validation.

### Without pom.xml
Add these JAR files to the MI directory "/home/wso2carbon/wso2mi-{version}/lib":
- wso2-mi-jwt-validator-1.3.1.jar (or latest version)
- nimbus-jose-jwt-10.0.1.jar (or latest version)

Download links:
- [wso2-mi-jwt-validator-1.3.1.jar](https://s01.oss.sonatype.org/service/local/repositories/releases/content/io/integon/wso2mi/jwt/wso2-mi-jwt-validator/1.3.1/wso2-mi-jwt-validator-1.3.1.jar)
- [nimbus-jose-jwt](https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt)

## Usage

### Available Properties (Custom Handler)

| Parameter Name  | Description                                                  | Examples                                              |
| --------------- | ------------------------------------------------------------ | ----------------------------------------------------- |
| jwtHeader       | Header name containing the JWT Token. | `<property name="jwtHeader" value="Authorization"/>` <br> `<property name="jwtHeader" value="env:JWT_HEADER"/>` |
| iatClaim        | Maximum token age in seconds. | `<property name="iatClaim" value="1800"/>` <br> `<property name="iatClaim" value="env:IAT_CLAIM"/>` <br> `<property name="iatClaim" value=""/>` |
| issClaim        | Regex for issuer claim. Multiple values: `^(myiss1\|myiss2\|myiss3)$` | `<property name="issClaim" value="issuer"/>` <br> `<property name="issClaim" value="env:ISS_CLAIM"/>` <br> `<property name="issClaim" value=""/>` |
| subClaim        | Expected subject claim. | `<property name="subClaim" value="subject"/>` <br> `<property name="subClaim" value="env:SUB_CLAIM"/>` <br> `<property name="subClaim" value=""/>` |
| audClaim        | Expected audience claim. | `<property name="audClaim" value="audience"/>` <br> `<property name="audClaim" value="env:AUD_CLAIM"/>` <br> `<property name="audClaim" value=""/>` |
| jtiClaim        | Set to "enabled" to verify token uniqueness using cache. | `<property name="jtiClaim" value="enabled"/>` <br> `<property name="jtiClaim" value="env:JTI_CLAIM"/>` |
| jwksEndpoint    | JWKS endpoint URL(s) or environment variable. Multiple endpoints use comma separation. | `<property name="jwksEndpoint" value="https://example.com/oauth2/jwks"/>` <br> `<property name="jwksEndpoint" value="env:JWKS_ENDPOINT"/>` |
| jwksTimeout     | Timeout in seconds for JWKS endpoint caching. | `<property name="jwksTimeout" value="30"/>` <br> `<property name="jwksTimeout" value="env:JWKS_TIMEOUT"/>` |
| jwksRefreshTime | Time in seconds after which the JWKS endpoint is refreshed. | `<property name="jwksRefreshTime" value="15"/>` <br> `<property name="jwksRefreshTime" value="env:JWKS_REFRESH_TIME"/>` |
| forwardToken    | If 'true', decoded JWT payload is set as 'X-JWT' property. | `<property name="forwardToken" value="true"/>` <br> `<property name="forwardToken" value="env:FORWARD_TOKEN"/>` |

**Note:** All properties can be specified directly or via environment variables using the `env:` prefix.

**Optional parameters:**
- All claim checks (iatClaim, issClaim, subClaim, audClaim, jtiClaim) - claims not specified will not be checked
- jwksTimeout (default: 6000)
- jwksRefreshTime (default: 3000)
- forwardToken (default: false)

### Available Properties (Custom Mediator)

| Parameter Name  | Description                                                  | Examples                                              |
| --------------- | ------------------------------------------------------------ | ----------------------------------------------------- |
| jwtToken        | JWT token to validate. | `<property name="jwtToken" expression="$trp:Authorization"/>` <br> `<property name="jwtToken" expression="$ctx:jwt"/>` |
| iatClaim        | Maximum token age in seconds. | `<property name="iatClaim" value="1800"/>` <br> `<property name="iatClaim" value="env:IAT_CLAIM"/>` <br> `<property name="iatClaim" value=""/>` |
| issClaim        | Regex for issuer claim. Multiple values: `^(myiss1\|myiss2\|myiss3)$` | `<property name="issClaim" value="issuer"/>` <br> `<property name="issClaim" value="env:ISS_CLAIM"/>` <br> `<property name="issClaim" value=""/>` |
| subClaim        | Expected subject claim. | `<property name="subClaim" value="subject"/>` <br> `<property name="subClaim" value="env:SUB_CLAIM"/>` <br> `<property name="subClaim" value=""/>` |
| audClaim        | Expected audience claim. | `<property name="audClaim" value="audience"/>` <br> `<property name="audClaim" value="env:AUD_CLAIM"/>` <br> `<property name="audClaim" value=""/>` |
| jtiClaim        | Set to "enabled" to verify token uniqueness using cache. | `<property name="jtiClaim" value="enabled"/>` <br> `<property name="jtiClaim" value="env:JTI_CLAIM"/>` |
| jwksEndpoint    | JWKS endpoint URL(s) or environment variable. Multiple endpoints use comma separation. | `<property name="jwksEndpoint" value="https://example.com/oauth2/jwks"/>` <br> `<property name="jwksEndpoint" value="env:JWKS_ENDPOINT"/>` |
| jwksTimeout     | Timeout in seconds for JWKS endpoint caching. | `<property name="jwksTimeout" value="30"/>` <br> `<property name="jwksTimeout" value="env:JWKS_TIMEOUT"/>` |
| jwksRefreshTime | Time in seconds after which the JWKS endpoint is refreshed. | `<property name="jwksRefreshTime" value="15"/>` <br> `<property name="jwksRefreshTime" value="env:JWKS_REFRESH_TIME"/>` |
| forwardToken    | If 'true', decoded JWT payload is set as 'X-JWT' property. | `<property name="forwardToken" value="true"/>` <br> `<property name="forwardToken" value="env:FORWARD_TOKEN"/>` |
| respond         | If 'true', mediator responds without triggering faultSequence. | `<property name="respond" value="true"/>` <br> `<property name="respond" value="env:RESPOND"/>` |

**Note:** All properties can be specified directly or via environment variables using the `env:` prefix.

**Optional parameters:**
- All claim checks (iatClaim, issClaim, subClaim, audClaim, jtiClaim) - claims not specified will not be checked
- jwksTimeout (default: 6000)
- jwksRefreshTime (default: 3000)
- forwardToken (default: false)
- respond (default: false)

## Examples

### Engage JWT Handler for MI APIs

#### Basic JWKS URL Configuration
```xml
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse">
      <resource methods="GET" uri-template="/">
            ...
      </resource>
      <handlers>
            <handler class="io.integon.JwtAuthHandler">
                  <property name="jwtHeader" value="Authorization"/>
                  <property name="jwksEndpoint" value="https://apim.ch/oauth2/jwks"/>
            </handler>
      </handlers>
</api>
```

#### Environment Variable Configuration
```xml
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse">
      <resource methods="GET" uri-template="/">
            ...
      </resource>
      <handlers>
            <handler class="io.integon.JwtAuthHandler">
                  <property name="jwtHeader" value="env:JWT_HEADER"/>
                  <property name="jwksEndpoint" value="env:JWKS_ENDPOINT"/>
            </handler>
      </handlers>
</api>
```

#### With Cache Configuration
```xml
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse">
      <resource methods="GET" uri-template="/">
            ...
      </resource>
      <handlers>
            <handler class="io.integon.JwtAuthHandler">
                  <property name="jwtHeader" value="Authorization"/>
                  <property name="jwksEndpoint" value="https://apim.ch/oauth2/jwks"/>
                  <property name="jwksTimeout" value="30"/>
                  <property name="jwksRefreshTime" value="15"/>
            </handler>
      </handlers>
</api>
```

#### With Claim Validation
```xml
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse">
      <resource methods="GET" uri-template="/">
            ...
      </resource>
      <handlers>
            <handler class="io.integon.JwtAuthHandler">
                  <property name="jwtHeader" value="Authorization"/>
                  <property name="jwksEndpoint" value="https://apim.ch/oauth2/jwks"/>
                  <property name="iatClaim" value="1800"/>
                  <property name="issClaim" value="issuer"/>
                  <property name="subClaim" value="subject"/>
                  <property name="audClaim" value="audience"/>
                  <property name="jtiClaim" value="enabled"/>
            </handler>
      </handlers>
</api>
```

#### With Claim Validation Using Environment Variables
```xml
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse">
      <resource methods="GET" uri-template="/">
            ...
      </resource>
      <handlers>
            <handler class="io.integon.JwtAuthHandler">
                  <property name="jwtHeader" value="Authorization"/>
                  <property name="jwksEndpoint" value="https://apim.ch/oauth2/jwks"/>
                  <property name="iatClaim" value="env:IAT_MAX_AGE"/>
                  <property name="issClaim" value="env:EXPECTED_ISSUER"/>
                  <property name="subClaim" value="env:EXPECTED_SUBJECT"/>
                  <property name="audClaim" value="env:EXPECTED_AUDIENCE"/>
                  <property name="jtiClaim" value="env:JTI_CHECK"/>
            </handler>
      </handlers>
</api>
```

#### Multiple JWKS Endpoints
```xml
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse">
      <resource methods="GET" uri-template="/">
            ...
      </resource>
      <handlers>
            <handler class="io.integon.JwtAuthHandler">
                  <property name="jwtHeader" value="Authorization"/>
                  <property name="jwksEndpoint" value="https://apim.ch/oauth2/jwks,https://apim-test.ch/oauth2/jwks"/>
            </handler>
      </handlers>
</api>
```

### Engage JWT Mediator for Micro Integrator

#### Basic Configuration
```xml
<proxy xmlns="http://ws.apache.org/ns/synapse" name="jwt-auth-mi" transports="http https" startOnLoad="true">
      <description>JWT Mediator Test Proxy</description>
      <target>
            <inSequence>
            <propertyGroup name="jwt-auth-mi">
                  <property name="jwtToken" expression="$trp:Authorization"/>
                  <property name="jwksEndpoint" value="https://apim-dev.ch/oauth2/jwks"/>
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            <!-- Your sequence continues here -->
            </inSequence>
            <faultSequence>
                  <log level="custom" category="ERROR">
                        <property name="jwt-auth-mi" value="faultSequence" />
                        <property name="ERROR_CODE" expression="$ctx:ERROR_CODE"/>
                        <property name="ERROR_MESSAGE" expression="$ctx:ERROR_MESSAGE"/>
                  </log>
            <property name="HTTP_SC" expression="$ctx:ERROR_CODE" scope="axis2"/>
                  <respond/>	
            </faultSequence>
      </target>
</proxy>
```

#### With Environment Variables
```xml
<proxy xmlns="http://ws.apache.org/ns/synapse" name="jwt-auth-mi" transports="http https" startOnLoad="true">
      <description>JWT Mediator Test Proxy</description>
      <target>
            <inSequence>
            <propertyGroup name="jwt-auth-mi">
                  <property name="jwtToken" expression="$trp:Authorization"/>
                  <property name="jwksEndpoint" value="env:JWKS_ENDPOINT"/>
                  <property name="iatClaim" value="env:IAT_MAX_AGE" />
                  <property name="issClaim" value="env:EXPECTED_ISSUER" />
                  <property name="subClaim" value="env:EXPECTED_SUBJECT" />
                  <property name="audClaim" value="env:EXPECTED_AUDIENCE" />
                  <property name="jtiClaim" value="env:JTI_CHECK" />
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            <!-- Your sequence continues here -->
            </inSequence>
            <faultSequence>
                  <!-- Error handling -->
            </faultSequence>
      </target>
</proxy>
```

#### With Cache Configuration
```xml
<proxy xmlns="http://ws.apache.org/ns/synapse" name="jwt-auth-mi" transports="http https" startOnLoad="true">
      <description>JWT Mediator Test Proxy</description>
      <target>
            <inSequence>
            <propertyGroup name="jwt-auth-mi">
                  <property name="jwtToken" expression="$trp:Authorization"/>
                  <property name="jwksEndpoint" value="env:JWKS_ENDPOINT"/>
                  <property name="jwksTimeout" value="3000"/>
                  <property name="jwksRefreshTime" value="1000"/>
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            <!-- Your sequence continues here -->
            </inSequence>
            <faultSequence>
                  <!-- Error handling -->
            </faultSequence>
      </target>
</proxy>
```

#### With Claim Validation
```xml
<proxy xmlns="http://ws.apache.org/ns/synapse" name="jwt-auth-mi" transports="http https" startOnLoad="true">
      <description>JWT Mediator Test Proxy</description>
      <target>
            <inSequence>
            <propertyGroup name="jwt-auth-mi">
                  <property name="jwtToken" expression="$trp:Authorization"/>
                  <property name="iatClaim" expression="$trp:test" />
                  <property name="issClaim" value="https://apim-dev.integon.ch:443/oauth2/token" />
                  <property name="subClaim" value="admin" />
                  <property name="audClaim" value="Y3wBS2AsdgHW6z2GfEfUpairc_Ma" />
                  <property name="jtiClaim" value="enabled" />
                  <property name="jwksEndpoint" value="env:JWKS_ENDPOINT"/>
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            <!-- Your sequence continues here -->
            </inSequence>
            <faultSequence>
                  <!-- Error handling -->
            </faultSequence>
      </target>
</proxy>
```

#### Multiple JWKS Endpoints
```xml
<proxy xmlns="http://ws.apache.org/ns/synapse" name="jwt-auth-mi" transports="http https" startOnLoad="true">
      <description>JWT Mediator Test Proxy</description>
      <target>
            <inSequence>
            <propertyGroup name="jwt-auth-mi">
                  <property name="jwtToken" expression="$trp:Authorization"/>
                  <property name="jwksEndpoint" value="https://apim-dev.ch/oauth2/jwks,https://apim-test.ch/oauth2/jwks"/>
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            <!-- Your sequence continues here -->
            </inSequence>
            <faultSequence>
                  <!-- Error handling -->
            </faultSequence>
      </target>
</proxy>
```

## Enable Debug Logs

To enable debugging for the JWT validator, add the following to "../mi-home/conf/log4j2.properties":

```properties
logger.JwtAuthMediator.name = io.integon.JwtAuthMediator
logger.JwtAuthMediator.level = DEBUG

logger.JwtAuthHandler.name = io.integon.JwtAuthHandler
logger.JwtAuthHandler.level = DEBUG
```

Then add these loggers to the list of loggers:

```properties
loggers = ..., ..., ..., JwtAuthMediator, JwtAuthHandler
```
