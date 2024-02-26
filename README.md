# wso2-mi-jwt-validator
The ws02-mi-jwt-validator is a custom handler and mediator for the WSO2 Micro Integrator. This class can be used to validate JWT tokens against a JWKS endpoint. The class can be used as a custom handler or as a custom mediator. The following example shows how to use the class as a custom handler and mediator.

The wso2-mi-jwt-validator is available on the Maven Central Repository. You can find the latest version [here](https://s01.oss.sonatype.org/service/local/repositories/releases/content/io/integon/wso2mi/jwt/wso2-mi-jwt-validator/1.1.4).


## Setup
### With pom.xml
Add the following dependencies to your pom.xml file:
```xml
<dependency>
  <groupId>io.integon.wso2mi.jwt</groupId>
  <artifactId>wso2-mi-jwt-validator</artifactId>
  <version>1.1.4</version>
</dependency>
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.37.3</version>
</dependency>
```

These dependencies are required for the wso2-mi-jwt-validator to work. The wso2-mi-jwt-validator uses the nimbus-jose-jwt library to validate the JWT token.

### Without pom.xml
Add the following .jar Files to the MI Folder "/home/wso2carbon/wso2mi-{version}/lib"
- wso2-mi-jwt-validator-1.1.3.jar (or the latest version)
- nimbus-jose-jwt-9.30.1.jar (or the latest version)

Both .jar files are available on the Maven Central Repository. You can find the latest version [here](https://s01.oss.sonatype.org/service/local/repositories/releases/content/io/integon/wso2mi/jwt/wso2-mi-jwt-validator/1.1.3/wso2-mi-jwt-validator-1.1.3.jar) and [here](https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt).

## Usage
### Available Properties (Custom Handler)
| Parameter Name  | Description                                                  | How to refrence                                              |
| --------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| jwtHeader       | The name of the header that contains the JWT Token.          | ```<property name="jwtHeader" value="Authorization"/>```     |
| iatClaim        | The value in seconds will be used to test if the jwt token is not older than the provided value. | ```<property name="iatClaim" value="1800"/>```<br>```<property name="iatClaim" value=""/>``` |
| issClaim        | The value of the iss claim that is expected to be present in the JWT Token. | ```<property name="issClaim" value="issuer"/>```<br>```<property name="issClaim" value=""/>``` |
| subClaim        | The value of the sub claim that is expected to be present in the JWT Token. | ```<property name="subClaim" value="subject"/>```<br>```<property name="subClaim" value=""/>``` |
| audClaim        | The value of the aud claim that is expected to be present in the JWT Token. | ```<property name="audClaim" value="audience"/>```<br>```<property name="audClaim" value=""/>``` |
| jtiClaim        | If the jti claim set to "enabled", the jti claim will be checked against a cache and will be denied if the same Token has already been used. | ```<property name="jtiClaim" value="enabled"/>```            |
| jwksEndpoint    | The URL of the JWKS Endpoint.                                | ```<property name="jwksEndpoint" value="https://apim.ch/oauth2/jwks"/>``` |
| jwksEnvVariable | The name of the environment variable that contains the URL of the JWKS Endpoint. | ```<property name="jwksEnvVariable" value="jwksEndpoint"/>``` |
| jwksTimeout     | The timeout in seconds for the JWKS Endpoint Caching.        | ```<property name="jwksTimeout" value="30"/>```<br>```<property name="jwksTimeout" value=""/>``` |
| jwksRefreshTime | The time in seconds after which the JWKS Endpoint is refreshed. | ```<property name="jwksRefreshTime" value="15"/>```<br>```<property name="jwksRefreshTime" value=""/>``` |
| forwardToken    | If set to 'true' the decoded JWT will be set to the message context property 'X-JWT' in json. | ```<property name="forwardToken" value="true"/>```           |


The following Parameters can be left empty:
- jwksEndpoint (IF jwksEnvVariable is set)
- jwksEnvVariable (IF jwksEndpoint is set)
- iatClaim (Claim will not be checked)
- issClaim (Claim will not be checked)
- subClaim (Claim will not be checked)
- audClaim (Claim will not be checked)
- jtiClaim (Claim will not be checked)
- jwksTimeout (default will be set: 6000)
- jwksRefreshTime (default will be set: 3000)

### Available Properties (Custom Mediator)
| Parameter Name  | Description                                                  | How to refrence                                              |
| --------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| jwtToken        | The jwt token that is to be validated.                       | ```<property name="jwtToken" expression="$trp:Authorization"/>```<br>```<property name="jwtToken" expression="$ctx:jwt"/>``` |
| iatClaim        | The value in seconds will be used to test if the jwt token is not older than the provided value. | ```<property name="iatClaim" value="1800"/>```<br>```<property name="iatClaim" value=""/>``` |
| issClaim        | The value of the iss claim that is expected to be present in the JWT Token. | ```<property name="issClaim" value="issuer"/>```<br>```<property name="issClaim" value=""/>``` |
| subClaim        | The value of the sub claim that is expected to be present in the JWT Token. | ```<property name="subClaim" value="subject"/>```<br>```<property name="subClaim" value=""/>``` |
| audClaim        | The value of the aud claim that is expected to be present in the JWT Token. | ```<property name="audClaim" value="audience"/>```<br>```<property name="audClaim" value=""/>``` |
| jtiClaim        | If the jti claim set to "enabled", the jti claim will be checked against a cache and will be denied if the same Token has already been used. | ```<property name="jtiClaim" value="enabled"/>```            |
| jwksEndpoint    | The URL of the JWKS Endpoint.                                | ```<property name="jwksEndpoint" value="https://apim.ch/oauth2/jwks"/>``` |
| jwksEnvVariable | The name of the environment variable that contains the URL of the JWKS Endpoint. | ```<property name="jwksEnvVariable" value="jwksEndpoint"/>``` |
| jwksTimeout     | The timeout in seconds for the JWKS Endpoint Caching.        | ```<property name="jwksTimeout" value="30"/>```<br>```<property name="jwksTimeout" value=""/>``` |
| jwksRefreshTime | The time in seconds after which the JWKS Endpoint is refreshed. | ```<property name="jwksRefreshTime" value="15"/>```<br/>```<property name="jwksRefreshTime" value=""/>``` |
| forwardToken    | If set to 'true' the decoded JWT will be set to the message context property 'X-JWT' in json. | ```<property name="forwardToken" value="true"/>```           |
| respond         | If set to 'true' the mediator will respond without triggering the faultSequence. | ```<property name="respond" value="true"/>```                |

The following Parameters can be left empty:
- jwksEndpoint (IF jwksEnvVariable is set)
- jwksEnvVariable (IF jwksEndpoint is set)
- iatClaim (Claim will not be checked)
- issClaim (Claim will not be checked)
- subClaim (Claim will not be checked)
- audClaim (Claim will not be checked)
- jtiClaim (Claim will not be checked)
- jwksTimeout (default will be set: 6000)
- jwksRefreshTime (default will be set: 3000)
- forwardToken (default: false)
- respond (default: false)

### Examples
#### Engage JWT Handler for MI APIs
The following examples show how to engage the JWT Handler for MI APIs. Use Cases:
- JWKS as a URL
- JWKS as an Environment Variable
- With JWKS Timeout and JWKS Refresh Time
- With Claim Checks

##### JKWS as a URL
```
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse" trace="enable" statistics="enable">
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
##### JKWS as an Environment Variable
```
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse" trace="enable" statistics="enable">
      <resource methods="GET" uri-template="/">
            ...
      </resource>
      <handlers>
            <handler class="io.integon.JwtAuthHandler">
                  <property name="jwtHeader" value="Authorization"/>
                  <property name="jwksEnvVariable" value="jwksEndpoint"/>
            </handler>
      </handlers>
</api>
```
##### With JWKS Timeout and JWKS Refresh Time
```
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse" trace="enable" statistics="enable">
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
##### With Claim Checks
``` 
<api context="/jwtHealth" name="jwt-health-api" xmlns="http://ws.apache.org/ns/synapse" trace="enable" statistics="enable">
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

#### Engage JWT Mediator for Micro Integrator
The following examples show how to engage the JWT Handler for MI APIs. Use Cases:
- JWKS as a URL
- JWKS as an Environment Variable
- JWKS with Timeout and Refresh Time
- With Claim Checks
##### JWKS as a URL
```
<proxy xmlns="http://ws.apache.org/ns/synapse" name="jwt-auth-mi" transports="http https" startOnLoad="true">
	<description>JWT Mediator Test Proxy</description>
	<target>
		<inSequence>
            <propertyGroup name="jwt-auth-mi">
                  <property name="jwtToken" expression="$trp:Authorization"/>
                  <property name="jwksEndpoint" value="https://apim-dev.ch/oauth2/jwks"/>
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            ....
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
##### JWKS as an Environment Variable
```
<proxy xmlns="http://ws.apache.org/ns/synapse" name="jwt-auth-mi" transports="http https" startOnLoad="true">
	<description>JWT Mediator Test Proxy</description>
	<target>
		<inSequence>
            <propertyGroup name="jwt-auth-mi">
                  <property name="jwtToken" expression="$trp:Authorization"/>
                  <property name="jwksEnvVariable" value="jwksEndpoint"/>
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            ....
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
##### JWKS with Timeout and Refresh Time
```
<proxy xmlns="http://ws.apache.org/ns/synapse" name="jwt-auth-mi" transports="http https" startOnLoad="true">
	<description>JWT Mediator Test Proxy</description>
	<target>
		<inSequence>
            <propertyGroup name="jwt-auth-mi">
                  <property name="jwtToken" expression="$trp:Authorization"/>
                  <property name="jwksEnvVariable" value="jwksEndpoint"/>
                  <property name="jwksTimeout" value="3000"/>
		      <property name="jwksRefreshTime" value="1000"/>
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            ....
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
##### With Claim Checks
```
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
                  <property name="jwksEnvVariable" value="jwksEndpoint"/>
            </propertyGroup>
            <class name="io.integon.JwtAuthMediator"/>
            ....
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

