# Spring Keycloak JWT auth example

OAuth2 und OpenID Connect haben sich zum standard in der Authentifizierung sowie in der Authorisierung entwickelt. Immer mehr wird auch Keycloak als Identity Provider eingesetzt. In diesem Beispiel möchte ich euch zeigen wie ihr einen vom Keycloak generierten JWT in einer Spring app für authentifizierung sowie authorisierung nutzen könnt.

# Table of Contents
1. [GET Endpunkt erstellen](#getendpoint)
2. [Authentifizierung](#Authentifizierung)
3. [Authorisierung](#Authorisierung)

## GET Endpunkt erstellen <a name="getendpoint"></a>

Zunächst einmal benötigen wir einen Endpunkt den wir absichern möchten. Hierzu können wir einen einfachen RestController schreiben. Bevor wir loslegen, hier noch die Abhängigkeiten die wir benötigen.

<details>
  <summary>Dependencies</summary>
  
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>

<dependency>
    <groupId>io.rest-assured</groupId>
    <artifactId>rest-assured</artifactId>
    <version>3.0.0</version>
    <scope>test</scope>
</dependency>

<dependency>
    <groupId>io.rest-assured</groupId>
    <artifactId>json-schema-validator</artifactId>
    <version>4.3.1</version>
</dependency>
```
    
</details>

<space></space>

Nachdem wir die Abhängigkeiten in die pom.xml hinzugefügt haben, können wir den RestController implementieren.

```java
@RestController
public class ExampleController {

    @RequestMapping(method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public String example(){

        return "hello world";
    }

}
```

Ich weiß, bis hierhin ist es noch sehr einfach. Aber lasst uns dennoch einen kleinen Test schreiben.

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthExampleApplicationTests {

    @LocalServerPort
    public int port;

    @Test
    void testAccessSecuredEndpoint_validJWT() {
        with().given().port(port).when().request("GET", "/").then().statusCode(HttpStatus.OK.value());
    }

}
```

Rest-Assured benutzen wir in unseren Tests um Rest-Requests gegen unsere Applikation zu senden. Später werden wir die Tests um Authentifizierung und Authorisierung erweitern.


## Authentifizierung

Jetzt wirds endlich interessant. Doch bevor wir starten müssen wir weitere Abhöngigkeiten laden:

<details>
    <summary>Dependencies</summary>

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

</details>

<space></space>

## Authorisierung