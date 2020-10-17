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

Da wir alle Aufrufe bereits vor unserem Restcontroller absichern möchten, werden wir einen Filter implementieren. Mit einem Filter können wir Requests vor sowie Responses nach unserem Restcontroller abfangen.

Bevor wir den Filter implementieren können, müssen wir die WebSecurityConfig erstellen. In der Konfiguration geben wir an, dass wir nur authentifizierte Aufrufe auf unsere Applikation zulassen. Da wir aber nicht die "BasicAuthentification" von Spring Security möchten, müssen wir die "BasicAuthentification" abschalten und einen Filter hinzufügen, welcher die Authentifizierung für uns übernimmt. Hier unsere Konfiguration mit dem Filter den wir im nächsten Schritt implementieren werden:

> Die "BasicAuthentification" schalten wir mit der folgenden Annotation aus: @EnableWebSecurity



```java 
@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/**")
                .authenticated().and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}
```

Wie ihr bemerkt habt, ist der Name unseres Filter wie foglt: "JWTAuthenticationFilter". Nun zu der Implementierung. Zunächst erstellen wir eine Klasse, welche von der Klasse BasicAuthenticationFilter abgeleitet wird. Dies ist notwendig, weil unser Filter vom Typ javax.servlet.filter sein muss. Später aber mehr dazu. 

```java
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }
}
```

Nachdem wir unseren Fitler erstellt haben, möchten wir nun folgendes Implementieren:

Zunäscht wollen das JWT aus dem "Authorization" Header lesen. Nachdem wir das JWT haben, möchten wir es dessen authentizität überprüfen. Dafür können wir den JwtParser aus dem io.jsonwebtoken package benutzen. Dafür muss der JwtParser wissen, wo der Schlüssel zum verifizieren des JWT ist. Ich gehe in diesem Beispiel davon aus, dass Keycloak den JWT mit seinem privaten schlüssel signiert hat. Um an den öffentlichen Schlüssel von Keycloak zu gelangen, bietet Keycloak einen Endpunkt an. Diese URL können wir nutzen um dan den öffentlichen Schlüssel zu gelangen. Nachdem wir unseren JwtParser konfiguriert haben, können wir nun unseren Token validieren:

```java
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    private URL wellKnownUrl = new URL("https://<url>/sec-api/auth/realms/<realm>/protocol/openid-connect/certs");

    private final JwkProvider provider;

    private final JwtParser jwtParser;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
        provider = new JwkProviderBuilder(wellKnownUrl)
                .cached(10, 24, TimeUnit.HOURS)
                .build();

        jwtParser = Jwts.parserBuilder().setSigningKeyResolver(new MyResolver()).build();
    }


    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {
        LOGGER.debug("received request: {}", request.getMethod());
        final String header = request.getHeader("Authorization");

        if (StringUtils.isEmpty(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwtParser.isSigned(token);
        filterChain.doFilter(request, response);
    }

    class MyResolver extends SigningKeyResolverAdapter {

        public Key resolveSigningKey(JwsHeader header, Claims claims) {
            try {
                return provider.get(header.getKeyId()).getPublicKey();
            } catch (JwkException e) {
                throw new RuntimeException("Failed to get public key.", e);
            }
        }
    }
}
```

Wenn ihr jetzt wir nun den Test starten, sollte dieser Fehlschlagen. 

//TODO test erweitern




## Authorisierung