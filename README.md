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

Da wir jetzt jeden Token validieren, wird unser Test fehlschlagen. Deshalb müssen wir den Test nun so erweitern,dass jeder Request den wir an unsere Applikation senden einen Authorization Header mit einem validen JWT beinhaltet. Da ich die Tests gerne so lose wie möglich schreiben möchte (also am besten ohne das ein Aufruf an Keycloak notwendig wird), werde ich in meinem Tests einen neuen FIlter schreiben. In dem Filter werde ich dafür vom produktiv code etwas abweichen. In dem Filter werde ich um eine lose Kopplung gewährleisten zu können eine symetrische Verschlüsselung verwenden. Dafür brauchen wir eine WebSecurityConfig in unseren Test in der wir unseren Filter hinzufügen.Wir erstellen also eine WebSecurityConfig die genau die selbe Konfiguration wie unser Produktivcode beinhaltet, nur das hier der Filter aus den Tests verwendet wird:

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
                .addFilter(new JWTAuthenticationFilter(authenticationManager())) //Filter aus der test package
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}
```


Unser TestFilter sieht wie folgt aus:

```java

public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    private final JwtParser jwtParser;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) throws UnsupportedEncodingException {
        super(authenticationManager);
        jwtParser = Jwts.parserBuilder().setSigningKey("Yn2kjibddFAWtnPJ2AFlL8WXmohJMCvigQggaEypa5E=".getBytes("UTF-8")).build();
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
}

```

Wie ihr in dem folgenden Beispiel sieht, haben wir hier einen symetrischen Schlüssel verwendet: 

```java
jwtParser = Jwts.parserBuilder().setSigningKey("Yn2kjibddFAWtnPJ2AFlL8WXmohJMCvigQggaEypa5E=".getBytes("UTF-8")).build();
```

Den gleichen Schlüssel können wir benutzen um in den Tests ein JWT zu signieren. Um das zu tun, implementieren wir noch eine helper Klasse, welche uns einen JWT generiert und auch mit dem symetrischen Schlüssel signiert:

```java
public class JwtHelper {

    private static final long EXPIRATIONTIME = 864_000_000; // 10 days

    public static String createToken(String exampleRole, String exampleClaim) {

        byte[] apiKeySecretBytes = new byte[0];
        try {
            apiKeySecretBytes = "Yn2kjibddFAWtnPJ2AFlL8WXmohJMCvigQggaEypa5E=".getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());

        Map<String, List<String>> realmroles = new HashMap<>();

        List<String> roles = List.of(exampleRole);

        realmroles.put("roles", roles);

        String jwt = Jwts.builder()
                .claim("exampleClaim", exampleClaim)
                .claim("realm_access",realmroles)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();

        return "Bearer " + jwt;
    }
}
```


Nachdem wir nun auch in der Lage sind JWT zu generieren, können wir nun unseren Test erweitern:

```java
@Test
void testAccessSecuredEndpoint_validJWT() {
    String exampleClaim = "HelloWorld";
    String jwt = JwtHelper.createToken("exampleRole", exampleClaim);
    final JsonNode response = with().given().header("Authorization", jwt).port(port).when().request("GET", "/").then().statusCode(HttpStatus.OK.value()).extract().body().as(JsonNode.class);
    assertThat(response.get("message").textValue()).isEqualTo(exampleClaim);
}
```

In dem Beispiel fügen wir beispielhaft eine claim hinzu und fügen den JWT in unseren Authorization Header hinzu. Jetzt sollte dieser Test wieder erfolgreich durchlaufen.


## Authorisierung

In vielen Fällen reicht eine Authentifizierung nicht aus. Oft ist man in der Situation, dass man einige Endpunkte nur für bestimmte Benutzergruppen zur Verfügung stellen möchte. In diesem Abschnitt möchte ich zeigen wie das mit einigen Erweiterungen möglich ist. 

Dafür erweitern wir zunächst unseren JWTAuthenticationFilter wie folgt:

```java
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    private final JwtParser jwtParser;

    private final JwkProvider provider;

    private URL wellKnownUrl = new URL("https://<keycloak-url>/sec-api/auth/realms/<realm>/protocol/openid-connect/certs");


    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) throws MalformedURLException {
        super(authenticationManager);
        provider = new JwkProviderBuilder(wellKnownUrl)
                .cached(10, 24, TimeUnit.HOURS)
                .build();

        jwtParser = Jwts.parserBuilder().setSigningKeyResolver(new MyResolver()).build();
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {
        final String header = request.getHeader("Authorization");

        if (StringUtils.isEmpty(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        final Authentication authentication = getAuthentication(header);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }

    private Authentication getAuthentication(String authorizationHeader) {
        try{
            final String token = authorizationHeader.replace("Bearer ", "");

            final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);

            final Claims body = claimsJws.getBody();
            final String exampleClaim = body.get("exampleClaim", String.class);
            final LinkedHashMap<String, List<String>> realm_access = claimsJws.getBody().get("realm_access", LinkedHashMap.class);
            final UserPrincipal userPrincipal = new UserPrincipal(exampleClaim, extractRoles(realm_access));
            return new UsernamePasswordAuthenticationToken(userPrincipal, null, getGrantedAuthorities(realm_access));
        }catch(Exception e){
            return new UsernamePasswordAuthenticationToken(null, null);
        }
    }

    private Set<String> extractRoles(LinkedHashMap<String, List<String>> realm_access){
        if (CollectionUtils.isEmpty(realm_access) || !realm_access.containsKey("roles")){
            return Set.of();
        }
        return new HashSet<>(realm_access.get("roles"));
    }

    private Set<GrantedAuthority> getGrantedAuthorities(LinkedHashMap<String, List<String>> realm_access) {
        if (CollectionUtils.isEmpty(realm_access) || !realm_access.containsKey("roles")){
            return Set.of();
        }
        return realm_access.get("roles").stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toSet());
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

Wie ihr sehen könnt rufen wir nicht mehr die folgende Methode auf:

```java
jwtParser.isSigned(token);
```

Stattdessen möchten wir nun das JWT parsen und mit den darin enthalten claims arbeiten. Dafür schreiben wir die neue Methode "getAuthentication":

```java
private Authentication getAuthentication(String authorizationHeader) {
    try{
        final String token = authorizationHeader.replace("Bearer ", "");

        final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);

        final Claims body = claimsJws.getBody();
        final String exampleClaim = body.get("exampleClaim", String.class);
        final LinkedHashMap<String, List<String>> realm_access = claimsJws.getBody().get("realm_access", LinkedHashMap.class);
        final UserPrincipal userPrincipal = new UserPrincipal(exampleClaim, extractRoles(realm_access));
        return new UsernamePasswordAuthenticationToken(userPrincipal, null, getGrantedAuthorities(realm_access));
    }catch(Exception e){
        return new UsernamePasswordAuthenticationToken(null, null);
    }
}
```

Um an die claims zu kommen können wir die Methode 

```java
jwtParser.parseClaimsJws(token);
```

aufrufen. Mit dieser Methode gelangen wir nicht nur an die claims, durch diesen Methoden aufruf wird auch unser JWT validiert und der User damit authentifiziert. Nachdem wir die claims haben möchten wir in diesem Beispiel die Rollen aus dem "realm_access" claim in unsere neue Entität "UserPrincipal" hinzufügen. Dies machen wir mit der Methode "extractRoles":

```java
private Set<String> extractRoles(LinkedHashMap<String, List<String>> realm_access){
    if (CollectionUtils.isEmpty(realm_access) || !realm_access.containsKey("roles")){
        return Set.of();
    }
    return new HashSet<>(realm_access.get("roles"));
}
```

Aber interessant für die Authorisierung wird es der nächste Schritt. Wir möchten basierend auf den Rollen "GrantedAuthorities" erstellen und diese dann in unsere Authentication Objekt hinzufügen:

```java
...
return new UsernamePasswordAuthenticationToken(userPrincipal, null, getGrantedAuthorities(realm_access));
...

private Set<GrantedAuthority> getGrantedAuthorities(LinkedHashMap<String, List<String>> realm_access) {
    if (CollectionUtils.isEmpty(realm_access) || !realm_access.containsKey("roles")){
        return Set.of();
    }
    return realm_access.get("roles").stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toSet());
}
```

Nachdem wir die "GrantedAuthorities" hinzugefügt haben können wir nun in unserem Rest-Endpunkt die folgende Anotation nutzen:

```java
@PreAuthorize("hasAuthority('exampleRole')")
```

Beispielsweise könnte der RestController also wie folgt aussehen:

```java
@RestController
public class ExampleController {

    @RequestMapping(method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('exampleRole')")
    public String example(Principal principal){
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) principal;
        final UserPrincipal userPrincipal = (UserPrincipal) usernamePasswordAuthenticationToken.getPrincipal();

        String response = "{\"message\" : \"" + userPrincipal.getExampleClaim() + "\"}";

        return response;
    }

}
```

Das heißt jeder Request benötigt erstmal ein valides JWT damit wir den User Authentifizieren können. Außerdem muss das JWT eine claim mit dem Namen "realm_access" beinhalten, in der die Rolle "exampleRole" enthalten ist. Nur dann ist man in der Lage den Endpunkt zu erreichen.

In dem Abschnitt der Authentifizierung haben wir bereits einen JWTHelper implementiert. DIeser fügt bereits die beispielhafte Rolle hinzu. Dadurch ist sollte der Test also erfolgreich durchlaufen. Testet es gerne mal aus und entferntt auch mal die Rolle. Dann sollte der Test nicht erfolgreich sein.