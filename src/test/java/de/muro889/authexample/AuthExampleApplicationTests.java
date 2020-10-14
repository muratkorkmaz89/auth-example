package de.muro889.authexample;

import com.fasterxml.jackson.databind.JsonNode;
import de.muro889.authexample.helper.JwtHelper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

import static io.restassured.RestAssured.with;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthExampleApplicationTests {

    @LocalServerPort
    public int port;

    @Test
    void testAccessSecuredEndpoint_validJWT() {
        String exampleClaim = "HelloWorld";
        String jwt = JwtHelper.createToken("exampleRole", exampleClaim);
        final JsonNode response = with().given().header("Authorization", jwt).port(port).when().request("GET", "/").then().statusCode(HttpStatus.OK.value()).extract().body().as(JsonNode.class);
        assertThat(response.get("message").textValue()).isEqualTo(exampleClaim);
    }

    @Test
    void testAccessSecuredEndpoint_withoutJWT() {
        with().given().port(port).when().request("GET", "/").then().statusCode(HttpStatus.FORBIDDEN.value());
    }

    @Test
    void testAccessSecuredEndpoint_validJWTMissingRole() {
        String exampleClaim = "hello world";
        String jwt = JwtHelper.createToken("anotherRole", exampleClaim);
        with().given().header("Authorization", jwt).port(port).when().request("GET", "/").then().statusCode(HttpStatus.FORBIDDEN.value());
    }

}
