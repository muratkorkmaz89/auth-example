package de.muro889.authexample.helper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
