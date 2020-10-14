package de.muro889.authexample.controller.filter;

import de.muro889.authexample.model.UserPrincipal;
import io.jsonwebtoken.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    private final JwtParser jwtParser;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) throws UnsupportedEncodingException {
        super(authenticationManager);
        jwtParser = Jwts.parserBuilder().setSigningKey("Yn2kjibddFAWtnPJ2AFlL8WXmohJMCvigQggaEypa5E=".getBytes("UTF-8")).build();
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
}
