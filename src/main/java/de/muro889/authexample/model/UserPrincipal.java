package de.muro889.authexample.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Set;

@AllArgsConstructor
@Getter
public class UserPrincipal  {

    private String exampleClaim;

    private Set<String> realmRoles;


}
