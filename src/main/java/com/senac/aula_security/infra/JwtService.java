package com.senac.aula_security.infra;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtService {

    public String gerarToken(String username){
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + 1000 * 60 * 60 // transformar milisegundos em horas
                ))
                .signWith(gerarChave())
                .compact();
    }
    public String extrairUsername(String token) {
        return Jwts.parser()
                .verifyWith(gerarChave())
                .build()
                .parseSignedClaims(token)
                .getPayload().getSubject();
    }

    public boolean tokenValido(String token, String username){
        try {
            String usernameExtraido = extrairUsername(token);
            Date dataExpiracao = Jwts
                    .parser()
                    .verifyWith(gerarChave())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload().getExpiration();

            return usernameExtraido.equals(username) && dataExpiracao.after(new Date());
        } catch (JwtException ex){
            return false;
        }
    }

    private SecretKey gerarChave() {
        return Keys.hmacShaKeyFor("Vasco".getBytes(StandardCharsets.UTF_8));
    }
}
