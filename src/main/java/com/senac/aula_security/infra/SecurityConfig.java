package com.senac.aula_security.infra;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public DefaultSecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http

                .csrf( csrf -> csrf.disable())
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers( "/publico/**").permitAll()
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                            .anyRequest().authenticated())
                .exceptionHandling( ex ->
                        ex.accessDeniedHandler((req,res, e) ->
                                res.sendError(HttpServletResponse.SC_FORBIDDEN,  "Acesso Negado")))
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder){
        UserDetails aluno = User.builder()
                . username ("aluno")
                .password(encoder. encode("123456"))
                .roles("USER") // rotas que o usuario pode acessar, tem o admin tbm que dai acessa rotas mais restritas, tipo configuração, que o user nao pode acesar
                .build();

        UserDetails admin = User.builder()
                . username ("admin")
                .password(encoder. encode("123456"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(aluno, admin);
    }
}
