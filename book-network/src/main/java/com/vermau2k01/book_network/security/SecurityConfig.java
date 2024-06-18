package com.vermau2k01.book_network.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;


@Configuration 
//This annotation is used to indicate that a class declares one or more @Bean methods and may be processed by the Spring container to generate bean definitions and service requests for those beans at runtime.
@EnableWebSecurity 
// This annotation is used to enable web security in a Spring-based application. It's a marker annotation that adds the Spring Security configuration to the application context. It's typically used in conjunction with WebSecurityConfigurerAdapter to configure the security settings.
@RequiredArgsConstructor 
// This annotation is a Lombok annotation that generates a constructor with the required arguments, which are the final fields in the class. 
@EnableMethodSecurity(securedEnabled = true)
// This annotation is used to enable method-level security in a Spring-based application. It allows you to use annotations like @Secured and @RolesAllowed to restrict access to specific methods based on the user's roles or permissions.


public class SecurityConfig {

    private final AuthenticationProvider authenticationProvider;
    private JwtFilter jwtFilter;
     
    @Bean
     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
     {
       
    return http
       .cors(withDefaults())
       .csrf(AbstractHttpConfigurer:: disable)
       .authorizeHttpRequests(req->req.requestMatchers(
                            "/auth/**",
                                        "/v2/api-docs",
                                        "/v3/api-docs",
                                        "/v3/api-docs/**",
                                        "/swagger-resources",
                                        "/swagger-resources/**",
                                        "/configuration/ui",
                                        "/configuration/security",
                                        "/swagger-ui/**",
                                        "/webjars/**",
                                        "/swagger-ui.html").permitAll()
                                        .anyRequest().authenticated())
                                        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).authenticationProvider(authenticationProvider).addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class).
                                        build();
       
     } 

}

// todo : read about it
/*
 * CORS stands for Cross-Origin Resource Sharing. Imagine you have a clubhouse (a website) and sometimes you want to share things with friends from other clubs (other websites). CORS is like setting rules for how these friends can access your clubhouse.

Here's what CORS does:

Sharing Rules: It decides which friends (other websites) are allowed to access certain parts of your clubhouse (website). For example, it might say, "Only friends from these specific clubs can come in."

Security: It ensures that when friends visit your clubhouse from their own clubhouses (websites), they can only do certain things you allow, like reading information but not changing anything.

Protection: CORS also protects your clubhouse from unwanted visitors who might try to sneak in and cause trouble.

 */

 // todo : Read about them

 /*
  * CSRF stands for Cross-Site Request Forgery. It's a type of cyber attack where a malicious website tricks a user's browser into making unintended requests to another website where the user is authenticated. Let's break down what CSRF is and how it works:

Attack Scenario: Imagine you're logged into your online banking account in one tab of your browser. You then visit a different website in another tab. This website, without your knowledge, sends requests to your banking website, using your browser's credentials (cookies or session), to perform actions like transferring money or changing settings.

How It Works: The malicious website crafts a request that your browser automatically sends to the banking website. Since your browser includes your session cookies (which authenticate you to the banking site), the request looks legitimate to the banking server. Thus, the server executes the request, thinking it came from you.

Prevention: To prevent CSRF attacks, websites typically use tokens (CSRF tokens) that are included in forms or HTTP requests. These tokens are unique per session and per form submission, making it difficult for attackers to forge requests even if they trick a user into making them.

Importance: CSRF attacks are dangerous because they can lead to unauthorized actions being performed on behalf of a user without their consent. It's important for developers to implement CSRF protection mechanisms in their web applications to safeguard against such attacks.

In the context of your earlier question about Spring Security, disabling CSRF with .csrf(AbstractHttpConfigurer::disable) in the configuration you provided ensures that your application is protected against CSRF attacks by explicitly turning off the default CSRF protection.

  */

// todo :  Read about them 
/*
 * Session management in web applications refers to how the server keeps track of user state across multiple requests. This is crucial for maintaining a user's authenticated session securely. Let's break down the concepts of session management and session creation policy:

Session Management:

Definition: Session management involves maintaining the state of a user's interactions with a website or web application across multiple requests. It typically includes activities like user authentication (logging in), authorization (permissions), and maintaining session-specific data.
Cookies: Sessions are often managed using cookies. When a user logs in, the server typically sends a session identifier (session cookie) to the browser, which is then sent back with subsequent requests to identify the session.
Session Creation Policy:

Definition: Session creation policy dictates how and when sessions are created and managed within a web application.
Stateless vs. Stateful: Web applications can be designed to be stateless (where each request is independent and does not rely on previous interactions) or stateful (where session data is stored on the server and linked to a user's session).
Session Creation Policy Options:
STATELESS: Sessions are not stored on the server. Each request from the client is treated independently, and the server does not maintain any session state.
STATEFUL: Sessions are stored on the server. The server maintains session data and associates it with the client's session identifier (typically stored in a cookie).
NEVER: Sessions are never created by the server. This is useful for completely stateless authentication mechanisms like token-based authentication.
Importance:

Security: Proper session management is crucial for security. It helps prevent attacks like session hijacking and ensures that only authorized users can access sensitive resources.
User Experience: Effective session management contributes to a seamless user experience by maintaining user context across interactions without requiring frequent re-authentication.
In the Java code snippet you provided earlier, .sessionManagement(session -> session.sessionCreationPolicy(STATELESS)) sets the session creation policy to STATELESS. This means that your application does not maintain server-side sessions. Each request is treated independently, and clients must authenticate themselves for each request (typically using tokens or other credentials), which is common in stateless authentication mechanisms.
 */