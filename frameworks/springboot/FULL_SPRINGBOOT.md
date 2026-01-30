# Spring Boot Security Guardrails — Full Reference

> **Version:** 1.0.0 | **Condensed:** [condensed.md](./condensed.md)

This document provides detailed security patterns for Java Spring Boot applications.

---

## Table of Contents

1. [SQL Injection](#sql-injection)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [Authentication & Authorization](#authentication--authorization)
4. [Mass Assignment](#mass-assignment)
5. [CSRF Protection](#csrf-protection)
6. [Secrets Management](#secrets-management)
7. [Security Headers](#security-headers)
8. [Input Validation](#input-validation)

---

## SQL Injection

### ❌ Vulnerable Patterns

```java
// String concatenation in queries
@Repository
public class UserRepository {
    @PersistenceContext
    private EntityManager em;
    
    // DANGEROUS - SQL Injection
    public User findByName(String name) {
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        return em.createNativeQuery(query, User.class).getSingleResult();
    }
    
    // DANGEROUS - even with JPQL
    public List<User> searchUsers(String search) {
        String jpql = "SELECT u FROM User u WHERE u.name LIKE '%" + search + "%'";
        return em.createQuery(jpql, User.class).getResultList();
    }
}
```

### ✅ Safe Patterns

```java
// JPA Repository (parameterized by default)
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // Method query (safe)
    Optional<User> findByName(String name);
    
    // @Query with parameters (safe)
    @Query("SELECT u FROM User u WHERE u.name = :name")
    Optional<User> findByNameQuery(@Param("name") String name);
    
    // Native query with parameters (safe)
    @Query(value = "SELECT * FROM users WHERE email = :email", nativeQuery = true)
    Optional<User> findByEmailNative(@Param("email") String email);
    
    // LIKE with parameter (safe)
    @Query("SELECT u FROM User u WHERE u.name LIKE %:search%")
    List<User> searchUsers(@Param("search") String search);
}

// EntityManager with parameters (safe)
public User findByName(String name) {
    return em.createQuery("SELECT u FROM User u WHERE u.name = :name", User.class)
             .setParameter("name", name)
             .getSingleResult();
}
```

---

## Cross-Site Scripting (XSS)

### Thymeleaf

```html
<!-- ❌ DANGEROUS - unescaped output -->
<div th:utext="${userInput}"></div>

<!-- ✅ SAFE - escaped by default -->
<div th:text="${userInput}"></div>

<!-- ✅ SAFE - attributes are escaped -->
<input th:value="${userInput}" />
```

### JSON Responses

```java
// Spring Boot escapes JSON by default, but be careful with:

// ❌ Returning raw HTML in JSON
@GetMapping("/api/preview")
public Map<String, String> preview(@RequestParam String content) {
    return Map.of("html", content);  // If rendered as HTML on client, XSS risk
}

// ✅ Return data, let client handle rendering safely
@GetMapping("/api/preview")
public Map<String, String> preview(@RequestParam String content) {
    return Map.of("text", content);  // Client uses textContent, not innerHTML
}
```

### Security Headers

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentTypeOptions(withDefaults())      // X-Content-Type-Options: nosniff
                .xssProtection(withDefaults())           // X-XSS-Protection
                .frameOptions(frame -> frame.sameOrigin()) // X-Frame-Options
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; script-src 'self'"))
            );
        return http.build();
    }
}
```

---

## Authentication & Authorization

### Spring Security Configuration

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/public/**", "/login").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/")
                .permitAll()
            )
            .sessionManagement(session -> session
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true)
            );
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);  // Strong hashing
    }
}
```

### Method-Level Security

```java
@Service
public class UserService {
    
    // ❌ No authorization check
    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }
    
    // ✅ Role-based access
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }
    
    // ✅ Expression-based (owner or admin)
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public User getUser(Long userId) {
        return userRepository.findById(userId).orElseThrow();
    }
    
    // ✅ Post-authorization (check result)
    @PostAuthorize("returnObject.owner == authentication.principal.username")
    public Document getDocument(Long docId) {
        return documentRepository.findById(docId).orElseThrow();
    }
}
```

### Controller Authorization

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // ❌ Missing authorization
    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
    }
    
    // ✅ With authorization
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
    }
}
```

---

## Mass Assignment

### The Problem

Spring's `@ModelAttribute` binds all request parameters to object fields.

### ❌ Vulnerable Patterns

```java
// Entity with sensitive fields
@Entity
public class User {
    private Long id;
    private String name;
    private String email;
    private String role;      // Sensitive!
    private boolean admin;    // Sensitive!
}

// Controller accepting entity directly
@PostMapping("/users")
public User createUser(@ModelAttribute User user) {
    return userRepository.save(user);  // Attacker can set role=ADMIN
}

// Or with @RequestBody
@PostMapping("/users")
public User createUser(@RequestBody User user) {
    return userRepository.save(user);  // Same problem
}
```

### ✅ Safe Patterns

```java
// DTO with only allowed fields
public class UserCreateDTO {
    @NotBlank
    private String name;
    
    @Email
    private String email;
    
    @NotBlank
    @Size(min = 12)
    private String password;
    
    // No role or admin fields!
}

// Controller uses DTO
@PostMapping("/users")
public User createUser(@Valid @RequestBody UserCreateDTO dto) {
    User user = new User();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    user.setPassword(passwordEncoder.encode(dto.getPassword()));
    user.setRole("USER");  // Server sets default role
    return userRepository.save(user);
}

// Or use MapStruct for mapping
@Mapper
public interface UserMapper {
    @Mapping(target = "role", ignore = true)
    @Mapping(target = "admin", ignore = true)
    User toEntity(UserCreateDTO dto);
}
```

---

## CSRF Protection

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // For web apps with forms - keep CSRF enabled
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            // ...
        return http.build();
    }
}

// For REST APIs with JWT - CSRF can be disabled
@Bean
public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/api/**")
        .csrf(csrf -> csrf.disable())  // OK for stateless JWT APIs
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // ...
    return http.build();
}
```

---

## Secrets Management

### ❌ Vulnerable Patterns

```yaml
# application.yml with hardcoded secrets
spring:
  datasource:
    password: mysecretpassword  # DANGEROUS - committed to git

jwt:
  secret: super-secret-key-123  # DANGEROUS
```

### ✅ Safe Patterns

```yaml
# application.yml - reference environment variables
spring:
  datasource:
    url: ${DATABASE_URL}
    username: ${DATABASE_USERNAME}
    password: ${DATABASE_PASSWORD}

jwt:
  secret: ${JWT_SECRET}
```

```java
// Configuration class with validation
@Configuration
@ConfigurationProperties(prefix = "jwt")
@Validated
public class JwtConfig {
    
    @NotBlank
    private String secret;
    
    @Min(3600)  // At least 1 hour
    private long expirationMs = 86400000;
    
    // getters and setters
}
```

```bash
# Set environment variables (not in code)
export DATABASE_PASSWORD=actual-secret-password
export JWT_SECRET=$(openssl rand -base64 32)
```

---

## Input Validation

```java
// DTO with validation annotations
public class UserRegistrationDTO {
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be 3-50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, underscores")
    private String username;
    
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;
    
    @NotBlank(message = "Password is required")
    @Size(min = 12, message = "Password must be at least 12 characters")
    private String password;
}

// Controller with @Valid
@PostMapping("/register")
public ResponseEntity<?> register(@Valid @RequestBody UserRegistrationDTO dto, 
                                   BindingResult result) {
    if (result.hasErrors()) {
        return ResponseEntity.badRequest()
            .body(result.getAllErrors().stream()
                .map(ObjectError::getDefaultMessage)
                .collect(Collectors.toList()));
    }
    // Process registration
}

// Global exception handler
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, List<String>>> handleValidationErrors(
            MethodArgumentNotValidException ex) {
        List<String> errors = ex.getBindingResult()
            .getFieldErrors()
            .stream()
            .map(FieldError::getDefaultMessage)
            .collect(Collectors.toList());
        return ResponseEntity.badRequest().body(Map.of("errors", errors));
    }
}
```

---

## Quick Reference

| Vulnerability | Spring Boot Protection |
|---------------|----------------------|
| SQL Injection | JPA Repository, `@Param` bindings |
| XSS | Thymeleaf `th:text`, CSP headers |
| CSRF | `CsrfTokenRepository` (enabled by default) |
| Auth Bypass | `@PreAuthorize`, `SecurityFilterChain` |
| Mass Assignment | DTOs, explicit field mapping |
| Secrets | `${ENV_VAR}` in properties |

---

*Condensed version: [condensed.md](./condensed.md)*
