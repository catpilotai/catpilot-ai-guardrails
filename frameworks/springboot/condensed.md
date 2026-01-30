## ☕ Spring Boot Security

| Risk | ❌ Never | ✅ Always |
|------|----------|----------|
| SQL Injection | `"SELECT * FROM users WHERE id=" + userId` | JPA: `findById(userId)` or `@Param` with `@Query` |
| XSS | `th:utext="${userInput}"` (Thymeleaf) | `th:text="${userInput}"` (auto-escaped) |
| Mass Assignment | `@ModelAttribute` without filtering | DTO pattern: map only allowed fields |
| Open Endpoints | Missing `@PreAuthorize` | `@PreAuthorize("hasRole('USER')")` on methods |
| Secrets | `application.properties` with passwords | Externalized config + `@Value("${secret}")` from env |

**Auth:** Use Spring Security with `SecurityFilterChain`. Always `http.csrf()` enabled for web apps.

*Full reference: [FULL_SPRINGBOOT.md](./FULL_SPRINGBOOT.md)*
