package payetonkawa.org.security;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtService jwtService;
    private final RouteSecurityConfig securityConfig;

    private static final Set<String> PUBLIC_PREFIXES = Set.of(
            "/api/auth/", "/actuator", "/health", "/favicon"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String path = exchange.getRequest().getURI().getPath();
        final String method = exchange.getRequest().getMethod().name();

        log.debug("➡️ Requête entrante : {} {}", method, path);

        if (isPublic(path)) {
            log.debug("🔓 Route publique détectée : {}, accès autorisé sans JWT", path);
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        if (token == null || token.isBlank()) {
            log.warn("❌ Aucun token trouvé pour route protégée : {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try {
            Claims claims = jwtService.parseAndValidate(token);
            String userEmail = claims.getSubject();
            List<String> userRoles = claims.get("roles", List.class);

            log.debug("✅ JWT valide pour : {}", userEmail);
            log.debug("🛡️ Rôles utilisateur extraits : {}", userRoles);

            for (RouteSecurityConfig.SecuredRoute rule : securityConfig.getRoutes()) {
                String pattern = rule.getPath();
                String regex = convertAntToRegex(pattern);

                boolean match = path.matches(regex);
                boolean methodMatch = rule.getMethods().stream()
                        .anyMatch(m -> m.equalsIgnoreCase(method));

                log.debug("🔍 Vérification de la règle : {} {}", rule.getMethods(), pattern);
                log.debug("  - Path regex : {}", regex);
                log.debug("  - Path match : {}", match);
                log.debug("  - Method match : {}", methodMatch);

                if (match && methodMatch) {
                    boolean authorized = hasRequiredRole(userRoles, rule.getRoles());
                    log.debug("  - Rôle requis : {}", rule.getRoles());
                    log.debug("  - Autorisé ? {}", authorized);

                    if (!authorized) {
                        log.warn("⛔ Accès refusé à {} {} pour {}, rôles : {}, requis : {}",
                                method, path, userEmail, userRoles, rule.getRoles());

                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        return exchange.getResponse().setComplete();
                    }
                }
            }

            // Tout est OK → ajout des headers JWT vers le backend
            var mutated = exchange.mutate()
                    .request(builder -> builder
                            .headers(headers -> {
                                headers.add("X-User-Sub", userEmail);
                                headers.add("X-User-Roles", String.join(",", userRoles));
                            }))
                    .build();

            log.debug("✅ Accès autorisé à {} {} pour {}", method, path, userEmail);
            return chain.filter(mutated);

        } catch (Exception ex) {
            log.error("❌ Erreur de validation du JWT : {}", ex.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    private boolean isPublic(String path) {
        return PUBLIC_PREFIXES.stream().anyMatch(path::startsWith);
    }

    private String extractToken(ServerWebExchange exchange) {
        String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth != null && auth.startsWith("Bearer ")) {
            log.debug("📥 Token extrait du header Authorization");
            return auth.substring(7);
        }

        HttpCookie cookie = exchange.getRequest().getCookies().getFirst("access_token");
        if (cookie != null) {
            log.debug("📥 Token extrait du cookie access_token");
            return cookie.getValue();
        }

        log.warn("⚠️ Aucun token trouvé ni dans le header ni dans le cookie");
        return null;
    }

    private boolean matches(RouteSecurityConfig.SecuredRoute rule, String path, String method) {
        return path.matches(convertAntToRegex(rule.getPath()))
                && rule.getMethods().stream().anyMatch(m -> m.equalsIgnoreCase(method));
    }

    private boolean hasRequiredRole(List<String> userRoles, List<String> requiredRoles) {
        if (userRoles == null || requiredRoles == null) return false;
        return userRoles.stream().anyMatch(requiredRoles::contains);
    }

    private String convertAntToRegex(String pattern) {
        String regex = pattern
                .replace(".", "\\.")         // escape .
                .replace("**", ".*")         // ** = tout
                .replace("*", "[^/]*");      // * = tout sauf /

        if (pattern.endsWith("/**")) {
            regex = regex.replace("/.*", "(/.*)?");
        }

        return "^" + regex + "$";
    }

    @Override
    public int getOrder() {
        return -100; // Exécuter ce filtre très tôt
    }
}
