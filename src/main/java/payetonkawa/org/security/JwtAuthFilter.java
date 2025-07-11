package payetonkawa.org.security;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtService jwtService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        logger.info("JwtAuthFilter: Checking for access_token cookie");

        HttpCookie tokenCookie = exchange.getRequest().getCookies().getFirst("access_token");

        if (tokenCookie == null) {
            logger.warn("JwtAuthFilter: access_token cookie not found");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = tokenCookie.getValue();

        if (token.isBlank()) {
            logger.warn("JwtAuthFilter: access_token cookie is blank");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        logger.info("JwtAuthFilter: Validating token: {}", token);

        if (!jwtService.isValid(token)) {
            logger.warn("JwtAuthFilter: Invalid JWT token");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        logger.info("JwtAuthFilter: Token is valid, continuing request");

        // (Optionnel) Ajouter un header avec l’email de l’utilisateur
        /*
        String email = jwtService.extractEmail(token);
        exchange = exchange.mutate()
                .request(builder -> builder.header("X-User-Email", email))
                .build();
        */

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1; // Prioritaire
    }
}
