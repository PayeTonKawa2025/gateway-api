package payetonkawa.org.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class JwtAuthFilterTest {

    private JwtService jwtService;
    private RouteSecurityConfig securityConfig;
    private JwtAuthFilter filter;

    @BeforeEach
    void setup() {
        jwtService = Mockito.mock(JwtService.class);

        securityConfig = new RouteSecurityConfig();

        RouteSecurityConfig.SecuredRoute productsPost = new RouteSecurityConfig.SecuredRoute();
        productsPost.setPath("/api/products");
        productsPost.setMethods(List.of("POST"));
        productsPost.setRoles(List.of("ADMIN"));

        RouteSecurityConfig.SecuredRoute productsWrite = new RouteSecurityConfig.SecuredRoute();
        productsWrite.setPath("/api/products/**");
        productsWrite.setMethods(List.of("PUT","PATCH","DELETE"));
        productsWrite.setRoles(List.of("ADMIN"));

        RouteSecurityConfig.SecuredRoute ordersDelete = new RouteSecurityConfig.SecuredRoute();
        ordersDelete.setPath("/api/orders/**");
        ordersDelete.setMethods(List.of("DELETE"));
        ordersDelete.setRoles(List.of("ADMIN"));

        securityConfig.setRoutes(List.of(productsPost, productsWrite, ordersDelete));

        filter = new JwtAuthFilter(jwtService, securityConfig);
    }

    static class TestChain implements GatewayFilterChain {
        boolean called = false;
        ServerWebExchange lastExchange;

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            this.called = true;
            this.lastExchange = exchange;
            return Mono.empty();
        }
    }

    private MockServerWebExchange exchange(String method, String path) {
        MockServerHttpRequest req = MockServerHttpRequest
                .method(HttpMethod.valueOf(method), path)
                .build();
        // Utiliser from(MockServerHttpRequest) (surcharge toujours présente)
        return MockServerWebExchange.from(req);
        // Alternative universelle si besoin :
        // return MockServerWebExchange.builder(req).build();
    }

    private MockServerWebExchange exchangeWithBearer(String method, String path, String token) {
        MockServerHttpRequest req = MockServerHttpRequest
                .method(HttpMethod.valueOf(method), path)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        return MockServerWebExchange.from(req);
    }

    private MockServerWebExchange exchangeWithCookie(String method, String path, String token) {
        MockServerHttpRequest req = MockServerHttpRequest
                .method(HttpMethod.valueOf(method), path)
                .cookie(new HttpCookie("access_token", token))
                .build();
        return MockServerWebExchange.from(req);
    }

    private Claims claims(String sub, List<String> roles) {
        DefaultClaims c = new DefaultClaims();
        c.setSubject(sub);
        c.put("roles", roles);
        return c;
    }

    @Test
    void public_route_passes_without_token() {
        MockServerWebExchange ex = exchange("GET", "/api/auth/login");
        TestChain chain = new TestChain();

        filter.filter(ex, chain).block();

        assertThat(chain.called).isTrue();
        assertThat(ex.getResponse().getStatusCode()).isNull();
    }

    @Test
    void protected_route_without_token_returns_401() {
        MockServerWebExchange ex = exchange("POST", "/api/products");
        TestChain chain = new TestChain();

        filter.filter(ex, chain).block();

        assertThat(chain.called).isFalse();
        assertThat(ex.getResponse().getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void protected_route_with_insufficient_role_returns_403() {
        String token = "t-user";
        when(jwtService.parseAndValidate(token))
                .thenReturn(claims("user@ex.com", List.of("USER")));

        MockServerWebExchange ex = exchangeWithBearer("POST", "/api/products", token);
        TestChain chain = new TestChain();

        filter.filter(ex, chain).block();

        assertThat(chain.called).isFalse();
        assertThat(ex.getResponse().getStatusCode().value()).isEqualTo(403);
        verify(jwtService, times(1)).parseAndValidate(token);
    }

    @Test
    void protected_route_with_admin_role_passes_and_adds_headers() {
        String token = "t-admin";
        when(jwtService.parseAndValidate(token))
                .thenReturn(claims("admin@ex.com", List.of("ADMIN")));

        MockServerWebExchange ex = exchangeWithBearer("PUT", "/api/products/123", token);
        TestChain chain = new TestChain();

        filter.filter(ex, chain).block();

        assertThat(chain.called).isTrue();
        ServerWebExchange forwarded = chain.lastExchange;
        assertThat(forwarded.getRequest().getHeaders().getFirst("X-User-Sub"))
                .isEqualTo("admin@ex.com");
        assertThat(forwarded.getRequest().getHeaders().getFirst("X-User-Roles"))
                .isEqualTo("ADMIN");
        verify(jwtService, times(1)).parseAndValidate(token);
    }

    @Test
    void token_in_cookie_is_accepted() {
        String token = "t-cookie";
        when(jwtService.parseAndValidate(token))
                .thenReturn(claims("cookie@ex.com", List.of("ADMIN")));

        MockServerWebExchange ex = exchangeWithCookie("DELETE", "/api/orders/42", token);
        TestChain chain = new TestChain();

        filter.filter(ex, chain).block();

        assertThat(chain.called).isTrue();
        verify(jwtService, times(1)).parseAndValidate(token);
    }

    @Test
    void invalid_token_returns_401() {
        String token = "bad";
        when(jwtService.parseAndValidate(token)).thenThrow(new RuntimeException("bad token"));

        MockServerWebExchange ex = exchangeWithBearer("PATCH", "/api/products/9", token);
        TestChain chain = new TestChain();

        filter.filter(ex, chain).block();

        assertThat(chain.called).isFalse();
        assertThat(ex.getResponse().getStatusCode().value()).isEqualTo(401);
    }
}
