package payetonkawa.org.security;

import com.github.benmanes.caffeine.cache.Cache;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {

    private JwtService jwtService;
    private KeyPair keyPair; // clé privée pour signer, clé publique injectée dans le service
    private Cache<String, Claims> cache;

    @BeforeEach
    void setUp() throws Exception {
        // Génère une paire RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        keyPair = kpg.generateKeyPair();

        // Cache réel (même conf que ta prod)
        cache = new TokenCacheConfig().tokenClaimsCache();

        // Instancie le service et injecte la publicKey (on bypasse le Resource)
        jwtService = new JwtService(cache);
        ReflectionTestUtils.setField(jwtService, "publicKey", keyPair.getPublic());
    }

    private String buildJwt(String sub, List<String> roles, Instant expiration) {
        return Jwts.builder()
                .setSubject(sub)
                .claim("roles", roles)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(expiration))
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
    }

    @Test
    void parseAndValidate_validToken_returnsClaims_andCaches() {
        String token = buildJwt("alice@example.com", List.of("ADMIN"), Instant.now().plusSeconds(3600));

        // 1er appel -> parse + vérif
        Claims c1 = jwtService.parseAndValidate(token);
        assertThat(c1.getSubject()).isEqualTo("alice@example.com");
        assertThat(c1.get("roles", List.class)).containsExactly("ADMIN");

        // 2e appel -> doit venir du cache (au moins pas d’exception)
        Claims c2 = jwtService.parseAndValidate(token);
        assertThat(c2).isSameAs(c1); // même instance = récupérée du cache
    }

    @Test
    void parseAndValidate_expiredToken_throwsExpiredJwtException() {
        String token = buildJwt("bob@example.com", List.of("USER"), Instant.now().minusSeconds(5));
        assertThrows(ExpiredJwtException.class, () -> jwtService.parseAndValidate(token));
    }

    @Test
    void parseAndValidate_tokenSignedWithAnotherKey_throws() throws Exception {
        // Génère une autre clé privée pour signer => signature invalide pour la publicKey injectée
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair other = kpg.generateKeyPair();

        String bad = Jwts.builder()
                .setSubject("mallory@example.com")
                .setExpiration(Date.from(Instant.now().plusSeconds(600)))
                .signWith(other.getPrivate(), SignatureAlgorithm.RS256)
                .compact();

        // JJWT lève une JwtException (SignatureException en cause)
        assertThrows(io.jsonwebtoken.JwtException.class, () -> jwtService.parseAndValidate(bad));
    }
}
