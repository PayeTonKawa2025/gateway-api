package payetonkawa.org.security;

import com.github.benmanes.caffeine.cache.Cache;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    @Value("${auth.jwt.public-key}")
    private Resource publicKeyResource;

    private volatile PublicKey publicKey;

    private final Cache<String, Claims> tokenClaimsCache;

    private PublicKey getPublicKey() {
        if (publicKey == null) {
            synchronized (this) {
                if (publicKey == null) {
                    try (InputStream is = publicKeyResource.getInputStream()) {
                        String key = new String(is.readAllBytes())
                                .replace("-----BEGIN PUBLIC KEY-----", "")
                                .replace("-----END PUBLIC KEY-----", "")
                                .replaceAll("\\s", "");
                        byte[] decoded = Base64.getDecoder().decode(key);
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
                        publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
                        if (!(publicKey instanceof RSAPublicKey)) {
                            throw new IllegalStateException("Public key is not RSA");
                        }
                        log.info("Public key loaded");
                    } catch (Exception e) {
                        throw new RuntimeException("Unable to load public key", e);
                    }
                }
            }
        }
        return publicKey;
    }

    /** Parse + vérifie la signature. Résultat mis en cache par token. */
    public Claims parseAndValidate(String token) {
        Claims cached = tokenClaimsCache.getIfPresent(token);
        if (cached != null) return cached;
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            tokenClaimsCache.put(token, claims);
            return claims;
        } catch (ExpiredJwtException e) {
            log.debug("JWT expired");
            throw e;
        } catch (SignatureException e) {
            log.debug("JWT signature invalid");
            throw e;
        } catch (JwtException e) {
            log.debug("JWT invalid: {}", e.getMessage());
            throw e;
        }
    }

    public String extractSubject(String token) {
        return parseAndValidate(token).getSubject();
    }
}
