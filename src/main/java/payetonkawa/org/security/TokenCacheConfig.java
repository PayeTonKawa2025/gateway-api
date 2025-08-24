package payetonkawa.org.security;

import com.github.benmanes.caffeine.cache.*;
import io.jsonwebtoken.Claims;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class TokenCacheConfig {
    @Bean
    public Cache<String, Claims> tokenClaimsCache() {
        // taille à ajuster selon charge; expiration = durée de vie restante du token
        return Caffeine.newBuilder()
                .initialCapacity(1_000)
                .maximumSize(50_000)
                .expireAfter(new Expiry<String, Claims>() {
                    @Override public long expireAfterCreate(String token, Claims claims, long now) {
                        long ttlSec = Math.max(1L,
                                (claims.getExpiration().getTime() - System.currentTimeMillis()) / 1000);
                        return TimeUnit.SECONDS.toNanos(ttlSec);
                    }
                    @Override public long expireAfterUpdate(String key, Claims value, long d, long n){ return d; }
                    @Override public long expireAfterRead(String key, Claims value, long d, long n){ return d; }
                })
                .build();
    }
}
