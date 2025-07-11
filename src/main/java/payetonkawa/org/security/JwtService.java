package payetonkawa.org.security;

import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Value("${auth.jwt.public-key}")
    private Resource publicKeyResource;

    private volatile PublicKey publicKey;

    private PublicKey getPublicKey() {
        if (publicKey == null) {
            synchronized (this) {
                if (publicKey == null) {
                    try (InputStream is = publicKeyResource.getInputStream()) {
                        logger.info("JwtService: Loading public key from resource {}", publicKeyResource.getFilename());

                        String key = new String(is.readAllBytes())
                                .replace("-----BEGIN PUBLIC KEY-----", "")
                                .replace("-----END PUBLIC KEY-----", "")
                                .replaceAll("\\s", "");

                        logger.debug("JwtService: Decoded public key base64 content: {}", key);

                        byte[] decoded = Base64.getDecoder().decode(key);
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        publicKey = keyFactory.generatePublic(keySpec);

                        logger.info("JwtService: Public key loaded successfully");

                    } catch (Exception e) {
                        logger.error("JwtService: Failed to load public key", e);
                        throw new RuntimeException("Unable to load public key", e);
                    }
                }
            }
        }
        return publicKey;
    }

    public boolean isValid(String token) {
        try {
            logger.debug("JwtService: Validating JWT token");
            Jwts.parserBuilder()
                    .setSigningKey(getPublicKey())
                    .build()
                    .parseClaimsJws(token);
            logger.debug("JwtService: Token is valid");
            return true;
        } catch (Exception e) {
            logger.warn("JwtService: Invalid token - {}", e.getMessage());
            return false;
        }
    }

    public String extractEmail(String token) {
        try {
            logger.debug("JwtService: Extracting email from token");
            return Jwts.parserBuilder()
                    .setSigningKey(getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (Exception e) {
            logger.error("JwtService: Failed to extract email from token", e);
            throw new RuntimeException("Failed to extract email from token", e);
        }
    }
}
