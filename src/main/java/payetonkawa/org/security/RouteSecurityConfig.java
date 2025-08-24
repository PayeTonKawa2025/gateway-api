package payetonkawa.org.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "secured")
public class RouteSecurityConfig {

    private List<SecuredRoute> routes;

    @Data
    public static class SecuredRoute {
        private String path;
        private List<String> methods;
        private List<String> roles;
    }
}
