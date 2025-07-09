package example.security_oauth2.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomLogoutHandler.class);

    private final OAuth2AuthorizedClientService authorizedClientService;

    private final RestTemplate restTemplate = new RestTemplate();

    public CustomLogoutHandler(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            String email = oauthToken.getPrincipal().getAttribute("email");

            if ("google".equals(oauthToken.getAuthorizedClientRegistrationId())) {
                OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                        oauthToken.getAuthorizedClientRegistrationId(),
                        oauthToken.getName()
                );
                String accessToken = client.getAccessToken().getTokenValue();
                log.info("Revoking token for email: {}", email);
                String revokeTokenUrl = "https://accounts.google.com/o/oauth2/revoke?token=" + accessToken;
                try {
                    restTemplate.getForObject(revokeTokenUrl, String.class);
                    log.info("User logged out: {}", email);
                } catch (Exception e) {
                    log.error("Failed to revoke token for email: {}", email, e);
                }
            }
        }
    }
}

