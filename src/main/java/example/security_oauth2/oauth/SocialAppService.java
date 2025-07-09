package example.security_oauth2.oauth;

import example.security_oauth2.entity.Role;
import example.security_oauth2.entity.User;
import example.security_oauth2.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class SocialAppService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private static final Logger logger = LoggerFactory.getLogger(SocialAppService.class);
    private final UserRepository userRepository;

    public SocialAppService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);
        // Логика сохранения юзера, определения роли на основе аутентификации

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .email(email)
                            .name(name)
                            .role(Role.USER)
                            .provider(registrationId)
                            .build();
                    if (userRepository.count() == 0) {
                        newUser.setRole(Role.ADMIN);
                    }
                    return userRepository.save(newUser);
                });
        CustomOauth2User savedUser = CustomOauth2User.create(user, attributes);
        logger.info("User authenticated: {}", user.getEmail());
        return savedUser;
    }
}
