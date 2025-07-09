package example.security_oauth2.oauth;

import example.security_oauth2.entity.Role;
import example.security_oauth2.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CustomOauth2User implements OAuth2User {
    private Long id;
    private String email;
    private String name;
    private String provider;
    private Role role;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    public static CustomOauth2User create(User user, Map<String, Object> attributes) {
        List<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_" + user.getRole().name())
        );

        return new CustomOauth2User(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getProvider(),
                user.getRole(),
                authorities,
                attributes
        );
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getName() {
        return name;
    }
}
