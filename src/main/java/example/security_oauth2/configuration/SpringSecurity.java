package example.security_oauth2.configuration;

import example.security_oauth2.oauth.CustomLogoutHandler;
import example.security_oauth2.oauth.SocialAppService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SpringSecurity {
    private final SocialAppService socialAppService;
    private final CustomLogoutHandler customLogoutHandler;

    public SpringSecurity(SocialAppService socialAppService, CustomLogoutHandler customLogoutHandler) {
        this.socialAppService = socialAppService;
        this.customLogoutHandler = customLogoutHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(Customizer.withDefaults())
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/", "/login", "/error", "/webjars/**", "/logout").permitAll() // Разрешаем доступ к этим маршрутам всем
                        .requestMatchers("/h2-console/*").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN") // Только для администраторов
                        .anyRequest().authenticated() // Все остальные запросы требуют аутентификации
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)) // Обработка ошибок аутентификации
                )

                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/login") // Указываем страницу для входа
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userService(socialAppService))
                        .defaultSuccessUrl("/user")
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // URL для выхода
                        .addLogoutHandler(customLogoutHandler)
                        .logoutSuccessHandler(oidcLogoutSuccessHandler()) // Обработчик для логаута
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                );
        return http.build();
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            response.sendRedirect("/login?logout");
        };
    }
}



