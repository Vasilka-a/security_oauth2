package example.security_oauth2.controller;

import example.security_oauth2.oauth.CustomOauth2User;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {

    @GetMapping("/user")
    public String user(@AuthenticationPrincipal CustomOauth2User principal, Model model) {
        model.addAttribute("name", principal.getAttribute("name"));
        model.addAttribute("email", principal.getAttribute("email"));
        model.addAttribute("role", principal.getRole());
        model.addAttribute("provider", principal.getProvider());
        return "user";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminPanel(@AuthenticationPrincipal CustomOauth2User principal, Model model) {
        model.addAttribute("name", principal.getAttribute("name"));
        model.addAttribute("email", principal.getAttribute("email"));
        model.addAttribute("role", principal.getRole());
        model.addAttribute("provider", principal.getProvider());
        return "admin";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
