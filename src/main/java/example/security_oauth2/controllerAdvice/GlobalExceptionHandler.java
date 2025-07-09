package example.security_oauth2.controllerAdvice;

import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied: " + ex.getMessage());
    }

    @ExceptionHandler(OAuth2AuthenticationException.class)
    public String handleOAuth2AuthenticationException(OAuth2AuthenticationException ex) {
        logger.error("OAuth2 authentication error: {}", ex.getMessage());
        return "redirect:/login?error=" + ex.getMessage();
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<String> handleExpiredJwtException(ExpiredJwtException ex) {
        logger.warn("Token expired: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("JWT token expired: " + ex.getMessage());
    }

    @ExceptionHandler(OAuth2AuthorizationException.class)
    public ResponseEntity<String> handleOAuth2AuthorizationException(OAuth2AuthorizationException ex) {
        logger.error("OAuth2 authorization error: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authorization server error" + ex.getMessage());
    }
}
