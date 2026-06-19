package org.jetbrains.teamcity.builds.oidc.api;

public class JWTSignerUnavailableException extends JWTSignerException {
    public JWTSignerUnavailableException(String message) {
        super(message);
    }

    public JWTSignerUnavailableException(Throwable cause) {
        super(cause);
    }

    public JWTSignerUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
