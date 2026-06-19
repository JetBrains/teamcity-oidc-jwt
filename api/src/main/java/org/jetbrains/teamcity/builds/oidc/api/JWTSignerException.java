package org.jetbrains.teamcity.builds.oidc.api;

public class JWTSignerException extends Exception {
    public JWTSignerException(String message) {
        super(message);
    }

    public JWTSignerException(Throwable cause) {
        super(cause);
    }

    public JWTSignerException(String message, Throwable cause) {
        super(message, cause);
    }
}
