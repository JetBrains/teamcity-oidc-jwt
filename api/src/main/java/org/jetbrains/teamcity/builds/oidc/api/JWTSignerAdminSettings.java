package org.jetbrains.teamcity.builds.oidc.api;

import org.jetbrains.annotations.NotNull;

import java.util.Map;

/**
 * Optional admin UI settings for a {@link JWTSigner}.
 * <p>
 * Implementations provide a JSP fragment for signer-specific configuration,
 * populate the view model, and persist submitted form parameters.
 * A signer that has no configurable settings returns {@code null} from
 * {@link JWTSigner#getAdminSettings()}.
 */
public interface JWTSignerAdminSettings {
    /**
     * Returns the path to a JSP fragment for signer-specific settings.
     *
     * @return JSP resource path
     */
    @NotNull String getSettingsPagePath();

    /**
     * Populates model entries needed by this signer's settings JSP fragment.
     *
     * @param model the model map to populate
     */
    void fillSettingsModel(@NotNull Map<String, Object> model);

    /**
     * Receives signer-specific settings form parameters to validate.
     *
     * @param params form parameters from the admin page
     * @return map of field names to error messages; empty map means success.
     *         Keys should match the field identifiers used in error span IDs
     *         within the signer's settings JSP fragment.
     */
    @NotNull Map<String, String> validateSettings(@NotNull Map<String, String> params);

    /**
     * Receives signer-specific settings form parameters to persist. The caller guarantees that
     * the params map was validated successfully by {@link #validateSettings(Map)}.
     *
     * @param params validated form parameters from the admin page
     * @return map of field names to error messages; empty map means success.
     *         Keys should match the field identifiers used in error span IDs
     *         within the signer's settings JSP fragment.
     */
    @NotNull Map<String, String> saveSettings(@NotNull Map<String, String> params);
}
