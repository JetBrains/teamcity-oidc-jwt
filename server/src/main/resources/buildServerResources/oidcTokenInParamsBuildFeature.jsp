<%@ page import="org.jetbrains.teamcity.builds.oidc.OIDCConstants" %>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<% pageContext.setAttribute("audienceParam", OIDCConstants.BuildFeatureInParams.AUDIENCES_PARAM); %>
<% pageContext.setAttribute("defaultParamName", OIDCConstants.BuildFeatureInParams.DEFAULT_BUILDPARAM); %>

<%-- This is not a typo, we need display name of on-demand feature --%>
<% pageContext.setAttribute("onDemandDisplayName", OIDCConstants.BuildFeatureOnDemand.DISPLAY_NAME); %>


<tr>
  <td colspan="2">
    <em>
      This build feature provides a JWT with specified audiences via build parameters or an environment variable.
      <br/><br/>
      If you would like to issue short-lived tokens on demand during the build, use <code><c:out value="${onDemandDisplayName}" /></code> build feature instead.
    </em>
  </td>
</tr>
<tr>
  <th><label for="${audienceParam}">Audiences:</label></th>
  <td>
    <props:multilineProperty name="${audienceParam}" linkTitle="" cols="40" rows="5" expanded="true"/>
    <span class="smallNote">Newline-separated list of audience values for the <code>aud</code> claim in the JWT.</span>
  </td>
</tr>
<tr>
  <th><label for="oidcIssuerURL">Issuer:</label></th>
  <td>
    <div id="clipboardOidcIssuer" class="clipboard-btn tc-icon icon16 tc-icon_copy" data-clipboard-action="copy"
          data-clipboard-target="#oidcIssuerURL"></div><code id="oidcIssuerURL"><c:out value="${issuer}"/></code>
    <span class="smallNote">Provide this URL to the OIDC token consumer, or upload&nbsp;the&nbsp;<a href="<c:out value="${jwksURL}"/>" target="_blank" download="<c:out value="${jwksFilename}"/>">JWKS</a>&nbsp;directly.</span>
  </td>
</tr>
<c:if test="${!empty sub}">
<tr>
  <th><label for="oidcSub"><code>sub</code> claim:</label></th>
  <td>
    <div id="clipboardSub" class="clipboard-btn tc-icon icon16 tc-icon_copy" data-clipboard-action="copy"
         data-clipboard-target="#oidcSub"></div><code id="oidcSub"><c:out value="${sub}"/></code>
    <span class="smallNote">This value will be used as the <code>sub</code> claim in JWTs issued for builds of this build configuration.</span>
  </td>
</tr>
</c:if>

<tr>
  <th><label for="buildParam">Build parameter:</label></th>
  <td>
    <props:textProperty name="buildParam" className="mediumField"/>
    <span class="smallNote">
      Build parameter for the token. Leave empty to use the default parameter name (<code>${defaultParamName}</code>).
    </span>
  </td>
</tr>

<tr class="advancedSetting">
  <th><label for="tokenLifetimeSeconds">Token lifetime:</label></th>
  <td>
    <props:textProperty name="tokenLifetimeSeconds" className="mediumField"/>
    <span class="error" id="error_tokenLifetimeSeconds"></span>
    <span class="smallNote">
      Seconds before the token provided via build parameters expires. Use empty, negative or zero value for
      the default token lifetime <code>(${defaultTimeoutSeconds}&nbsp;seconds after&nbsp;build&nbsp;timeout)</code>.
    </span>
  </td>
</tr>

<script type="text/javascript">
  BS.Clipboard('#clipboardOidcIssuer');
  BS.Clipboard('#clipboardSub');
</script>
