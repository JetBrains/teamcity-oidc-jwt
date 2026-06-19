<%@ page import="org.jetbrains.teamcity.builds.oidc.OIDCConstants" %>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<% pageContext.setAttribute("audienceParam", OIDCConstants.BuildFeatureOnDemand.AUDIENCES_PARAM); %>
<%-- This is not a typo, we need display name of in-params feature --%>
<% pageContext.setAttribute("inParamsDisplayName", OIDCConstants.BuildFeatureInParams.DISPLAY_NAME); %>

<tr>
  <td colspan="2">
    <em>
      This build feature allows builds to issue short-lived JWTs via GET requests with <a href="https://www.jetbrains.com/help/teamcity/artifact-dependencies.html#build-level-auth" target="_blank">build-level authentication credentials</a>.
      The endpoint to call is provided in <code><c:out value="${onDemandUrlParam}" /></code> build parameter.
      <br/><br/>
      If you would like to provide the token via build parameters or issue tokens with a longer lifetime, please use <code><c:out value="${inParamsDisplayName}" /></code> build feature instead.
    </em>
  </td>
</tr>
<tr>
  <th><label for="${audienceParam}">Allowed audiences:</label></th>
  <td>
    <props:multilineProperty name="${audienceParam}" linkTitle="" cols="40" rows="5" expanded="true"/>
    <span class="smallNote">Newline-separated list of allowed audience values for the <code>aud</code> claim of the JWT token.</span>
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

<script type="text/javascript">
  BS.Clipboard('#clipboardOidcIssuer');
  BS.Clipboard('#clipboardSub');
</script>
