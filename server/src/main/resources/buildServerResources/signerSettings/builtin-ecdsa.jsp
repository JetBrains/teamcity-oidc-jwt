<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="bs" tagdir="/WEB-INF/tags" %>

<table class="runnerFormTable">
  <tr class="groupingTitle">
    <td colspan="2">Built-In (ECDSA) Settings</td>
  </tr>
  <tr>
    <th>Key file location:</th>
    <td>
      <code><c:out value="${signer.settings.keyFilePath}"/></code>
      <span class="smallNote">The EC key pair is stored in this file, encrypted with TeamCity server encryption. Backups of regenerated keys are stored in the same directory.</span>
    </td>
  </tr>
  <tr>
    <th>Key fingerprint:</th>
    <td>
      <code><c:out value="${signer.settings.keyFingerprint}"/></code>
      <span class="smallNote">SHA-256 thumbprint of the current EC key (used as <code>kid</code> in JWT headers).</span>
    </td>
  </tr>
  <tr>
    <th><label for="builtinJwsAlgorithm">JWT signature algorithm:</label></th>
    <td>
      <select name="${signer.paramPrefix}jwsAlgorithm" id="builtinJwsAlgorithm" class="longField">
        <c:forEach var="alg" items="${signer.settings.allowedJwsAlgorithms}">
          <option value="${alg}" ${alg == signer.settings.jwsAlgorithm ? 'selected="selected"' : ''}>${alg}</option>
        </c:forEach>
      </select>
      <span class="error" id="${signer.errorPrefix}jwsAlgorithm"></span>
      <span class="smallNote">
        The JWS algorithm advertised in the OpenID configuration and used in the JWT header.
        Changing this value will regenerate the signing key. <span class="icon icon16 tc-icon_help_grey"
              <bs:tooltipAttrs containerId="ecAlgoKeyHelp"/>></span> An encrypted backup copy of the current private key will be saved.
        <c:if test="${not empty issuer}">
          <span style="color:#cc3300;">All previously issued tokens will become invalid until you update the externally hosted JWKS.</span>
        </c:if>
      </span>
      <div id="ecAlgoKeyHelp" style="display: none">
        Each ECDSA algorithm uses a different curve (<code>ES256</code> uses <code>P-256</code>, <code>ES384</code> uses <code>P-384</code>, <code>ES512</code> uses <code>P-521</code>).
        Keys using one curve cannot be used with another.
      </div>
    </td>
  </tr>
  <jsp:include page="keyRotationRow.jsp">
    <jsp:param name="signerKind" value="Ecdsa"/>
    <jsp:param name="signerDisplayName" value="ECDSA"/>
    <jsp:param name="keyTypeName" value="EC key"/>
    <jsp:param name="rotationEndpoint" value="${signer.settings.rotationEndpoint}"/>
    <jsp:param name="active" value="${signer.id == activeSignerId}"/>
  </jsp:include>
</table>
