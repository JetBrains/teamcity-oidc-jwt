<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<table class="runnerFormTable">
  <tr class="groupingTitle">
    <td colspan="2">Built-in (RSA) Settings</td>
  </tr>
  <tr>
    <th>Key file location:</th>
    <td>
      <code><c:out value="${signer.settings.keyFilePath}"/></code>
      <span class="smallNote">The RSA key pair is stored in this file, encrypted with TeamCity server encryption. Backups of regenerated keys are stored in the same directory.</span>
    </td>
  </tr>
  <tr>
    <th>Key fingerprint:</th>
    <td>
      <code><c:out value="${signer.settings.keyFingerprint}"/></code>
      <span class="smallNote">SHA-256 thumbprint of the current RSA key (used as <code>kid</code> in JWT headers).</span>
    </td>
  </tr>
  <tr>
    <th><label for="builtinRsaKeyBits">RSA key size:</label></th>
    <td>
      <select name="${signer.paramPrefix}rsaKeyBits" id="builtinRsaKeyBits" class="longField">
        <c:forEach var="bits" items="${signer.settings.allowedRsaKeyBits}">
          <option value="${bits}" ${bits == signer.settings.rsaKeyBits ? 'selected="selected"' : ''}>${bits} bits</option>
        </c:forEach>
      </select>
      <span class="error" id="${signer.errorPrefix}rsaKeyBits"></span>
      <span class="smallNote">Key size for RSA key generation. Changing this value will regenerate the signing key.
        An encrypted backup copy of the current private key will be saved.
        <c:if test="${not empty issuer}">
          <span style="color:#cc3300;">All previously issued tokens will become invalid until you update the externally hosted JWKS.</span>
        </c:if>
      </span>

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
      <span class="smallNote">The JWS algorithm advertised in the OpenID configuration and used in the JWT header. Changing this value does not regenerate the signing key. Note: some token consumers only support <code>RS256</code>.</span>
    </td>
  </tr>
  <jsp:include page="keyRotationRow.jsp">
    <jsp:param name="signerKind" value="Rsa"/>
    <jsp:param name="signerDisplayName" value="RSA"/>
    <jsp:param name="keyTypeName" value="RSA key"/>
    <jsp:param name="rotationEndpoint" value="${signer.settings.rotationEndpoint}"/>
    <jsp:param name="active" value="${signer.id == activeSignerId}"/>
  </jsp:include>
</table>
