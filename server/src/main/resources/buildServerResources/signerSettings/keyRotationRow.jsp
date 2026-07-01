<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<tr>
  <th>Manual key rotation:</th>
  <td>
    <button type="button" class="btn btn_mini" id="rotateBuiltin${param.signerKind}Key"
            onclick="doRotateBuiltin${param.signerKind}Key(); return false;"
            <c:if test="${param.active != 'true'}">disabled</c:if>>
      Rotate key now
    </button>
    <span class="error" id="error_rotateBuiltin${param.signerKind}Key"></span>
    <c:if test="${not empty signer.settings.keyRotationLastError}">
    <span class="error" id="error_rotateBuiltin${param.signerKind}KeyLastError">Error rotating key: <code><c:out value="${signer.settings.keyRotationLastError}" /></code></span>
    </c:if>
    <c:choose>
      <c:when test="${param.active != 'true'}">
        <span class="smallNote">Key rotation is available only when this signer is the active one. Save your changes first.</span>
      </c:when>
      <c:otherwise>
        <span class="smallNote">
          Generates a new ${param.keyTypeName} immediately. The current key file is renamed and kept as an encrypted backup; a fresh key is created on next use.
          <c:if test="${not empty issuer}">
            <span style="color:#cc3300;">All previously issued tokens will become invalid until you update the externally hosted JWKS.</span>
          </c:if>
        </span>
      </c:otherwise>
    </c:choose>
    <br>
    <span class="smallNote">
      The same operation can be triggered programmatically by sending a POST request to<br><code><c:out value="${param.rotationEndpoint}"/></code>.
      Requires the <code><c:out value="${signer.settings.rotationRequiredPermission.getDescription()}"/></code> permission.
    </span>
    <script type="text/javascript">
      function doRotateBuiltin${param.signerKind}Key() {
        var errorEl = $('error_rotateBuiltin${param.signerKind}Key');
        if (errorEl) errorEl.innerHTML = '';
        BS.confirmDialog.show({
          title: "Rotate the ${param.signerDisplayName} signing key now?",
          text: '<c:if test="${not empty issuer}"><span style="color:#cc3300;">All previously issued tokens will become invalid until you update the externally hosted JWKS.</span> </c:if>The current key will be kept as an encrypted backup. <br><br>Please note that in a multi-node setup, this change takes about 5 minutes to propagate.',
          actionButtonText: "Rotate key",
          cancelButtonText: "Cancel",
          action: function() {
            BS.ajaxRequest('<c:out value="${param.rotationEndpoint}"/>', {
              method: 'POST',
              onComplete: function(transport) {
                var hadErrors = BS.XMLResponse.processErrors(transport.responseXML, {
                  onRotationError: function(elem) {
                    if (errorEl) errorEl.innerHTML = elem.firstChild.nodeValue;
                  }
                });
                if (!hadErrors) BS.reload(true);
              }
            });
          }
        });
      }
    </script>
  </td>
</tr>
