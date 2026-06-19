<%@ include file="/include-internal.jsp" %>
<%@ taglib prefix="forms" tagdir="/WEB-INF/tags/forms" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<c:url var="saveUrl" value="${saveUrl}"/>

<bs:linkCSS dynamic="${true}">
  /css/admin/adminMain.css
</bs:linkCSS>

<div>
  <form id="oidcSignerForm" action="${saveUrl}" method="POST">
    <table class="runnerFormTable">
      <tr class="groupingTitle">
        <td colspan="2">Global Settings</td>
      </tr>
      <tr>
        <th><label for="issuer">Issuer URL:</label></th>
        <td>
          <forms:textField name="issuer" id="issuer" value="${issuer}" className="longField"/>
          <span class="error" id="error_issuer"></span>
          <span class="smallNote">Custom issuer URL for the <code>iss</code> claim. Leave empty to use the default (<code><c:out value="${defaultIssuer}"/></code>).</span>
        </td>
      </tr>
      <tr>
        <th><label for="issuerURL">Effective issuer:</label></th>
        <td>
          <div id="clipboardOidcIssuerURL" class="clipboard-btn tc-icon icon16 tc-icon_copy" data-clipboard-action="copy"
                data-clipboard-target="#issuerURL"></div><code id="issuerURL"><c:out value="${effectiveIssuer}"/></code>
          <span class="smallNote">
            Provide this URL to the OIDC token consumer if your TeamCity instance is publicly available, or upload&nbsp;the&nbsp;<a href="<c:out value="${jwksURL}"/>" target="_blank" download="<c:out value="${jwksFilename}"/>">JWKS</a>
            and <a href="<c:out value="${configURL}"/>" target="_blank" download="<c:out value="${configFilename}"/>">OIDC configuration</a> to a publicly available server, or directly to the consumer.
          </span>
        </td>
      </tr>
      <tr>
        <th><label for="signerId">Active Signer:</label></th>
        <td>
          <forms:select name="signerId" id="signerId">
            <c:forEach var="signer" items="${signers}">
              <forms:option value="${signer.id}" selected="${signer.id == activeSignerId}">
                <c:out value="${signer.displayName}"/>
              </forms:option>
            </c:forEach>
          </forms:select>
          <span class="error" id="error_signerId"></span>
          <span class="smallNote">Choose the JWT signer used for OIDC token generation.</span>
        </td>
      </tr>
    </table>

    <c:forEach var="signer" items="${signers}">
      <c:if test="${not empty signer.settingsPagePath}">
        <div id="signerSettings_${signer.id}" class="signerSettingsPanel" style="${signer.id == activeSignerId ? '' : 'display:none;'}">
          <c:set var="signer" value="${signer}" scope="request"/>
          <jsp:include page="${signer.settingsPagePath}"/>
        </div>
      </c:if>
    </c:forEach>

    <table class="runnerFormTable">
      <tr class="groupingTitle">
        <td colspan="2">Global Actions</td>
      </tr>
      <tr>
        <th>Purge JWK cache:</th>
        <td>
          <button type="button" class="btn btn_mini" id="purgeJwkCache" onclick="doPurgeJwkCache(); return false;">
            Purge cache now
          </button>
          <span class="error" id="error_purgeJwkCache"></span>
          <span class="smallNote">
            Removes all cached keys from JWKS, effectively invalidating tokens signed with keys other than the current&nbsp;one.
            <c:if test="${not empty issuer}">
              To invalidate older tokens after key rotation when using an externally hosted JWKS file, upload an <a href="<c:out value="${jwksURL}"/>" target="_blank" download="<c:out value="${jwksFilename}"/>">up-to-date JWKS</a> to the external host instead.
            </c:if>
          </span>
          <br>
          <span class="smallNote">
            The same operation can be triggered programmatically by sending a POST request to<br><code><c:out value="${jwkCachePurgeURL}"/></code>.
            Requires the <code><c:out value="${jwkCachePurgeRequiredPermission}"/></code> permission.
          </span>
        </td>
      </tr>
    </table>

    <div class="saveButtonsBlock">
      <forms:submit label="Save" onclick="return saveOidcSettings();"/>
    </div>
  </form>
</div>

<script type="text/javascript">
  (function() {
    var signerSelect = $('signerId');
    if (signerSelect) {
      signerSelect.on('change', function() {
        $$('.signerSettingsPanel').each(function(el) { el.hide(); });
        var panel = $('signerSettings_' + signerSelect.value);
        if (panel) panel.show();
      });
    }

    BS.Clipboard('#clipboardOidcIssuerURL');
  })();

  function clearErrors() {
    $('error_issuer').innerHTML = '';
    $('error_signerId').innerHTML = '';
    $('error_purgeJwkCache').innerHTML = '';
    $$('.signerSettingsPanel .error').each(function(el) { el.innerHTML = ''; });
  }

  function doPurgeJwkCache() {
    var errorEl = $('error_purgeJwkCache');
    if (errorEl) errorEl.innerHTML = '';
    BS.confirmDialog.show({
      title: "Purge JWK cache?",
      text: 'All tokens signed with keys other than the current one will become invalid.<c:if test="${not empty issuer}"><br><br>Note: to invalidate older tokens when using externally hosted JWKS files, upload an <a href="<c:out value="${jwksURL}"/>" target="_blank" download="<c:out value="${jwksFilename}"/>">up-to-date JWKS</a> to the external host instead.</c:if>',
      actionButtonText: "Purge cache",
      cancelButtonText: "Cancel",
      action: function() {
        BS.ajaxRequest('<c:out value="${jwkCachePurgeURL}"/>', {
          method: 'POST',
          onComplete: function(transport) {
            var hadErrors = BS.XMLResponse.processErrors(transport.responseXML, {
              onJwkCachePurgeError: function(elem) {
                if (errorEl) errorEl.innerHTML = elem.firstChild.nodeValue;
              }
            });
            if (!hadErrors) BS.reload(true);
          }
        });
      }
    });
  }

  function saveOidcSettings() {
    clearErrors();
    BS.ajaxRequest('${saveUrl}', {
      parameters: BS.Util.serializeForm($('oidcSignerForm')),
      onComplete: function(transport) {
        var errors = BS.XMLResponse.processErrors(transport.responseXML, {
          onIssuerError: function(elem) {
            $('error_issuer').innerHTML = elem.firstChild.nodeValue;
          },
          onSignerIdError: function(elem) {
            $('error_signerId').innerHTML = elem.firstChild.nodeValue;
          }
        }, function(id, elem) {
          var el = $(id);
          if (el) el.innerHTML = elem.firstChild.nodeValue;
        });
        if (!errors) {
          BS.reload(true);
        }
      }
    });
    return false;
  }
</script>
