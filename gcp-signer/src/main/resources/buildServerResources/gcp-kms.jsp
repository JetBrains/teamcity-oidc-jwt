<%@ page import="org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSConstants" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="bs" tagdir="/WEB-INF/tags" %>
<%@ taglib prefix="forms" tagdir="/WEB-INF/tags/forms" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>

<% pageContext.setAttribute("CRED_ENVIRONMENT", CloudKMSConstants.CredentialsType.ENVIRONMENT); %>
<% pageContext.setAttribute("CRED_SERVICE_ACCOUNT_KEY", CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY); %>

<table class="runnerFormTable">
  <tr class="groupingTitle">
    <td colspan="2">Google Cloud KMS Settings</td>
  </tr>
  <tr>
    <th><label for="gcpEndpoint">GCP Endpoint:</label></th>
    <td>
      <forms:textField name="${signer.paramPrefix}gcpEndpoint" id="gcpEndpoint" value="${signer.settings.gcpEndpoint}" className="longField"/>
      <span class="error" id="${signer.errorPrefix}gcpEndpointError"></span>
      <span class="smallNote">Optional. Custom GCP KMS API endpoint (e.g. <code>cloudkms.us-east1.rep.googleapis.com:443</code>). Must be a hostname with a port and no URL scheme. Leave empty to use the default endpoint.</span>
    </td>
  </tr>
  <tr>
    <th><label>Credentials source:</label></th>
    <td>
      <p style="margin-top:0;">
        <label>
          <input type="radio" name="${signer.paramPrefix}credentialsType" id="gcpCredentialsTypeEnv"
                 value="${CRED_ENVIRONMENT}" ${signer.settings.credentialsType == CRED_ENVIRONMENT ? 'checked="checked"' : ''}/>
          Server environment
          <br/>
          <span class="smallNote">Use <a href="https://cloud.google.com/docs/authentication/application-default-credentials" target="_blank">Application Default Credentials</a> from the server environment.</span>
        </label>
      </p>
      <p style="margin-bottom: 0">
        <label>
          <input type="radio" name="${signer.paramPrefix}credentialsType" id="gcpCredentialsTypeSA"
                 value="${CRED_SERVICE_ACCOUNT_KEY}" ${signer.settings.credentialsType == CRED_SERVICE_ACCOUNT_KEY ? 'checked="checked"' : ''}/>
          Service account JSON key
          <br/>
          <span class="smallNote">Use the provided service account private key in JSON format.</span>
        </label>
      </p>
      <span class="error" id="${signer.errorPrefix}credentialsError"></span>
    </td>
  </tr>
  <tr id="gcpServiceAccountKeyRow" style="${signer.settings.credentialsType == CRED_SERVICE_ACCOUNT_KEY ? '' : 'display:none;'}">
    <th><label for="gcpServiceAccountKey">GCP Service account JSON key:<l:star/></label></th>
    <td>
      <forms:file name="${signer.paramPrefix}gcpServiceAccountKeyFile" size="28"/>
      <span class="smallNote">
        <c:if test="${signer.settings.hasServiceAccountKey}">A service account key is already provided. </c:if>
        Upload a key file or <a href="#" id="gcpPasteKeyLink">paste the key contents</a>
        <c:if test="${signer.settings.hasServiceAccountKey}"> to overwrite</c:if>.
      </span>
      <div id="gcpServiceAccountKeyPasteArea" style="display:none; margin-top: 6px;">
        <textarea name="${signer.paramPrefix}serviceAccountKey" id="gcpServiceAccountKey" class="longField" rows="5"
                  placeholder="Paste service account JSON key here"></textarea>
      </div>
      <span class="error" id="${signer.errorPrefix}serviceAccountKey"></span>
    </td>
  </tr>
  <tr>
    <th><label for="gcpImpersonationChain">Impersonate service account:</label></th>
    <td>
      <input type="text" name="${signer.paramPrefix}impersonationChain" id="gcpImpersonationChain"
             value="<c:out value="${signer.settings.impersonationChain}"/>" class="longField"/>
      <span class="error" id="${signer.errorPrefix}impersonationChain"></span>
      <span class="error" id="${signer.errorPrefix}testConnectionImpersonation"></span>
      <span class="smallNote">Optional. Provide a service account email to impersonate. For a delegation chain, separate email addresses with <code>|</code> (e.g. <code>delegate@...&#x7C;target@...</code>), where the last entry is the target service account.</span>
    </td>
  </tr>
  <tr>
    <th>
      <label for="gcpKmsResourceName">Cloud KMS resource name:<l:star/></label>
    </th>
    <td>
      <input type="text" name="${signer.paramPrefix}kmsResourceName" id="gcpKmsResourceName"
             value="<c:out value="${signer.settings.kmsResourceName}"/>" class="longField"/>
      <span class="error" id="${signer.errorPrefix}kmsResourceName"></span>
      <span class="error" id="${signer.errorPrefix}testConnectionKey"></span>
      <span class="smallNote">Resource name of a key <span class="icon icon16 tc-icon_help_grey"
              <bs:tooltipAttrs containerId="gcpKmsKeyHelp"/>></span> or a specific key version <span class="icon icon16 tc-icon_help_grey"
              <bs:tooltipAttrs containerId="gcpKmsKeyVersionHelp"/>></span>
      </span>

      <div id="gcpKmsKeyHelp" style="display: none">
        <code>projects/<i>PROJECT</i>/locations/<i>LOCATION</i>/keyRings/<i>KEY_RING</i>/cryptoKeys/<i>KEY</i></code>
        <br/><br/>
        Uses the first enabled key version returned by Google Cloud (in no particular order). Requires the following permissions:
        <ul>
          <li><code>cloudkms.cryptoKeyVersions.list</code></li>
          <li><code>cloudkms.cryptoKeyVersions.useToSign</code></li>
          <li><code>cloudkms.cryptoKeyVersions.viewPublicKey</code></li>
        </ul>
        (e.g., via <a href="https://docs.cloud.google.com/iam/docs/roles-permissions/cloudkms#cloudkms.viewer" target="_blank"><code>roles/cloudkms.viewer</code></a> and <a href="https://docs.cloud.google.com/iam/docs/roles-permissions/cloudkms#cloudkms.signerVerifier" target="_blank"><code>roles/cloudkms.signerVerifier</code></a>)
      </div>
      <div id="gcpKmsKeyVersionHelp" style="display: none">
        <code>projects/<i>PROJECT</i>/locations/<i>LOCATION</i>/keyRings/<i>KEY_RING</i>/cryptoKeys/<i>KEY</i>/cryptoKeyVersions/<i>VERSION</i></code>
        <br/><br/>
        Uses only the specified key version. Requires the following permissions:
        <ul>
          <li><code>cloudkms.cryptoKeyVersions.useToSign</code></li>
          <li><code>cloudkms.cryptoKeyVersions.viewPublicKey</code></li>
        </ul>
        (e.g., via <a href="https://docs.cloud.google.com/iam/docs/roles-permissions/cloudkms#cloudkms.signerVerifier" target="_blank"><code>roles/cloudkms.signerVerifier</code></a>)
      </div>
    </td>
  </tr>
  <c:if test="${not empty signer.settings.currentKeyVersionName}">
    <tr>
      <th>Current Key Version:</th>
      <td>
        <code><c:out value="${signer.settings.currentKeyVersionName}"/></code>
        <br/>
        <span class="smallNote">
          <c:out value="${signer.settings.currentKeyVersionGCPAlgorithm}"/> /
          <c:out value="${signer.settings.currentKeyVersionJWSAlgorithm}"/>
        </span>
      </td>
    </tr>
  </c:if>
</table>

<script type="text/javascript">
  (function() {
    const envRadio = $('gcpCredentialsTypeEnv');
    const saRadio = $('gcpCredentialsTypeSA');
    const saKeyRow = $('gcpServiceAccountKeyRow');
    const pasteLink = $('gcpPasteKeyLink');
    const pasteArea = $('gcpServiceAccountKeyPasteArea');

    if (!envRadio || !saRadio || !saKeyRow) return;

    envRadio.on('change', function() { saKeyRow.hide(); });
    saRadio.on('change', function() { saKeyRow.show(); });
    if (pasteLink && pasteArea) {
      pasteLink.on('click', function(e) { e.preventDefault(); pasteArea.toggle(); });
    }

    var fileInput = $('file:${signer.paramPrefix}gcpServiceAccountKeyFile');
    var keyTextarea = $('gcpServiceAccountKey');
    if (fileInput && keyTextarea && pasteArea) {
      fileInput.on('change', function() {
        var file = fileInput.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function() {
          keyTextarea.value = reader.result;
          pasteArea.show();
        };
        reader.readAsText(file);
      });
    }
  })();
</script>
