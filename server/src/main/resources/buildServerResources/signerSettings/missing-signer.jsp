<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<table class="runnerFormTable">
  <tr class="groupingTitle">
    <td colspan="2">Signer Settings</td>
  </tr>
  <tr>
    <td colspan="2">
      <span class="error">
        The active signer <code><c:out value="${signer.id}"/></code> is currently missing or disabled, so its settings cannot be edited.
      </span>
      <span class="error">
        You can still save global settings. This will not affect the currently saved settings of the disabled signer. However, builds
        relying on OIDC tokens will fail until you change the current signer or enable the missing one.
      </span>
    </td>
  </tr>
</table>
