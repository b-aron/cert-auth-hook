<%@ include file="/html/portlet/login/init.jsp" %>

<c:choose>
	<c:when test="<%= themeDisplay.isSignedIn() %>">

		<%
		String signedInAs = HtmlUtil.escape(user.getFullName());

		if (themeDisplay.isShowMyAccountIcon()) {
			signedInAs = "<a href=\"" + HtmlUtil.escape(themeDisplay.getURLMyAccount().toString()) + "\">" + signedInAs + "</a>";
		}
		%>

		<%= LanguageUtil.format(pageContext, "you-are-signed-in-as-x", signedInAs) %>
	</c:when>
	<c:otherwise>
		<c:choose>
			<c:when test="<%= !request.isSecure() %>">
				<aui:a href="<%= HtmlUtil.escape(themeDisplay.getURLSignIn()) %>" label="sign-in" />
			</c:when>
			<c:otherwise>
				<div class="portlet-msg-error">
					<liferay-ui:message key="authentication-not-possible-missing-cert" />
				</div>
			</c:otherwise>
		</c:choose>
	</c:otherwise>
</c:choose>