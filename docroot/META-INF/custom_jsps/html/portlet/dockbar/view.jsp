<%@ include file="/html/portlet/dockbar/init.jsp" %>

<liferay-util:buffer var="html">

	<liferay-util:include page="/html/portlet/dockbar/view.portal.jsp" />

</liferay-util:buffer>

<%
int x = html.indexOf("<span class=\"sign-out\">");

if (x != -1) {
	int y = html.indexOf("</span>", x);
	html = html.replace(html.substring(x, y + 7), StringPool.BLANK);
}
%>


<%= html %>