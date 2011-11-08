X.509 Certificate Authentication for Liferay Portal
===================================================

This hook enables certificate-based authentication in Liferay Portal.

Behavior
--------

This is an *Auto Login* hook for Liferay. If the user opens the portal via HTTPS connection, they are asked for their client certificate, and automatically logged in based on the identity information in their certificate that can be directly mapped to Liferay's. If they arrive through HTTP connection, a switch to HTTPS, and login occurs when they attempt to Sign in.

While *Sign out* link is now hidden in *Dockbar*, and *Login portlet* is overridden to hide password login, the functionalities are still there.


Usage
-----

By default the hook authenticates based on Screen Name in field `CN` of subject distinguished name. This can be changed easily in the source code, independently of regular authentication setting `company.security.auth.type`.

In method `login` of `class com.github.cert.auth.CertAutoLogin`, local variables `authType` and `authAttr` control authentication type, and field used for authentication.

* `screenName` / `_ATTR_CN`
* `emailAddress` / `_ATTR_EMAIL`
* `userId` / `_ATTR_UID`

*Note*: According to RFC 2253 and RFC 2580, attributes `CN` and `UID` are available in subject distinguished name, while e-mail addresses should reside in *Subject Alternative Name* extension. However to support legacy implementations, `emailAddress` attribute can be used in subject distinguished name as well.


Prerequisites
-------------

Set up server to accept HTTPS connections, and require client authentication. Implement PKI infrastructure.

Add following settings to portal-ext.properties (ports are just examples):

	company.security.auth.requires.https=true
	web.server.http.port=8080
	web.server.https.port=8443


Notes
-----

**IMPORTANT**: Because phishing protection is not activated upon autologin, regardless of setting `session.enable.phishing.protection`, there is currently a security hole if the user initiates login using HTTP connection. While they are transferred to HTTPS, the cookie JSESSIONID remains available to "Any type of connection", not to "Encrypted connections only". If the user switches back to HTTP connection, their session persists over insecure connection. A workaround is to disable HTTP connections altogether.

If the certificate is invalid, the user receives an error message from the server in the browser: "SSL peer cannot verify your certificate. (Error code: ssl_error_bad_cert_alert)", which is not very helpful.