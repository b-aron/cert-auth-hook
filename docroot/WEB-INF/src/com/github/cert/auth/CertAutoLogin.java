/**
 * Copyright (c) 2000-2011 Áron Budea. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.github.cert.auth;

import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.model.CompanyConstants;
import com.liferay.portal.model.User;
import com.liferay.portal.security.auth.AutoLogin;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.util.PortalUtil;

import java.nio.charset.Charset;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CertAutoLogin implements AutoLogin {

	public String[] login(
		HttpServletRequest request, HttpServletResponse response) {

			// authType should either be emailAddress, screenName or userId
			// corresponding certificate attribute authAttr is typically
			// "emailaddress", "cn" and "uid" respectively
			// however Java transforms emailaddress into OID + ASN.1 DER

			final String authType = CompanyConstants.AUTH_TYPE_SN;
			final String authAttr = _ATTR_CN;

			String[] credentials = null;

			if (!request.isSecure()) {
				return credentials;
			}

			long companyId = PortalUtil.getCompanyId(request);

			X509Certificate[] certs;
			certs = (X509Certificate[]) request.getAttribute(
				"javax.servlet.request.X509Certificate");
			if (certs == null) {
				return credentials;
			}

			Collection altNames;

			for (int i = 0; i < certs.length && credentials == null; i++) {

				altNames = null;
				try {
					altNames = certs[i].getSubjectAlternativeNames();
				}
				catch (CertificateParsingException cpe) {
				}

				credentials = _identify(
					authAttr, authType, companyId,
					certs[i].getSubjectX500Principal().getName(),
					altNames);
			}

			return credentials;
	}

	private String _derIA5StringToString(byte[] derIA5String) {
		// DER encoded IA5String to String conversion
		String result = new String(derIA5String, Charset.forName("US-ASCII"));

		// 22 (0x16) as 1st byte defines IA5String
		if (derIA5String.length < 2 || derIA5String[0] != 22) {
			return null;
		}

		// 2nd byte is size, if 1st bit = 0, or
		// size is defined by the value in the following N bytes, where
		// N = 2nd byte's last 7 bits
		int size = 0;
		if (derIA5String[1] < 0) {
			// 1st bit = 1
			// Max length of e-mail address is 254 chars, size fits in 1 byte
			size = 1;
		}
		result = result.substring(2 + size);

		return result;
	}

	private String[] _findCredentials(
			String authType, long companyId, String userIdent) {

		String[] credentials = null;

		if (Validator.isNull(userIdent)) {
			return credentials;
		}

		User user = null;

		try {
			if (authType.equals(CompanyConstants.AUTH_TYPE_SN)) {
				user = UserLocalServiceUtil.getUserByScreenName(
					companyId, userIdent);
			}
			else if (authType.equals(CompanyConstants.AUTH_TYPE_ID)) {
				user = UserLocalServiceUtil.getUserById(
					Long.parseLong(userIdent));
			}
			else if (authType.equals(CompanyConstants.AUTH_TYPE_EA)) {
				user = UserLocalServiceUtil.getUserByEmailAddress(
					companyId, userIdent);
			}
			String password = user.getPassword();

			credentials = new String[3];
			credentials[0] = String.valueOf(user.getUserId());
			credentials[1] = password;
			credentials[2] = Boolean.TRUE.toString();
		}
		catch (Exception e) {
		}

		return credentials;

	}

	private String[] _identify(
		String authAttr, String authType, long companyId,
		String distinguishedName, Collection altNames) {

		String[] credentials = null;
		LdapName ldName = null;

		try {
			ldName = new LdapName(distinguishedName);
		}
		catch (InvalidNameException ine) {
			return credentials;
		}

		String userIdent = null;

		for (Rdn rdn : ldName.getRdns()) {
			String attr = rdn.getType();
			if (attr.toLowerCase().equals(authAttr)) {
				if (authAttr.equals(_ATTR_EMAIL)) {
					userIdent = _derIA5StringToString((byte[])rdn.getValue());
				}
				else {
					userIdent = rdn.getValue().toString();
				}
				credentials = _findCredentials(authType, companyId, userIdent);
				if (credentials != null) {
					break;
				}
			}
		}

		// If no credentials found in DN, and auth is e-mail,
		// try Subject Alternative Name extension
		if (credentials == null
				&& authType.equals(CompanyConstants.AUTH_TYPE_EA)
				&& altNames != null) {
			Iterator altNameIterator = altNames.iterator();
			while (altNameIterator.hasNext()) {
				List altName = (List)altNameIterator.next();

				// 1 as list's 1st item means 2nd is rfc822Name (e-mail addr.)
				if (((Integer)altName.get(0)).intValue() == 1) {
					userIdent = (String)altName.get(1);
					credentials = _findCredentials(
						authType, companyId, userIdent);
					if (credentials != null) {
						break;
					}
				}
			}
		}
		return credentials;
	}

	private final static String _ATTR_CN = "cn";
	private final static String _ATTR_EMAIL = "1.2.840.113549.1.9.1";
	private final static String _ATTR_UID = "uid";

}