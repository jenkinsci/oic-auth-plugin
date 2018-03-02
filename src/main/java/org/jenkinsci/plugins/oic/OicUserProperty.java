package org.jenkinsci.plugins.oic;

import java.io.StringWriter;
import java.util.logging.Logger;

import org.acegisecurity.GrantedAuthority;

import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;

class OicUserProperty extends UserProperty {
	private static final Logger LOGGER = Logger.getLogger(OicUserProperty.class.getName());
    static class OicUserPropertyDescriptor extends UserPropertyDescriptor {

		@Override
		public UserProperty newInstance(User user) {
			LOGGER.info("OicUserPropertyDescriptor.newInstance called, user:" + user);
			return new OicUserProperty(user.getId(), new GrantedAuthority[0]);
		}

		@Override
		public String getDisplayName() {
			return "OpenID Connect user property";
		}
    	
    }
	@Override
	public UserPropertyDescriptor getDescriptor() {
		return new OicUserPropertyDescriptor();
	}
	private GrantedAuthority[] authorities;
	private String userName;

	public OicUserProperty(String userName, GrantedAuthority[] authorities) {
		this.userName = userName;
		this.authorities = authorities;
	}
	public GrantedAuthority[] getAuthorities() {
		return authorities;
	}
	
	public String getAllGrantedAuthorities() {
		StringWriter result = new StringWriter();
		result.append("Number of GrantedAuthorities in OicUserProperty for " + userName + ": " + (authorities == null ? "null" : authorities.length));
		if (authorities != null) {
			for (GrantedAuthority a: authorities) {
				result.append("<br>\nAuthority: " + a.getAuthority());
			}
		}
		return result.toString();
	}
	
	public String getUserName() {
		return userName;
	}
}