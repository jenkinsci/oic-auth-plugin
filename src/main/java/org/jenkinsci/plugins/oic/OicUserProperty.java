package org.jenkinsci.plugins.oic;

import java.io.StringWriter;
import java.util.Arrays;
import java.util.logging.Logger;

import org.acegisecurity.GrantedAuthority;

import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;

public class OicUserProperty extends UserProperty {

    public static class Descriptor extends UserPropertyDescriptor {

		@Override
		public UserProperty newInstance(User user) {
			LOGGER.fine("OicUserPropertyDescriptor.newInstance called, user:" + user);
			return new OicUserProperty(user.getId(), new GrantedAuthority[0]);
		}

		@Override
		public String getDisplayName() {
			return "OpenID Connect user property";
		}
    	
    }

	private static final Logger LOGGER = Logger.getLogger(OicUserProperty.class.getName());

	private final GrantedAuthority[] authorities;
	private final String userName;

	public OicUserProperty(String userName, GrantedAuthority[] authorities) {
		this.userName = userName;
		this.authorities = Arrays.copyOf(authorities, authorities.length);
	}
	public GrantedAuthority[] getAuthorities() {
		return Arrays.copyOf(authorities, authorities.length);
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

	@Override
	public UserPropertyDescriptor getDescriptor() {
		return new Descriptor();
	}
}