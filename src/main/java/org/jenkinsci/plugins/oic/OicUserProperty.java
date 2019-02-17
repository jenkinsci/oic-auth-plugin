package org.jenkinsci.plugins.oic;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import org.acegisecurity.GrantedAuthority;

import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import org.acegisecurity.GrantedAuthorityImpl;

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

	private final List<String> authorities = new ArrayList<String>();
	private final String userName;

	public OicUserProperty(String userName, GrantedAuthority[] authorities) {
		this.userName = userName;
		for(GrantedAuthority authority : authorities) {
			this.authorities.add(authority.getAuthority());
		}
	}

	public List<String> getAuthorities() {
		return Collections.unmodifiableList(authorities);
	}

	public GrantedAuthority[] getAuthoritiesAsGrantedAuthorities() {
		GrantedAuthority[] authorities = new GrantedAuthority[this.authorities.size()];
		for(int i=0; i<authorities.length; i++) {
			authorities[i] = new GrantedAuthorityImpl(this.authorities.get(i));
		}
		return authorities;
	}
	
	public String getAllGrantedAuthorities() {
		StringBuilder result = new StringBuilder();
		result.append("Number of GrantedAuthorities in OicUserProperty for ").append(userName).append(": ").append(authorities.size());
		for (String authority: authorities) {
			result.append("<br>\nAuthority: ").append(authority);
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