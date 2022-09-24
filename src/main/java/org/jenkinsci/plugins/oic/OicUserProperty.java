package org.jenkinsci.plugins.oic;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;

public class OicUserProperty extends UserProperty {

    public static class Descriptor extends UserPropertyDescriptor {

		@Override
		public UserProperty newInstance(User user) {
			LOGGER.fine("OicUserPropertyDescriptor.newInstance called, user:" + user);
			return new OicUserProperty(user.getId(), new ArrayList<GrantedAuthority>());
		}

		@Override
		public String getDisplayName() {
			return Messages.openid_connect_user_property();
		}
    	
    }

	private static final Logger LOGGER = Logger.getLogger(OicUserProperty.class.getName());

	private final List<String> authorities = new ArrayList<>();
	private final String userName;

	public OicUserProperty(String userName, Collection<? extends GrantedAuthority> authorities) {
		this.userName = userName;
		for(GrantedAuthority authority : authorities) {
			this.authorities.add(authority.getAuthority());
		}
	}

	public List<String> getAuthorities() {
		return Collections.unmodifiableList(authorities);
	}

	public List<GrantedAuthority> getAuthoritiesAsGrantedAuthorities() {
		List<GrantedAuthority> authorities = new ArrayList<>();
		for(String auth : this.authorities)
			authorities.add(new SimpleGrantedAuthority(auth));

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