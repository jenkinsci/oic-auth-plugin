package org.jenkinsci.plugins.oic;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;

import java.io.IOException;

@Extension
public class EscapeHatchCrumbExclusion extends CrumbExclusion {
	
	@Override
	public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String pathInfo = request.getPathInfo();
		if (pathInfo != null && "/securityRealm/escapeHatch".equals(pathInfo)) {
			chain.doFilter(request, response);
			return true;
		}
		return false;
	}
}
