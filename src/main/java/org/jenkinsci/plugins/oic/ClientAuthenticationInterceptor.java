package org.jenkinsci.plugins.oic;

import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.util.Data;
import com.google.api.client.util.Preconditions;
import java.io.IOException;
import java.util.Map;

public class ClientAuthenticationInterceptor implements HttpExecuteInterceptor {

  private final String clientId;
  private final String clientSecret;
  private final boolean useBasicAuth;

  public ClientAuthenticationInterceptor(String clientId, String clientSecret, boolean useBasicAuth) {
    this.clientId = Preconditions.checkNotNull(clientId);
    this.clientSecret = clientSecret;
    this.useBasicAuth = useBasicAuth;
  }

  @Override
  public void intercept(HttpRequest httpRequest) throws IOException {
    addUriParameters(httpRequest);
    addBasicAuth(httpRequest);
  }

  private void addUriParameters(HttpRequest httpRequest) {
    Map<String, Object> data = Data.mapOf(UrlEncodedContent.getContent(httpRequest).getData());
    data.put("client_id", this.clientId);
    if (!useBasicAuth && this.clientSecret != null) {
      data.put("client_secret", this.clientSecret);
    }
  }

  private void addBasicAuth(HttpRequest httpRequest) {
    if (useBasicAuth) {
      HttpHeaders headers = httpRequest
          .getHeaders()
          .setBasicAuthentication(clientId, clientSecret);
      httpRequest.setHeaders(headers);
    }
  }
}
