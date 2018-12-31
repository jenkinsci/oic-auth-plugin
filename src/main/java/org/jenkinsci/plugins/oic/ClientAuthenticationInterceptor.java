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
  private final boolean useClientBasicAuthForToken;

  public ClientAuthenticationInterceptor(String clientId, String clientSecret, boolean useClientBasicAuthForToken) {
    this.clientId = Preconditions.checkNotNull(clientId);
    this.clientSecret = clientSecret;
    this.useClientBasicAuthForToken = useClientBasicAuthForToken;
  }

  @Override
  public void intercept(HttpRequest httpRequest) throws IOException {
    addUriParameters(httpRequest);
    addBasicAuth(httpRequest);
  }

  private void addUriParameters(HttpRequest httpRequest) {
    Map<String, Object> data = Data.mapOf(UrlEncodedContent.getContent(httpRequest).getData());
    data.put("client_id", this.clientId);
    if (!useClientBasicAuthForToken && this.clientSecret != null) {
      data.put("client_secret", this.clientSecret);
    }
  }

  private void addBasicAuth(HttpRequest httpRequest) {
    if (useClientBasicAuthForToken) {
      HttpHeaders headers = httpRequest
          .getHeaders()
          .setBasicAuthentication(clientId, clientSecret);
      httpRequest.setHeaders(headers);
    }
  }
}
