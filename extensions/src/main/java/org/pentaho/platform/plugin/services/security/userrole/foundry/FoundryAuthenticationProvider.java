package org.pentaho.platform.plugin.services.security.userrole.foundry;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;

import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.AuthenticationProvider;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class FoundryAuthenticationProvider implements AuthenticationProvider {

  private Logger logger = LoggerFactory.getLogger( getClass() );

  private static final String FOUNDRY_AUTHENTICATION_ENDPOINT = "/auth/oauth";

  // required form params
  private static final String FOUNDRY_PARAM_GRANT_TYPE = "grant_type";
  private static final String FOUNDRY_PARAM_USERNAME = "username";
  private static final String FOUNDRY_PARAM_PASSWORD = "password";
  private static final String FOUNDRY_PARAM_REALM = "realm";
  private static final String FOUNDRY_PARAM_CLIENT_SECRET = "client_secret";
  private static final String FOUNDRY_PARAM_CLIENT_ID = "client_id";

  private boolean useHttps = true; // default
  private String hostname;
  private Integer port;
  private String realm;
  private String grantType;
  private String clientSecret;
  private String clientId;

  @Override
  public Authentication authenticate( Authentication authentication ) throws AuthenticationException {


    HttpPost httpPost = null;

    try {

      new HttpPost( buildEndpoint().toString() );
      httpPost.addHeader( new BasicHeader( HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON ) );
      httpPost.addHeader( new BasicHeader( HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED ) );

      String user = "batman"; // TODO
      String pass = "Pentaho06"; // TODO

      httpPost.setEntity( new UrlEncodedFormEntity( buildPostParameters( user, pass ), StandardCharsets.UTF_8 ));

      getLogger().info( "Sending auth request to {1} for username {2}" , buildEndpoint().toString(), authentication.getPrincipal() );
      HttpResponse response = HttpClients.createDefault().execute( httpPost );
      int statusCode = response.getStatusLine().getStatusCode();
      getLogger().info( "Received auth response of {1}" , statusCode );

    } catch ( URISyntaxException e ) {
      getLogger().error( e.getLocalizedMessage(), e );

    } catch ( IOException e ) {
      getLogger().error( e.getLocalizedMessage(), e );
    }

    return null; // TODO
  }

  @Override
  public boolean supports( Class<?> aClass ) {
    return UsernamePasswordAuthenticationToken.class.getName().equals( aClass );
  }

  protected URI buildEndpoint() throws URISyntaxException {

    return new URIBuilder()
            .setScheme( isUseHttps() ? "https" : "http" )
            .setHost( getHostname() )
            .setPort( getPort() )
            .setPath( FOUNDRY_AUTHENTICATION_ENDPOINT )
            .build();
  }

  protected ArrayList<NameValuePair> buildPostParameters( String username, String password ) {
    ArrayList<NameValuePair> postParameters = new ArrayList<>();

    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_USERNAME, username ) );
    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_PASSWORD, password ) );
    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_REALM, getRealm() ) );
    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_CLIENT_ID, getClientId() ) );
    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_CLIENT_SECRET, getClientSecret() ) );
    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_GRANT_TYPE, getGrantType() ) );

    return postParameters;
  }

  public boolean isUseHttps() {
    return useHttps;
  }

  public void setUseHttps(boolean useHttps) {
    this.useHttps = useHttps;
  }

  public String getHostname() {
    return hostname;
  }

  public void setHostname( String hostname ) {
    this.hostname = hostname;
  }

  public Integer getPort() {
    return port;
  }

  public void setPort( Integer port ) {
    this.port = port;
  }

  public String getRealm() {
    return realm;
  }

  public void setRealm( String realm ) {
    this.realm = realm;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret( String clientSecret ) {
    this.clientSecret = clientSecret;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId( String clientId ) {
    this.clientId = clientId;
  }

  public String getGrantType() {
    return grantType;
  }

  public void setGrantType(String grantType) {
    this.grantType = grantType;
  }

  public Logger getLogger() {
    return logger;
  }
}
