package org.pentaho.platform.plugin.services.security.userrole.foundry;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;

import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.AuthenticationProvider;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class FoundryAuthenticationProvider implements AuthenticationProvider {

  private Logger logger = LoggerFactory.getLogger( getClass() );

  private static final String FOUNDRY_AUTHENTICATION_ENDPOINT = "/api/sentinel/security/authenticate";

  // required form params
  private static final String FOUNDRY_PARAM_GRANT_TYPE = "grant_type";
  private static final String FOUNDRY_PARAM_USERNAME = "username";
  private static final String FOUNDRY_PARAM_PASSWORD = "password";
  private static final String FOUNDRY_PARAM_REALM = "realm";

  private Map<String, UserDetails> userMap;

  private boolean useHttps = true; // default
  private String hostname;
  private String port;
  private String realm;
  private String grantType;
  private String clientSecret;
  private String clientId;


  public FoundryAuthenticationProvider( Map<String, UserDetails> userMap ) {
    setUserMap( userMap );
  }

  @Override
  public Authentication authenticate( Authentication authentication ) throws AuthenticationException {

    String username = authentication.getPrincipal().toString();
    String password = authentication.getCredentials().toString();

    try {

      HttpPost httpPost = new HttpPost( buildEndpoint().toString() );
      httpPost.addHeader( new BasicHeader( HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON ) );
      httpPost.addHeader( new BasicHeader( HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED ) );

      httpPost.setEntity( new UrlEncodedFormEntity( buildPostParameters( username, password ), StandardCharsets.UTF_8 ));

      getLogger().info( "Sending auth request to " +  buildEndpoint().toString() + " for username " + authentication.getPrincipal() );
      HttpResponse response = HttpClients.createDefault().execute( httpPost );
      int statusCode = response.getStatusLine().getStatusCode();
      String responseBody = responseBodyToString( response );
      getLogger().info( "Received response of " + statusCode + ": with body " + responseBody );

      if( statusCode == HttpStatus.SC_OK ) {

        // TODO properly implement this GrantedAuthority part
        List<GrantedAuthority> auths = new ArrayList<GrantedAuthority>();
        auths.add( new SimpleGrantedAuthority( "Authenticated" ) );


        UserDetails user = new User(
                username,
                "ignored" /* password */,
                true /* isEnabled */,
                true /* isAccountNonExpired */,
                true /* isCredentialsNonExpired */,
                true /* isAccountNonExpired */,
                auths );

        getUserMap().put( username, user );
        return new UsernamePasswordAuthenticationToken( user.getUsername(), user.getPassword(), user.getAuthorities() );
      }

    } catch ( URISyntaxException | IOException e ) {
      getLogger().error( e.getLocalizedMessage(), e );
      throw new AuthenticationServiceException( e.getLocalizedMessage(), e );
    }

    throw new AuthenticationServiceException( "Failed to authenticate user " + username );
  }

  @Override
  public boolean supports( Class<?> aClass ) {
    return aClass != null && UsernamePasswordAuthenticationToken.class.getName().equals( aClass.getName() );
  }

  protected URI buildEndpoint() throws URISyntaxException {

    return new URIBuilder()
            .setScheme( isUseHttps() ? "https" : "http" )
            .setHost( getHostname() )
            .setPort( Integer.parseInt( getPort() ) )
            .setPath( FOUNDRY_AUTHENTICATION_ENDPOINT )
            .build();
  }

  protected ArrayList<NameValuePair> buildPostParameters( String username, String password ) {
    ArrayList<NameValuePair> postParameters = new ArrayList<>();

    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_USERNAME, username ) );
    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_PASSWORD, password ) );
    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_REALM, getRealm() ) );
    postParameters.add( new BasicNameValuePair( FOUNDRY_PARAM_GRANT_TYPE, getGrantType() ) );

    return postParameters;
  }

  protected String responseBodyToString( HttpResponse response ) throws IOException {

    InputStream is = null;
    StringBuilder sb = new StringBuilder();

    try {
      is = response.getEntity().getContent();
      for ( String line : IOUtils.readLines( is, StandardCharsets.UTF_8.displayName() ) ){
        sb.append( line + "\n" );
      }
    } finally {
      IOUtils.closeQuietly( is );
    }

    return sb.toString();
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

  public String getPort() {
    return port;
  }

  public void setPort( String port ) {
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

  public Map<String, UserDetails> getUserMap() {
    return userMap;
  }

  public void setUserMap(Map<String, UserDetails> userMap) {
    this.userMap = userMap;
  }
}
