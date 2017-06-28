/*!
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License, version 2.1 as published by the Free Software
 * Foundation.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this
 * program; if not, you can obtain a copy at http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
 * or from the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * Copyright (c) 2017 Pentaho Corporation..  All rights reserved.
 */
package org.pentaho.platform.plugin.action;

import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.api.engine.IPentahoSystemListener;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.pentaho.platform.util.ActionUtil;
import org.pentaho.platform.util.logging.Logger;
import org.pentaho.platform.web.http.api.resources.ActionResource;

import javax.ws.rs.core.Response;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;


/**
 * Created by pteixeira on 23/06/2017.
 */
public class PentahoActionInvokerSystemListener implements IPentahoSystemListener {

  private final String FILE_EXTENSION = ".json";
  private static final String DEFAULT_FOLDER = "system/default-content";

  @Override
  public boolean startup( IPentahoSession session ) {

    String solutionPath = PentahoSystem.getApplicationContext().getSolutionPath( DEFAULT_FOLDER );

    try {

      // step 1: locate all files with 'FILE_EXTENSION' within 'solutionPath'
      File[] files = listFiles( new File( solutionPath ), FILE_EXTENSION );

      if ( files == null || files.length == 0 ) {
        return true; // nothing to do here
      }

      for ( File file : files ) {

        try {

          // step 2: convert java.io.File to org.json.JSONObject
          JSONObject json = fileToJSONObject( file );

          // step 3: call IActionInvoker.invokeAction() with async=false
          Response response = new ActionResource().invokeAction(
                            String.valueOf( false ),
                            get( json, ActionUtil.INVOKER_ACTIONID ),
                            get( json, ActionUtil.INVOKER_ACTIONCLASS ),
                            get( json, ActionUtil.INVOKER_ACTIONUSER ),
                            get( json, ActionUtil.INVOKER_ACTIONPARAMS ) );

        } catch ( Exception e ) {
          Logger.error( e, "" );
          continue; // carry on with iteration of files

        } finally {
          // at the end: always rename processed file, appending the timestamp
          file.renameTo( new File( file.getAbsolutePath() + "." + System.currentTimeMillis() ) );

        }
      }

    } catch ( IOException e ) {
      Logger.error( e, "" );
      return false;
    }

    return true;
  }

  @Override
  public void shutdown() {
  }

  protected File[] listFiles( final File folder, final String fileExtension ) throws IOException {

    if ( folder.exists() && folder.isDirectory() && folder.canRead() ) {

      return folder.listFiles( new FileFilter() {
        @Override
        public boolean accept( File f ) {
          return  f.isFile() && f.getName().toLowerCase().endsWith( fileExtension );
        }
      } );

    } else {
      Logger.error( null, folder.getAbsolutePath() + " is not a valid directory" );
    }

    return null;
  }

  protected JSONObject fileToJSONObject( final File file ) throws IOException, JSONException {

    final String SERIALIZED_PARAMS_ATTR_KEY = "\"" + "serializedParams" + "\"" + ":";

    String unescapedJsonContent = IOUtils.toString( new FileInputStream( file ) );
    int serializedParamsIdx = unescapedJsonContent.indexOf( SERIALIZED_PARAMS_ATTR_KEY );
    StringBuffer escapedJsonContent = new StringBuffer();

    // first section ( actionId, actionClass, actionUser ): already properly set
    escapedJsonContent.append( unescapedJsonContent.substring( 0, serializedParamsIdx ) );

    // actionParams/serializedParams section: needs escaping
    escapedJsonContent.append( org.json.simple.JSONObject.escape(
                unescapedJsonContent.substring( serializedParamsIdx, unescapedJsonContent.length() - 2 ) ) );

    // close the JSON object
    escapedJsonContent.append( "\"}" );

    return new JSONObject( escapedJsonContent.toString() );
  }

  protected String get( final JSONObject json, final String key ) throws JSONException {
    // also get rid of any unwanted characters that may have lurked in
    return json == null ? "" : json.getString( key ).replaceAll( "\n", "" ).replaceAll( "\r", "" );
  }
}
