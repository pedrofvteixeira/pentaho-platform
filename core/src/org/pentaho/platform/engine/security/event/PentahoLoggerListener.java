/*
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License, version 2 as published by the Free Software
 * Foundation.
 *
 * You should have received a copy of the GNU General Public License along with this
 * program; if not, you can obtain a copy at http://www.gnu.org/licenses/gpl-2.0.html
 * or from the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 *
 * Copyright 2006 - 2015 Pentaho Corporation.  All rights reserved.
 */
package org.pentaho.platform.engine.security.event;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.LoggerListener;
import org.springframework.security.core.Authentication;

/**
 * org.pentaho.platform.engine.security.event.PentahoLoggerListener
 * wraps org.springframework.security.authentication.event.LoggerListener
 * and safeguards onApplicationEvent() calls
 */
public class PentahoLoggerListener implements ApplicationListener {

  LoggerListener loggerListener;

  public PentahoLoggerListener( LoggerListener loggerListener ) {
    this.loggerListener = loggerListener;
  }

  @Override public void onApplicationEvent( ApplicationEvent event ) {

    if ( event != null && event.getClass().isAssignableFrom( AbstractAuthenticationEvent.class ) ) {
      loggerListener.onApplicationEvent( new WrappedAuthenticationEvent( (Authentication) event.getSource() ) );
    }
  }

  public boolean isLogInteractiveAuthenticationSuccessEvents() {
    return loggerListener.isLogInteractiveAuthenticationSuccessEvents();
  }

  public void setLogInteractiveAuthenticationSuccessEvents( boolean logInteractiveAuthenticationSuccessEvents ) {
    loggerListener.setLogInteractiveAuthenticationSuccessEvents( logInteractiveAuthenticationSuccessEvents );
  }

  private class WrappedAuthenticationEvent extends AbstractAuthenticationEvent {

    public WrappedAuthenticationEvent( Authentication authentication ) {
      super( authentication );
    }
  }
}
