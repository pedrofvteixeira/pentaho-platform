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
 * Copyright (c) 2002-2017 Hitachi Vantara..  All rights reserved.
 */

package org.pentaho.mantle.client.events;

import com.google.gwt.event.shared.GwtEvent;
import com.google.gwt.user.client.ui.Widget;
import org.pentaho.mantle.client.solutionbrowser.filelist.FileItem;

import java.util.List;

public class SolutionBrowserUndefinedEvent extends GwtEvent<SolutionBrowserUndefinedEventHandler> implements
    ISolutionBrowserEvent {

  public static Type<SolutionBrowserUndefinedEventHandler> TYPE = new Type<SolutionBrowserUndefinedEventHandler>();

  public static final String TYPE_STR = "SolutionBrowserUndefinedEvent";

  private Widget widget;
  private List<FileItem> fileItems;

  public SolutionBrowserUndefinedEvent() {
  }

  public SolutionBrowserUndefinedEvent( Widget widget, List<FileItem> fileItems ) {
    this.widget = widget;
    this.fileItems = fileItems;
  }

  public Type<SolutionBrowserUndefinedEventHandler> getAssociatedType() {
    return TYPE;
  }

  protected void dispatch( SolutionBrowserUndefinedEventHandler handler ) {
    handler.onUndefinedEvent( this );
  }

  public Widget getWidget() {
    return widget;
  }

  public void setWidget( Widget widget ) {
    this.widget = widget;
  }

  public List<FileItem> getFileItems() {
    return fileItems;
  }

  public void setFileItems( List<FileItem> fileItems ) {
    this.fileItems = fileItems;
  }

}
