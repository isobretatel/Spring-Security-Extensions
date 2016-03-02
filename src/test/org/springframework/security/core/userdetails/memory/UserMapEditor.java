/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package org.springframework.security.core.userdetails.memory;

import java.beans.PropertyEditorSupport;
import java.util.Properties;

import org.springframework.beans.propertyeditors.PropertiesEditor;
import org.springframework.security.core.userdetails.*;

/**
 * Property editor to assist with the setup of a {@link UserMap}.
 * <p>
 * The format of entries should be:
 * </p>
 * <p>
 * <code> username=password,grantedAuthority[,grantedAuthority][,enabled|disabled] </code>
 * </p>
 * <p>
 * The <code>password</code> must always be the first entry after the equals. The
 * <code>enabled</code> or <code>disabled</code> keyword can appear anywhere (apart from the first
 * entry reserved for the password). If neither <code>enabled</code> or <code>disabled</code>
 * appear, the default is <code>enabled</code>. At least one granted authority must be listed.
 * </p>
 * <p>
 * The <code>username</code> represents the key and duplicates are handled the same was as
 * duplicates would be in Java <code>Properties</code> files.
 * </p>
 * <p>
 * If the above requirements are not met, the invalid entry will be silently ignored.
 * </p>
 * <p>
 * This editor always assumes each entry has a non-expired account and non-expired credentials.
 * However, it does honour the user enabled/disabled flag as described above.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserMapEditor extends PropertyEditorSupport {
    // ~ Methods
    // ========================================================================================================
    
    public static UserMap addUsersFromProperties(final UserMap userMap, final Properties props) {
        // Now we have properties, process each one individually
        final UserAttributeEditor configAttribEd = new UserAttributeEditor();
        
        for (final Object name : props.keySet()) {
            final String username = (String) name;
            final String value = props.getProperty(username);
            
            // Convert value to a password, enabled setting, and list of granted authorities
            configAttribEd.setAsText(value);
            
            final UserAttribute attr = (UserAttribute) configAttribEd.getValue();
            
            // Make a user object, assuming the properties were properly provided
            if (attr != null) {
                final UserDetails user =
                        new User(username, attr.getPassword(), attr.isEnabled(), true, true, true,
                            attr.getAuthorities());
                userMap.addUser(user);
            }
        }
        
        return userMap;
    }
    
    @Override
    public void setAsText(final String s) throws IllegalArgumentException {
        final UserMap userMap = new UserMap();
        
        if ((s == null) || "".equals(s)) {
            // Leave value in property editor null
        } else {
            // Use properties editor to tokenize the string
            final PropertiesEditor propertiesEditor = new PropertiesEditor();
            propertiesEditor.setAsText(s);
            
            final Properties props = (Properties) propertiesEditor.getValue();
            addUsersFromProperties(userMap, props);
        }
        
        setValue(userMap);
    }
}
