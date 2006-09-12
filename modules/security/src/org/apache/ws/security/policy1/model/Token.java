/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ws.security.policy1.model;

import org.apache.ws.security.policy1.Constants;
import org.apache.ws.security.policy1.WSSPolicyException;

public class Token extends PolicyEngineData {

    /**
     * Inclusiong property of a TokenAssertion
     */
    private String inclusion = Constants.INCLUDE_ALWAYS;
    
    /**
     * Whether to derive keys or not
     */
    private boolean derivedKeys;
    
    /**
     * @return Returns the inclusion.
     */
    public String getInclusion() {
        return inclusion;
    }

    /**
     * @param inclusion The inclusion to set.
     */
    public void setInclusion(String inclusion) throws WSSPolicyException {
        if(Constants.INCLUDE_ALWAYS.equals(inclusion) || 
           Constants.INCLUDE_ALWAYS_TO_RECIPIENT.equals(inclusion) ||
           Constants.INCLUDE_NEVER.equals(inclusion) ||
           Constants.INCLUDE_ONCE.equals(inclusion)) {
            this.inclusion = inclusion;
        } else {
            throw new WSSPolicyException("Incorrect inclusion value: " + inclusion);
        }
    }
    
    /**
     * @return Returns the derivedKeys.
     */
    public boolean isDerivedKeys() {
        return derivedKeys;
    }

    /**
     * @param derivedKeys The derivedKeys to set.
     */
    public void setDerivedKeys(boolean derivedKeys) {
        this.derivedKeys = derivedKeys;
    }    
    
}