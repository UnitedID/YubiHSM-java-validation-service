/*
 * Copyright (c) 2011 United ID. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author Stefan Wold <stefan.wold@unitedid.org>
 */

package org.unitedid.yhsm.ws;

import org.unitedid.yhsm.internal.YubiHSMErrorException;

import javax.jws.WebParam;
import javax.jws.WebService;

@WebService(endpointInterface = "org.unitedid.yhsm.ws.ValidateAeadService")
public class ValidateAeadServiceImpl implements ValidateAeadService {

    @Override
    public boolean validateAEAD(@WebParam(name = "nonce") String nonce,
                                @WebParam(name = "keyHandle") int keyHandle,
                                @WebParam(name = "aead") String aead,
                                @WebParam(name = "plaintext") byte[] plaintext) throws YubiHSMErrorException {
        ValidateAead validateAead = new ValidateAead();
        return validateAead.validate(nonce, keyHandle, aead, plaintext);
    }
}