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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unitedid.yhsm.YubiHSM;
import org.unitedid.yhsm.internal.YubiHSMCommandFailedException;
import org.unitedid.yhsm.internal.YubiHSMErrorException;
import org.unitedid.yhsm.internal.YubiHSMInputException;

public class ValidateAead {
    private final Logger log = LoggerFactory.getLogger(ValidateAead.class);

    private YubiHSM yubiHSM;

    ValidateAead() throws YubiHSMErrorException {
        yubiHSM = new YubiHSM(Config.getHsmDevice(), 1);
    }

    public boolean validate(String nonce, int keyHandle, String aead, byte[] plaintext) {
        try {
            return yubiHSM.validateAEAD(nonce, keyHandle, aead, new String(plaintext));
        } catch (YubiHSMInputException e) {
            return false;
        } catch (YubiHSMCommandFailedException e) {
            throw new RuntimeException(e);
        } catch (YubiHSMErrorException e) {
            throw new RuntimeException(e);
        }
    }
}
