/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.exception;

import de.gematik.pki.error.ErrorCode;
import lombok.Getter;

@Getter
public class GemPkiException extends Exception {

    private static final long serialVersionUID = 7405265126912779712L;
    private final ErrorCode error;

    public GemPkiException(final String productType, final ErrorCode error) {
        super(error.getErrorMessage(productType));
        this.error = error;
    }
}
