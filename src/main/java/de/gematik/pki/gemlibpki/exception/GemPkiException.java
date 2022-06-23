/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.gemlibpki.exception;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import java.io.Serial;
import lombok.Getter;

/**
 * {@link GemPkiException} class. Mandatory for all constructors: an {@link ErrorCode} has to be
 * parameterized.
 */
@Getter
public class GemPkiException extends Exception {

  @Serial private static final long serialVersionUID = 6802689240697358373L;
  private final ErrorCode error;

  public GemPkiException(final String productType, final ErrorCode error) {
    super(error.getErrorMessage(productType));
    this.error = error;
  }

  public GemPkiException(final String productType, final ErrorCode error, final Exception e) {
    super(error.getErrorMessage(productType), e);
    this.error = error;
  }

  public GemPkiException(final ErrorCode error, final String message, final Exception e) {
    super(message, e);
    this.error = error;
  }
}
