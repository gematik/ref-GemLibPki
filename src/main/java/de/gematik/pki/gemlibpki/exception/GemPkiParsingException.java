/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.exception;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import java.io.Serial;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.NonNull;

/** Utility class for {@link GemPkiException}. */
public class GemPkiParsingException extends GemPkiException {

  @Serial private static final long serialVersionUID = -7856481365407564745L;

  /**
   * Constructor to build a message.
   *
   * @param productType a string determines the caller of function
   * @param errorMap the error map
   */
  public GemPkiParsingException(
      @NonNull final String productType, final Map<CertificateProfile, GemPkiException> errorMap) {
    super(
        // first ErrorCode
        extractFirstError(errorMap)
            .map(GemPkiException::getError)
            .orElseThrow(
                () -> new GemPkiRuntimeException("Please understand the api of this library.")),
        // all ErrorMessages
        errorMap.entrySet().stream()
            .map(entry -> mapToErrorMessage(entry, productType))
            .collect(Collectors.joining()),
        // rootCause
        extractFirstError(errorMap).orElseThrow());
  }

  /**
   * Map given parameters to a string.
   *
   * @param entry with {@link CertificateProfile} and {@link GemPkiException}
   * @param productType a string determines the caller of function
   * @return formatted String
   */
  private static String mapToErrorMessage(
      final Entry<CertificateProfile, GemPkiException> entry, final String productType) {
    return "%s (für Prüfung gegen das Zertifikatsprofil: %s)"
        .formatted(entry.getValue().getError().getErrorMessage(productType), entry.getKey());
  }

  /**
   * Get first {@link GemPkiException} from Map of exceptions.
   *
   * @param errorMap the error map
   * @return {@link GemPkiException}
   */
  private static Optional<GemPkiException> extractFirstError(
      final Map<CertificateProfile, GemPkiException> errorMap) {
    return errorMap.values().stream().findFirst();
  }
}
