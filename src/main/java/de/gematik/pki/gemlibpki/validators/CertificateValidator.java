/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import lombok.NonNull;

public interface CertificateValidator {

  default void validateCertificate(@NonNull final X509Certificate x509EeCert) throws GemPkiException {
    validateCertificate(x509EeCert, ZonedDateTime.now(ZoneOffset.UTC));
  }

  void validateCertificate(
      @NonNull X509Certificate x509EeCert, @NonNull ZonedDateTime referenceDate)
      throws GemPkiException;
}
