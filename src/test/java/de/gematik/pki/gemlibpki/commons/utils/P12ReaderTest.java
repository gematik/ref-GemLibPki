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

package de.gematik.pki.gemlibpki.commons.utils;

import static de.gematik.pki.gemlibpki.commons.TestConstants.P12_PASSWORD;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.gematik.pki.gemlibpki.commons.TestConstantsNonQes;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class P12ReaderTest {

  @Test
  void readP12nonQes_whenRsaP12IsValid_thenDoesNotThrow() {
    assertDoesNotThrow(() -> TestUtils.readP12nonQes("ocsp/rsaOcspSigner.p12"));
  }

  @Test
  void getContentFromP12_whenEccP12IsValid_thenDoesNotThrow() {
    final Path p12Path = Path.of(TestConstantsNonQes.CERT_DIR_NON_QES, "ocsp/eccOcspSigner.p12");
    assertDoesNotThrow(() -> P12Reader.getContentFromP12(p12Path, P12_PASSWORD));
  }

  @Test
  void getContentFromP12_whenP12ContainsNoEntries_thenReturnsNull() {
    assertNull(
        P12Reader.getContentFromP12(
            Path.of(TestConstantsNonQes.CERT_DIR_NON_QES, "empty.p12"), P12_PASSWORD));
  }

  @Test
  void getContentFromP12_whenFileIsNotAP12_thenThrowsGemPkiRuntimeException() {
    final Path invalidP12 = Path.of("src/test/resources/log4j2.xml");
    assertThatThrownBy(() -> P12Reader.getContentFromP12(invalidP12, P12_PASSWORD))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Konnte .p12 Datei nicht verarbeiten.");
  }

  @Test
  void getContentFromP12_whenPathDoesNotExist_thenThrowsGemPkiRuntimeException() {
    final Path invalidPath = Path.of("invalid");
    assertThatThrownBy(() -> P12Reader.getContentFromP12(invalidPath, P12_PASSWORD))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Cannot read path: " + invalidPath);
  }

  @Test
  void getContentFromP12_whenRequiredArgumentIsNull_thenThrowsNullPointerException() {

    assertNonNullParameter(
        () -> P12Reader.getContentFromP12((byte[]) null, P12_PASSWORD), "p12FileContent");

    assertNonNullParameter(() -> P12Reader.getContentFromP12((Path) null, P12_PASSWORD), "path");

    final Path path = Path.of("foo");
    assertNonNullParameter(() -> P12Reader.getContentFromP12(path, null), "p12Password");
    assertNonNullParameter(() -> P12Reader.getContentFromP12(new byte[] {}, null), "p12Password");
  }
}
