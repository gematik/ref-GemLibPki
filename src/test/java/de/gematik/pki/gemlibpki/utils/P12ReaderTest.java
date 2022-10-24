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

package de.gematik.pki.gemlibpki.utils;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.gematik.pki.gemlibpki.TestConstants;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class P12ReaderTest {

  @Test
  void verifyGetContentFromP12Valid() {
    assertDoesNotThrow(() -> TestUtils.readP12("ocsp/rsaOcspSigner.p12"));
  }

  @Test
  void verifyGetContentFromP12Null() {
    assertNull(
        P12Reader.getContentFromP12(
            Path.of(TestConstants.CERT_DIR, "empty.p12"), TestConstants.P12_PASSWORD));
  }

  @Test
  void verifyGetInvalidP12() {
    final Path invalidP12 = Path.of("src/test/resources/log4j2.xml");
    assertThatThrownBy(() -> P12Reader.getContentFromP12(invalidP12, TestConstants.P12_PASSWORD))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Konnte .p12 Datei nicht verarbeiten.");
  }

  @Test
  void verifyFileMissing() {
    final Path invalidPath = Path.of("invalid");
    assertThatThrownBy(() -> P12Reader.getContentFromP12(invalidPath, TestConstants.P12_PASSWORD))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Cannot read path: " + invalidPath);
  }

  @Test
  void verifyGetContentFromP12NonNull() {
    assertThatThrownBy(() -> P12Reader.getContentFromP12((byte[]) null, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("p12Password is marked non-null but is null");

    assertThatThrownBy(() -> P12Reader.getContentFromP12((Path) null, "foo"))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("path is marked non-null but is null");

    final Path path = Path.of("foo");
    assertThatThrownBy(() -> P12Reader.getContentFromP12(path, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("p12Password is marked non-null but is null");
  }
}
