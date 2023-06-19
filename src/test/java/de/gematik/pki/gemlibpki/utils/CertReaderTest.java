/*
 * Copyright (c) 2023 gematik GmbH
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

import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.TestConstants;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.nio.file.Path;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

class CertReaderTest {

  @SneakyThrows
  @Test
  void readExistingX509DerCert() {
    final byte[] file =
        GemLibPkiUtils.readContent(
            Path.of(TestConstants.CERT_DIR, "GEM.SMCB-CA10/valid/DrMedGunther.der"));
    assertThat(CertReader.readX509(file).getSubjectX500Principal().getName())
        .contains("Zahnarztpraxis Dr. med.Gunther");
  }

  @Test
  void readX509NonNull() {
    assertNonNullParameter(() -> CertReader.readX509((Path) null), "path");
  }

  @SneakyThrows
  @Test
  void readX509() {
    assertThat(
            CertReader.readX509(
                    Path.of(TestConstants.CERT_DIR, "GEM.SMCB-CA10/valid/DrMedGunther.der"))
                .getSubjectX500Principal()
                .getName())
        .contains("Zahnarztpraxis Dr. med.Gunther");
  }

  @SneakyThrows
  @Test
  void readExistingX509PemCert() {
    final byte[] file =
        GemLibPkiUtils.readContent(
            Path.of(TestConstants.CERT_DIR, "GEM.SMCB-CA10/valid/DrMedGunther.pem"));
    assertThat(CertReader.readX509(file).getSubjectX500Principal().getName())
        .contains("Zahnarztpraxis Dr. med.Gunther");
  }

  @SneakyThrows
  @Test
  void readInvalidCert() {
    final byte[] file = GemLibPkiUtils.readContent(Path.of("src/test/resources/log4j2.xml"));
    assertThatThrownBy(() -> CertReader.readX509(file))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Konnte Zertifikat nicht lesen.");
  }

  @SneakyThrows
  @Test
  void readInvalidP12Path() {
    final Path path = Path.of("invalid/path.p12");
    assertThatThrownBy(() -> CertReader.getX509FromP12(path, ""))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Cannot read path: " + path);
  }

  @SneakyThrows
  @Test
  void getX509CertificateFromP12() {
    assertThat(
            CertReader.getX509FromP12(
                    Path.of(TestConstants.CERT_DIR, "ocsp/eccOcspSigner.p12"),
                    TestConstants.P12_PASSWORD)
                .getSubjectX500Principal()
                .getName())
        .contains("OCSP Signer 09 ecc TEST-ONLY");
  }

  @Test
  void nullTest() {
    final Path path = Path.of("unimportant");

    assertNonNullParameter(() -> CertReader.getX509FromP12(null, "foo"), "path");

    assertNonNullParameter(() -> CertReader.getX509FromP12(path, null), "password");
  }
}
