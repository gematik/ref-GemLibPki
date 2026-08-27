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
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.commons.TestConstantsNonQes;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

class CertReaderTest {

  @SneakyThrows
  @Test
  void readX509_whenDerCertificateBytesAreValid_thenReturnsCertificateWithExpectedSubject() {
    final byte[] file =
        GemLibPkiUtils.readContent(
            Path.of(
                TestConstantsNonQes.CERT_DIR_NON_QES,
                "GEM.SMCB-CA57/valid/PraxisBabetteBeyer.der"));
    assertThat(CertReader.readX509(file).getSubjectX500Principal().getName())
        .contains("Psychotherapeutische Praxis Babette Beyer");
  }

  @Test
  void readX509_whenPathIsNull_thenThrowsNullPointerException() {
    assertNonNullParameter(() -> CertReader.readX509((Path) null), "path");
  }

  @SneakyThrows
  @Test
  void readX509_whenDerCertificatePathIsValid_thenReturnsCertificateWithExpectedSubject() {
    assertThat(
            CertReader.readX509(
                    Path.of(
                        TestConstantsNonQes.CERT_DIR_NON_QES,
                        "GEM.SMCB-CA57/valid/PraxisBabetteBeyer.der"))
                .getSubjectX500Principal()
                .getName())
        .contains("Psychotherapeutische Praxis Babette Beyer");
  }

  @SneakyThrows
  @Test
  void readX509_whenPemCertificateBytesAreValid_thenReturnsCertificateWithExpectedSubject() {
    final Path certPath =
        Path.of(TestConstantsNonQes.CERT_DIR_NON_QES, "GEM.SMCB-CA57/valid/PraxisBabetteBeyer.pem");
    final byte[] certBytes = GemLibPkiUtils.readContent(certPath);
    final X509Certificate cert = CertReader.readX509(certBytes);
    assertThat(cert.getSubjectX500Principal().getName())
        .contains("Psychotherapeutische Praxis Babette Beyer");
  }

  @SneakyThrows
  @Test
  void readX509_whenCertificateBytesAreInvalid_thenThrowsGemPkiRuntimeException() {
    final byte[] file = GemLibPkiUtils.readContent(Path.of("src/test/resources/log4j2.xml"));
    assertThatThrownBy(() -> CertReader.readX509(file))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Konnte Zertifikat nicht lesen.");
  }

  @SneakyThrows
  @Test
  void getX509FromP12_whenPathDoesNotExist_thenThrowsGemPkiRuntimeException() {
    final Path path = Path.of("invalid/path.p12");
    assertThatThrownBy(() -> CertReader.getX509FromP12(path, ""))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Cannot read path: " + path);
  }

  @SneakyThrows
  @Test
  void getX509FromP12_whenP12ContainsCertificate_thenReturnsCertificateWithExpectedSubject() {
    final Path p12Path = Path.of(TestConstantsNonQes.CERT_DIR_NON_QES, "ocsp/eccOcspSigner.p12");
    assertThat(CertReader.getX509FromP12(p12Path, P12_PASSWORD).getSubjectX500Principal().getName())
        .contains("pkits OCSP Signer 57 ecc TEST-ONLY");
  }

  @Test
  void getX509FromP12_whenPathOrPasswordIsNull_thenThrowsNullPointerException() {
    final Path path = Path.of("unimportant");

    assertNonNullParameter(() -> CertReader.getX509FromP12(null, "foo"), "path");

    assertNonNullParameter(() -> CertReader.getX509FromP12(path, null), "password");
  }
}
