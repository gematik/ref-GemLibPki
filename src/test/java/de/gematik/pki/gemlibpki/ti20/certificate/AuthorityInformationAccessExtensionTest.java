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

package de.gematik.pki.gemlibpki.ti20.certificate;

import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

class AuthorityInformationAccessExtensionTest {

  private static final X509Certificate NONQES_CERT_WITH_OCSP =
      TestUtils.readCertNonQes(
          "ti20/GEM.SMCB-CA57/Arztpraxis-Olga-Olbricht-Internet-TEST-ONLY.pem");
  private static final X509Certificate QES_CERT = VALID_X509_EE_CERT_QES;

  @Test
  void getSsp_whenCertificateIsNonQesWithOcsp_thenReturnsHttpUrl() throws IOException {
    final String ssp = new AuthorityInformationAccessExtension(NONQES_CERT_WITH_OCSP).getSsp();
    assertThat(ssp).isNotNull().startsWith("http://");
  }

  @Test
  void getSsp_whenCertificateIsQesWithOcsp_thenReturnsHttpUrl() throws IOException {
    final String ssp = new AuthorityInformationAccessExtension(QES_CERT).getSsp();
    assertThat(ssp).isNotNull().startsWith("http://");
  }

  @Test
  void constructor_whenCertificateIsNull_thenThrowsNullPointerException() {
    assertNonNullParameter(() -> new AuthorityInformationAccessExtension(null), "x509EeCert");
  }

  @Test
  void getSsp_whenCertificateContainsSpecificOcspUrl_thenReturnsExpectedValue() throws IOException {
    assertThat(new AuthorityInformationAccessExtension(NONQES_CERT_WITH_OCSP).getSsp())
        .isEqualTo("http://127.0.0.1:8083/ocsp/");
  }
}
