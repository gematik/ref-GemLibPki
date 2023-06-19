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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

final class AdmissionTest {

  private final X509Certificate certValid =
      TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther.pem");

  private AdmissionTest() {}

  @Test
  void admissionNull() {
    assertNonNullParameter(() -> new Admission(null), "x509EeCert");
  }

  @Test
  void getAdmissionAuthority() throws IOException {
    assertThat(new Admission(certValid).getAdmissionAuthority()).isEqualTo("C=DE,O=KZV Berlin");
  }

  @Test
  void getProfessionItems() throws IOException {
    assertThat(new Admission(certValid).getProfessionItems())
        .contains(Role.OID_ZAHNARZTPRAXIS.getProfessionItem());
  }

  @Test
  void getProfessionOids() throws IOException {
    assertThat(new Admission(certValid).getProfessionOids())
        .contains(Role.OID_ZAHNARZTPRAXIS.getProfessionOid());
  }

  @Test
  void getRegistrationNumber() throws IOException {
    assertThat(new Admission(certValid).getRegistrationNumber()).isEqualTo("2-2.30.1.16.TestOnly");
  }

  @Test
  void verifyMissingProfOid() throws IOException {
    final X509Certificate missingProfOid =
        TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther_missing-prof-oid.pem");
    assertDoesNotThrow(() -> new Admission(missingProfOid));
    assertThat(new Admission(missingProfOid).getProfessionOids()).isEmpty();
  }
}
