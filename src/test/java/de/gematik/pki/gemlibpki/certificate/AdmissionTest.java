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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB_KZBV;
import static de.gematik.pki.gemlibpki.certificate.Role.OID_PRAXIS_PSYCHOTHERAPEUT;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

final class AdmissionTest {

  @Test
  void admissionNull() {
    assertNonNullParameter(() -> new Admission(null), "x509EeCert");
  }

  @Test
  void getAdmissionAuthority() throws IOException {
    assertThat(new Admission(VALID_X509_EE_CERT_SMCB_KZBV).getAdmissionAuthority())
        .isEqualTo("C=DE,O=KZV Berlin");
  }

  @Test
  void getAdmissionAuthorityEmpty() throws IOException {
    final Admission admission = new Admission(VALID_X509_EE_CERT_SMCB);

    try (final MockedStatic<AdmissionSyntax> admissionSyntaxMockedStatic =
        Mockito.mockStatic(AdmissionSyntax.class)) {

      admissionSyntaxMockedStatic
          .when(() -> AdmissionSyntax.getInstance(Mockito.any()))
          .thenReturn(null);

      final String admissionAuthority = admission.getAdmissionAuthority();
      assertThat(admissionAuthority).isEmpty();
    }
  }

  @Test
  void getProfessionItems() throws IOException {
    assertThat(new Admission(VALID_X509_EE_CERT_SMCB).getProfessionItems())
        .contains(OID_PRAXIS_PSYCHOTHERAPEUT.getProfessionItem());
  }

  @Test
  void getProfessionOids() throws IOException {
    assertThat(new Admission(VALID_X509_EE_CERT_SMCB).getProfessionOids())
        .contains(OID_PRAXIS_PSYCHOTHERAPEUT.getProfessionOid());
  }

  @Test
  void getRegistrationNumber() throws IOException {
    assertThat(new Admission(VALID_X509_EE_CERT_SMCB).getRegistrationNumber())
        .isEqualTo("1-2-Psycho-BabetteBeyer01");
  }

  @Test
  void verifyMissingProfOid() throws IOException {
    final X509Certificate missingProfOid =
        TestUtils.readCert("GEM.SMCB-CA57/valid/BabetteBeyer-missing-prof-oid.pem");
    assertDoesNotThrow(() -> new Admission(missingProfOid));
    assertThat(new Admission(missingProfOid).getProfessionOids()).isEmpty();
  }

  @Test
  void verifyMissingAdmission() throws IOException {
    final X509Certificate missingAdmission =
        TestUtils.readCert("GEM.SMCB-CA57/valid/BabetteBeyer-missing-admission.pem");
    assertDoesNotThrow(() -> new Admission(missingAdmission));
    assertThat(new Admission(missingAdmission).getProfessionOids()).isEmpty();
  }

  @Test
  void verifyGetProfessionItems_empty1() throws IOException {
    final Admission admission = new Admission(VALID_X509_EE_CERT_SMCB);

    try (final MockedStatic<AdmissionSyntax> admissionSyntaxMockedStatic =
        Mockito.mockStatic(AdmissionSyntax.class)) {

      admissionSyntaxMockedStatic
          .when(() -> AdmissionSyntax.getInstance(Mockito.any()))
          .thenReturn(null);

      final Set<String> professionItems = admission.getProfessionItems();
      assertThat(professionItems).isEmpty();
    }
  }

  @Test
  void verifyGetProfessionItems_empty2() throws IOException {
    final Admission admission = new Admission(VALID_X509_EE_CERT_SMCB);

    final AdmissionSyntax admissionInstanceMock = Mockito.mock(AdmissionSyntax.class);
    Mockito.when(admissionInstanceMock.getContentsOfAdmissions()).thenReturn(new Admissions[] {});

    try (final MockedStatic<AdmissionSyntax> admissionSyntaxMockedStatic =
        Mockito.mockStatic(AdmissionSyntax.class)) {

      admissionSyntaxMockedStatic
          .when(() -> AdmissionSyntax.getInstance(Mockito.any()))
          .thenReturn(admissionInstanceMock);

      final Set<String> professionItems = admission.getProfessionItems();
      assertThat(professionItems).isEmpty();
    }
  }

  @Test
  void verifyGetProfessionItems_empty3() throws IOException {
    final Admission admission = new Admission(VALID_X509_EE_CERT_SMCB);

    final Admissions bcAdmissionsMock = Mockito.mock(Admissions.class);
    Mockito.when(bcAdmissionsMock.getProfessionInfos()).thenReturn(new ProfessionInfo[] {});

    final AdmissionSyntax admissionInstanceMock = Mockito.mock(AdmissionSyntax.class);
    Mockito.when(admissionInstanceMock.getContentsOfAdmissions())
        .thenReturn(new Admissions[] {bcAdmissionsMock});

    try (final MockedStatic<AdmissionSyntax> admissionSyntaxMockedStatic =
        Mockito.mockStatic(AdmissionSyntax.class)) {

      admissionSyntaxMockedStatic
          .when(() -> AdmissionSyntax.getInstance(Mockito.any()))
          .thenReturn(admissionInstanceMock);

      final Set<String> professionItems = admission.getProfessionItems();
      assertThat(professionItems).isEmpty();
    }
  }
}
