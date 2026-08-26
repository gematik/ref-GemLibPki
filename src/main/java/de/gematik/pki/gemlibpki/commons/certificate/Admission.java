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

package de.gematik.pki.gemlibpki.commons.certificate;

import static org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_admission;

import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Class to abstract the admission of a certificate. This class works with a parameterized variable
 * for the certificate in its constructor.
 */
@Slf4j
public class Admission {

  private final ASN1Encodable asn1Admission;
  private static final String NO_ADMISSION_MESSAGE = "Keine Admission vorhanden.";

  /**
   * Constructor
   *
   * @param x509EeCert end entity certificate to get admission information from
   * @throws IOException if certificate cannot be read
   */
  public Admission(@NonNull final X509Certificate x509EeCert) throws IOException {
    asn1Admission =
        new X509CertificateHolder(GemLibPkiUtils.certToBytes(x509EeCert))
            .getExtensions()
            .getExtensionParsedValue(id_isismtt_at_admission);
    if (asn1Admission == null) {
      log.info(NO_ADMISSION_MESSAGE);
    }
  }

  /**
   * Reading admission authority
   *
   * @return String of the admission authority or an empty string if not present
   */
  public String getAdmissionAuthority() {
    final AdmissionSyntax admissionInstance = AdmissionSyntax.getInstance(asn1Admission);

    if (admissionInstance == null) {
      return "";
    }

    return admissionInstance.getAdmissionAuthority().getName().toString();
  }

  /**
   * Reading profession items
   *
   * @return Non-duplicate list of profession items of all profession infos in the certificate
   */
  public Set<String> getProfessionItems() {
    final Stream<ProfessionInfo> professionInfoStream = getProfessionInfoStream();
    if (professionInfoStream == null) {
      return Collections.emptySet();
    }

    final Set<String> professionItems =
        professionInfoStream
            .flatMap(professionInfo -> Arrays.stream(professionInfo.getProfessionItems()))
            .map(DirectoryString::getString)
            .collect(Collectors.toSet());

    if (professionItems.isEmpty()) {
      log.info("Keine ProfessionItems vorhanden.");
      return Collections.emptySet();
    }

    return professionItems;
  }

  /**
   * Reading profession oid's
   *
   * @return Non-duplicate list of profession oid's of all profession infos in the certificate
   */
  public Set<String> getProfessionOids() {
    final Stream<ProfessionInfo> professionInfoStream = getProfessionInfoStream();
    if (professionInfoStream == null) {
      return Collections.emptySet();
    }

    final Set<String> professionOids =
        professionInfoStream
            .flatMap(professionInfo -> Arrays.stream(professionInfo.getProfessionOIDs()))
            .map(ASN1ObjectIdentifier::getId)
            .collect(Collectors.toSet());

    if (professionOids.isEmpty()) {
      log.info("Keine ProfessionOid vorhanden.");
      return Collections.emptySet();
    }

    return professionOids;
  }

  /**
   * Reading registration number
   *
   * @return String of the registration number of the first profession info with a registration
   *     number in the certificate
   */
  public String getRegistrationNumber() {
    final Stream<ProfessionInfo> professionInfoStream = getProfessionInfoStream();
    if (professionInfoStream == null) {
      return "";
    }

    final String regNr =
        professionInfoStream
            .map(ProfessionInfo::getRegistrationNumber)
            .filter(registrationNumber -> !registrationNumber.isEmpty())
            .findFirst()
            .orElse("");

    if (regNr.isEmpty()) {
      log.info("Keine RegistrationNumber vorhanden.");
      return "";
    }

    return regNr;
  }

  boolean hasAdmissionSyntax() {
    return AdmissionSyntax.getInstance(asn1Admission) != null;
  }

  boolean hasProfessionInfos() {
    final AdmissionSyntax admissionInstance = AdmissionSyntax.getInstance(asn1Admission);
    if (admissionInstance == null) {
      return false;
    }

    return Arrays.stream(admissionInstance.getContentsOfAdmissions())
        .anyMatch(admission -> admission.getProfessionInfos().length > 0);
  }

  private Stream<ProfessionInfo> getProfessionInfoStream() {
    final AdmissionSyntax admissionInstance = AdmissionSyntax.getInstance(asn1Admission);
    if (admissionInstance == null) {
      log.info(NO_ADMISSION_MESSAGE);
      return null;
    }

    final Admissions[] admissions = admissionInstance.getContentsOfAdmissions();
    if (admissions.length == 0) {
      log.info("Keine Elemente in der Admission vorhanden.");
      return null;
    }

    final Stream<ProfessionInfo> professionInfoStream =
        Arrays.stream(admissions)
            .flatMap(admission -> Arrays.stream(admission.getProfessionInfos()));
    final ProfessionInfo[] professionInfos = professionInfoStream.toArray(ProfessionInfo[]::new);
    if (professionInfos.length == 0) {
      log.info("Keine ProfessionInfo vorhanden.");
      return null;
    }

    return Arrays.stream(professionInfos);
  }
}
