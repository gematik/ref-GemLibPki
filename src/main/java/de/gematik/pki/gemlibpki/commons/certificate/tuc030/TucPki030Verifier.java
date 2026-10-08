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

package de.gematik.pki.gemlibpki.commons.certificate.tuc030;

import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_HP_QES_ECC;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils.setBouncyCastleProvider;

import de.gematik.pki.gemlibpki.commons.certificate.Admission;
import de.gematik.pki.gemlibpki.commons.certificate.AdmissionSupport;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiverFactory;
import de.gematik.pki.gemlibpki.commons.tsl.TslConstants;
import de.gematik.pki.gemlibpki.commons.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.commons.validators.KeyUsageValidator;
import de.gematik.pki.gemlibpki.commons.validators.QesCaQualificationValidator;
import de.gematik.pki.gemlibpki.commons.validators.SignatureValidator;
import de.gematik.pki.gemlibpki.commons.validators.TucPki030OcspValidator;
import de.gematik.pki.gemlibpki.commons.validators.ValidityValidator;
import de.gematik.pki.gemlibpki.ti10.ocsp.TucPki030OcspTransceiverFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Entry point to access verification of certificate(s) regarding a standard process called
 * TucPki030. This class works with parameterized variables (defined by builder pattern) and with
 * given variables provided by runtime (method parameters).
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public class TucPki030Verifier {

  static {
    setBouncyCastleProvider();
  }

  @NonNull protected final String productType;
  @NonNull protected final List<TspService> tspServiceListBNetzAVl;
  @Builder.Default @NonNull protected final List<TspService> tspServiceListTsl = List.of();
  @Builder.Default protected final boolean withOcspCheck = true;

  @Builder.Default
  protected final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @Builder.Default
  protected final int ocspTimeToleranceProducedAtFutureMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;

  @Builder.Default
  protected final int ocspTimeToleranceProducedAtPastMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

  @Builder.Default protected final boolean tolerateOcspFailure = false;

  @Builder.Default protected OcspTransceiverFactory ocspTransceiverFactory = null;

  @Builder.Default protected TucPki030OcspValidator tucPki030OcspValidator = null;
  @Builder.Default protected OcspTransceiver ocspTransceiver = null;

  public Admission performTucPki030Checks(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    return performTucPki030Checks(x509EeCert, referenceDate, null, null);
  }

  public Admission performTucPki030Checks(
      @NonNull final X509Certificate x509EeCert, final Extension nonce) throws GemPkiException {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    return performTucPki030Checks(x509EeCert, referenceDate, nonce, null);
  }

  public Admission performTucPki030Checks(
      @NonNull final X509Certificate x509EeCert, final OCSPResp ocspResponse)
      throws GemPkiException {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    return performTucPki030Checks(x509EeCert, referenceDate, null, ocspResponse);
  }

  public Admission performTucPki030Checks(
      @NonNull final X509Certificate x509EeCert, final Extension nonce, final OCSPResp ocspResponse)
      throws GemPkiException {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    return performTucPki030Checks(x509EeCert, referenceDate, nonce, ocspResponse);
  }

  public Admission performTucPki030Checks(
      @NonNull final X509Certificate x509EeCert, @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    return performTucPki030Checks(x509EeCert, referenceDate, null, null);
  }

  public Admission performTucPki030Checks(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final ZonedDateTime referenceDate,
      final OCSPResp ocspResponse)
      throws GemPkiException {
    return performTucPki030Checks(x509EeCert, referenceDate, null, ocspResponse);
  }

  public Admission performTucPki030Checks(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final ZonedDateTime referenceDate,
      final Extension nonce)
      throws GemPkiException {
    return performTucPki030Checks(x509EeCert, referenceDate, nonce, null);
  }

  public Admission performTucPki030Checks(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final ZonedDateTime referenceDate,
      final Extension nonce,
      final OCSPResp ocspResponse)
      throws GemPkiException {
    log.debug("TUC_PKI_030 Checks...");
    final ZonedDateTime chainReferenceDate = getChainReferenceDate(x509EeCert);

    // 1.
    QcStatementVerification.checkQcStatementPresent(productType, x509EeCert);

    // 2. TUC_PKI_002 "Gültigkeitsprüfung des Zertifikats"
    new ValidityValidator(productType).validateCertificate(x509EeCert, referenceDate);

    // 3. KeyUsage = nonRepudiation
    new KeyUsageValidator(productType).validateCertificate(x509EeCert, CERT_PROFILE_C_HP_QES_ECC);

    // 4. Suche QES-CA-Zertifikat in BNetzA-VL
    final TspServiceSubset qesCaTspServiceSubset = findQesCaCertificate(x509EeCert);

    // 5. Prüfung Qualifikation & Status (QES-CA in VL, Kettenmodell zum Ausstellungszeitpunkt)
    new QesCaQualificationValidator(productType, qesCaTspServiceSubset)
        .validate(chainReferenceDate);

    // 6. Mathematische Signaturprüfung (Kettenmodell zum Ausstellungszeitpunkt)
    new SignatureValidator(productType, qesCaTspServiceSubset.getX509IssuerCert())
        .validateCertificate(x509EeCert, chainReferenceDate);

    final Extension ocspNonce = resolveOcspNonce(nonce, ocspResponse);

    // 7. - 12. OCSP
    // 7. Bestimmung OCSP-URL (AIA + ggf. TSL Override)
    // 8. OCSP-Request durchführen (mit NONCE)
    // 9. OCSP-Signer-Zertifikat aus BNetzA-VL extrahieren
    // 10. OCSP-Signer-Zertifikat aus OCSP-Response extrahieren, Vergleich CA des
    // OCSP-Signer-Zertifikat mit QES-CA-Zertifikat, Validierung des OCSP-Signers gegen
    // QES-CA-Zertifikat, Validierung Signatur OCSP-Response mit OCSP-Signer-Zertifikat
    // 11. Auswertung OCSP-Response (Status, CertID, Zeitwerte, NONCE)
    // 12. Prüfung certStatus == "good" (zum Referenzzeitpunkt)
    doOcspIfConfigured(
        x509EeCert,
        qesCaTspServiceSubset.getX509IssuerCert(),
        referenceDate,
        ocspNonce,
        ocspResponse);

    // 13. TUC_PKI_009 "Rollenermittlung"
    // 14. OK (Rollen-OID(s) zurückgeben)
    return AdmissionSupport.getAdmission(x509EeCert);
  }

  private void initializeValidator() {

    if (tucPki030OcspValidator != null) {
      return;
    }

    tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(productType)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVl)
            .withOcspCheck(withOcspCheck)
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .ocspTransceiver(ocspTransceiver)
            .tolerateOcspFailure(tolerateOcspFailure)
            .ocspTimeToleranceProducedAtFutureMilliseconds(
                ocspTimeToleranceProducedAtFutureMilliseconds)
            .ocspTimeToleranceProducedAtPastMilliseconds(
                ocspTimeToleranceProducedAtPastMilliseconds)
            .build();
  }

  private void initializeTransceiver(
      @NonNull final X509Certificate x509EeCert, @NonNull final X509Certificate x509IssuerCert)
      throws GemPkiException {

    if (ocspTransceiver != null) {
      return;
    }

    if (ocspTransceiverFactory == null) {
      ocspTransceiverFactory =
          new TucPki030OcspTransceiverFactory(
              productType,
              x509IssuerCert,
              tspServiceListTsl,
              ocspTimeoutSeconds,
              tolerateOcspFailure);
    }

    ocspTransceiver = ocspTransceiverFactory.create(x509EeCert);
  }

  protected void doOcspIfConfigured(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      @NonNull final ZonedDateTime referenceDate,
      final Extension nonce,
      final OCSPResp ocspResponse)
      throws GemPkiException {

    // TODO: Warnmeldung, dass keine Online-Statusprüfung durchgeführt wurde (NO_OCSP_CHECK).
    initializeTransceiver(x509EeCert, x509IssuerCert);
    initializeValidator();

    tucPki030OcspValidator.validateCertificate(
        x509EeCert, x509IssuerCert, referenceDate, nonce, ocspResponse);
  }

  protected Extension resolveOcspNonce(final Extension nonce, final OCSPResp ocspResponse) {
    if (nonce != null) {
      return nonce;
    }

    if (ocspResponse != null) {
      return null;
    }

    return OcspRequestGenerator.generateNonceExtension();
  }

  protected ZonedDateTime getChainReferenceDate(@NonNull final X509Certificate x509EeCert) {
    return x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);
  }

  protected TspServiceSubset findQesCaCertificate(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    final List<TspService> qesCaServices =
        tspServiceListBNetzAVl.stream()
            .filter(
                tspService ->
                    TslConstants.STI_QC.equals(
                        tspService
                            .getTspServiceType()
                            .getServiceInformation()
                            .getServiceTypeIdentifier()))
            .toList();
    return new TspInformationProvider(qesCaServices, productType)
        .getIssuerQesCaTspServiceSubset(x509EeCert);
  }
}
