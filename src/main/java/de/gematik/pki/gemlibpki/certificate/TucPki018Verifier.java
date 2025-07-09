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

import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiParsingException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.validators.OcspValidator;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.EnumMap;
import java.util.List;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Entry point to access a verification of certificate(s) regarding standard process called
 * TucPki018. This class works with parameterized variables (defined by builder pattern) and with
 * given variables provided by runtime (method parameters).
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public class TucPki018Verifier {

  @NonNull protected final String productType;
  @NonNull protected final List<TspService> tspServiceList;
  @NonNull protected final List<CertificateProfile> certificateProfiles;
  @Builder.Default protected final boolean withOcspCheck = true;
  protected final OCSPResp ocspResponse;
  protected final OcspRespCache ocspRespCache;

  @Builder.Default
  protected final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @Builder.Default
  private final int ocspTimeToleranceProducedAtFutureMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;

  @Builder.Default
  private final int ocspTimeToleranceProducedAtPastMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

  @Builder.Default protected final boolean tolerateOcspFailure = false;

  @Builder.Default private OcspValidator ocspValidator = null;
  @Builder.Default private OcspTransceiver ocspTransceiver = null;

  /**
   * Verify given end-entity certificate against TucPki18 (Technical Use Case 18 "Zertifikatsprüfung
   * in der TI", specified by gematik). If there is no {@link GemPkiException} the verification
   * process ends successfully. GS-A_4660-02
   *
   * @param x509EeCert end-entity certificate to check
   * @return the determined {@link Admission}
   * @throws GemPkiException if the certificate is invalid
   */
  public Admission performTucPki018Checks(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    return performTucPki018Checks(x509EeCert, referenceDate);
  }

  /**
   * Verify given end-entity certificate against TucPki18 (Technical Use Case 18 "Zertifikatsprüfung
   * in der TI", specified by gematik). If there is no {@link GemPkiException} the verification
   * process ends successfully. GS-A_4660-02
   *
   * @param x509EeCert end-entity certificate to check
   * @param referenceDate date to check revocation, producedAt, thisUpdate and nextUpdate against
   * @return the determined {@link Admission}
   * @throws GemPkiException if the certificate is invalid
   */
  public Admission performTucPki018Checks(
      @NonNull final X509Certificate x509EeCert, @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    log.debug("TUC_PKI_018 Checks...");
    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(tspServiceList, productType)
            .getIssuerTspServiceSubset(x509EeCert);

    commonChecks(x509EeCert, tspServiceSubset, referenceDate);
    doOcspIfConfigured(x509EeCert, referenceDate);
    return tucPki018ProfileChecks(x509EeCert, tspServiceSubset);
  }

  private void initializeValidator() {

    if (ocspValidator != null) {
      return;
    }

    ocspValidator =
        OcspValidator.builder()
            .productType(productType)
            .tspServiceList(tspServiceList)
            .withOcspCheck(withOcspCheck)
            .ocspResponse(ocspResponse)
            .ocspRespCache(ocspRespCache)
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .ocspTransceiver(ocspTransceiver)
            .tolerateOcspFailure(tolerateOcspFailure)
            .ocspTimeToleranceProducedAtFutureMilliseconds(
                ocspTimeToleranceProducedAtFutureMilliseconds)
            .ocspTimeToleranceProducedAtPastMilliseconds(
                ocspTimeToleranceProducedAtPastMilliseconds)
            .build();
  }

  private void initializeTransceiver(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {

    if (ocspTransceiver != null) {
      return;
    }

    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(tspServiceList, productType)
            .getIssuerTspServiceSubset(x509EeCert);
    final X509Certificate x509IssuerCert = tspServiceSubset.getX509IssuerCert();

    ocspTransceiver =
        OcspTransceiver.builder()
            .productType(productType)
            .x509EeCert(x509EeCert)
            .x509IssuerCert(x509IssuerCert)
            .ssp(tspServiceSubset.getServiceSupplyPoint())
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .tolerateOcspFailure(tolerateOcspFailure)
            .build();
  }

  /**
   * @param x509EeCert Certificate to check the OCSP status from
   * @param referenceDate date to check revocation, producedAt, thisUpdate and nextUpdate against
   * @throws GemPkiException thrown if OCSP status is not "good" for the certificate
   */
  protected void doOcspIfConfigured(
      @NonNull final X509Certificate x509EeCert, @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    initializeTransceiver(x509EeCert);
    initializeValidator();

    ocspValidator.validateCertificate(x509EeCert, referenceDate);
  }

  /**
   * Performs TUC_PKI_018 checks (Certificate verification). Verifies given end-entity certificate
   * against the list of parameterized certificate profiles {@link CertificateProfile}.
   *
   * @param x509EeCert end-entity certificate to check
   * @param tspServiceSubset the issuing certificates as trust store
   * @return the determined {@link Admission}
   * @throws GemPkiException if the certificate is invalid
   */
  protected Admission tucPki018ProfileChecks(
      @NonNull final X509Certificate x509EeCert, @NonNull final TspServiceSubset tspServiceSubset)
      throws GemPkiException {
    if (certificateProfiles.isEmpty()) {
      throw new GemPkiRuntimeException("Liste der konfigurierten Zertifikatsprofile ist leer.");
    }

    final EnumMap<CertificateProfile, GemPkiException> errors =
        new EnumMap<>(CertificateProfile.class);
    for (final CertificateProfile certificateProfile : certificateProfiles) {
      try {
        tucPki018ChecksForProfile(x509EeCert, certificateProfile, tspServiceSubset);
        log.debug(
            "Übergebenes Zertifikat wurde erfolgreich gegen das Zertifikatsprofil {} getestet.",
            certificateProfile);

        final Admission admission = new Admission(x509EeCert);
        if (!admission.getProfessionOids().isEmpty()) {
          log.debug("Gefundene Rolle(n): {}", admission.getProfessionItems());
        }
        return admission;
      } catch (final IOException e) {
        throw new GemPkiRuntimeException(
            "Error in processing the admission of the end entity certificate.", e);
      } catch (final GemPkiException e) {
        errors.put(certificateProfile, e);
      }
    }
    throw new GemPkiParsingException(productType, errors);
  }

  /**
   * Verify given end-entity certificate against a parameterized single certificate profile {@link
   * CertificateProfile}. If there is no {@link GemPkiException} the verification process ends
   * successfully.
   *
   * @param x509EeCert end-entity certificate to check
   * @param certificateProfile the profile to check the certificate against
   * @param tspServiceSubset the issuing certificates as trust store
   * @throws GemPkiException if the certificate is invalid
   */
  protected void tucPki018ChecksForProfile(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final CertificateProfile certificateProfile,
      @NonNull final TspServiceSubset tspServiceSubset)
      throws GemPkiException {

    final CertificateProfileVerification certificateProfileVerification =
        CertificateProfileVerification.builder()
            .productType(productType)
            .x509EeCert(x509EeCert)
            .certificateProfile(certificateProfile)
            .tspServiceSubset(tspServiceSubset)
            .build();

    certificateProfileVerification.verifyAll();
  }

  /**
   * Common checks for date/mathematical validity and certificate chain
   *
   * @param x509EeCert end-entity certificate to check
   * @param tspServiceSubset the issuing certificates as trust store
   * @throws GemPkiException if the certificate verification fails
   */
  protected void commonChecks(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final TspServiceSubset tspServiceSubset,
      @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {

    final CertificateCommonVerification certificateCommonVerification =
        CertificateCommonVerification.builder()
            .productType(productType)
            .x509EeCert(x509EeCert)
            .tspServiceSubset(tspServiceSubset)
            .referenceDate(referenceDate)
            .build();

    certificateCommonVerification.verifyAll();
  }

  /**
   * Check if the professionOid from a given admission matches one from a parameterized list
   *
   * @param admissionToCheck the admission from the certificate
   * @param allowedProfessionOids the list of allowed profession oid's
   * @return Boolean if the profession item is in the list
   */
  public static boolean checkAllowedProfessionOids(
      final Admission admissionToCheck, @NonNull final Set<String> allowedProfessionOids) {

    if (admissionToCheck == null) {
      return false;
    }

    if (admissionToCheck.getProfessionOids().isEmpty()) {
      return false;
    }

    return isPresent(admissionToCheck.getProfessionOids(), allowedProfessionOids);
  }

  private static boolean isPresent(final Set<String> setToSearch, final Set<String> set) {
    return setToSearch.removeAll(set);
  }
}
