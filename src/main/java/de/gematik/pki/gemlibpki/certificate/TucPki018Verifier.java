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

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiParsingException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.ocsp.TucPki006OcspVerifier;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.EnumMap;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Entry point to access a verification of certificate(s) regarding standard process called
 * TucPki018. This class works with parameterized variables (defined by builder pattern) and with
 * given variables provided by runtime (method parameters).
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
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

  @Builder.Default protected final boolean tolerateOcspFailure = false;

  /**
   * Verify given end-entity certificate against TucPki18 (Technical Use Case 18 "Zertifikatsprüfung
   * in der TI", specified by gematik). If there is no {@link GemPkiException} the verification
   * process ends successfully.
   *
   * @param x509EeCert end-entity certificate to check
   * @return the determined {@link Admission}
   * @throws GemPkiException if the certificate is invalid
   */
  public Admission performTucPki18Checks(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    return performTucPki18Checks(x509EeCert, referenceDate);
  }

  /**
   * Verify given end-entity certificate against TucPki18 (Technical Use Case 18 "Zertifikatsprüfung
   * in der TI", specified by gematik). If there is no {@link GemPkiException} the verification
   * process ends successfully.
   *
   * @param x509EeCert end-entity certificate to check
   * @param referenceDate date to check revocation, producedAt, thisUpdate and nextUpdate against
   * @return the determined {@link Admission}
   * @throws GemPkiException if the certificate is invalid
   */
  public Admission performTucPki18Checks(
      @NonNull final X509Certificate x509EeCert, @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    log.debug("TUC_PKI_018 Checks...");
    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(tspServiceList, productType)
            .getIssuerTspServiceSubset(x509EeCert);

    commonChecks(x509EeCert, tspServiceSubset);
    doOcspIfConfigured(x509EeCert, tspServiceSubset, referenceDate);
    return tucPki018ProfileChecks(x509EeCert, tspServiceSubset);
  }

  /**
   * @param x509EeCert Certificate to check the OCSP status from
   * @param tspServiceSubset the corresponding TSL issuing service
   * @param referenceDate date to check revocation, producedAt, thisUpdate and nextUpdate against
   * @throws GemPkiException thrown if OCSP status is not "good" for the certificate
   */
  protected void doOcspIfConfigured(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final TspServiceSubset tspServiceSubset,
      @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {

    if (withOcspCheck) {
      final X509Certificate x509IssuerCert = tspServiceSubset.getX509IssuerCert();
      final OcspTransceiver transceiver =
          OcspTransceiver.builder()
              .productType(productType)
              .tspServiceList(tspServiceList)
              .x509EeCert(x509EeCert)
              .x509IssuerCert(x509IssuerCert)
              .ssp(tspServiceSubset.getServiceSupplyPoint())
              .ocspTimeoutSeconds(ocspTimeoutSeconds)
              .tolerateOcspFailure(tolerateOcspFailure)
              .build();

      if (ocspResponse == null) {
        transceiver.verifyOcspResponse(ocspRespCache, referenceDate);
      } else {
        final OCSPReq ocspReq =
            OcspRequestGenerator.generateSingleOcspRequest(x509EeCert, x509IssuerCert);
        try {
          final TucPki006OcspVerifier verifier =
              TucPki006OcspVerifier.builder()
                  .productType(productType)
                  .tspServiceList(tspServiceList)
                  .eeCert(x509EeCert)
                  .ocspResponse(ocspResponse)
                  .build();

          verifier.performOcspChecks(ocspReq, referenceDate);

        } catch (final GemPkiException e) {
          log.warn(ErrorCode.TW_1050_PROVIDED_OCSP_RESPONSE_NOT_VALID.getErrorMessage(productType));
          transceiver.verifyOcspResponse(ocspRespCache, referenceDate);
        }
      }
    } else {
      log.warn(ErrorCode.SW_1039_NO_OCSP_CHECK.getErrorMessage(productType));
    }
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
        log.debug("Rolle(n): {}", new Admission(x509EeCert).getProfessionItems());
        return new Admission(x509EeCert);
      } catch (final IOException e) {
        throw new GemPkiRuntimeException(
            "Fehler bei der Verarbeitung der Admission des Zertifikats: "
                + x509EeCert.getSubjectX500Principal().getName(),
            e);
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
      @NonNull final X509Certificate x509EeCert, @NonNull final TspServiceSubset tspServiceSubset)
      throws GemPkiException {

    final CertificateCommonVerification certificateCommonVerification =
        CertificateCommonVerification.builder()
            .productType(productType)
            .x509EeCert(x509EeCert)
            .tspServiceSubset(tspServiceSubset)
            .build();

    certificateCommonVerification.verifyAll();
  }
}
