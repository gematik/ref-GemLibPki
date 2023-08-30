/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_TSL_SIG;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;
import org.w3c.dom.Node;

/**
 * Class for verification checks on a certificate against a profile. This class works with
 * parameterized variables (defined by builder pattern) and with given variables provided by runtime
 * (method parameters).
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public final class CertificateProfileVerification {

  @NonNull private final String productType;
  @NonNull private final TspServiceSubset tspServiceSubset;
  @NonNull private final CertificateProfile certificateProfile;
  @NonNull private final X509Certificate x509EeCert;

  // ####################  Start KeyUsage ########################################################

  /**
   * Perform all verification checks
   *
   * @throws GemPkiException thrown if cert cannot be verified according to KeyUsage, ExtKeyUsage or
   *     CertType
   */
  public void verifyAll() throws GemPkiException {
    verifyKeyUsage();
    verifyExtendedKeyUsage();
    verifyCertificateType();
    verifyCriticalExtensions();
  }

  /**
   * Verify that all intended KeyUsage bit(s) of certificate profile {@link CertificateProfile}
   * match against KeyUsage(s) of parameterized end-entity certificate.
   *
   * @throws GemPkiException if the certificate has a wrong key usage
   */
  public void verifyKeyUsage() throws GemPkiException {
    final boolean[] certKeyUsage = x509EeCert.getKeyUsage();
    if (certKeyUsage == null) {
      throw new GemPkiException(productType, ErrorCode.SE_1016_WRONG_KEYUSAGE);
    }
    int nrBitsEe = 0;

    for (final boolean bit : certKeyUsage) {
      if (bit) {
        nrBitsEe++;
      }
    }
    final List<KeyUsage> intendedKeyUsageList =
        getIntendedKeyUsagesFromCertificateProfile(certificateProfile);
    if (nrBitsEe != intendedKeyUsageList.size()) {
      throw new GemPkiException(productType, ErrorCode.SE_1016_WRONG_KEYUSAGE);
    }
    for (final KeyUsage keyUsage : intendedKeyUsageList) {
      if (!certKeyUsage[keyUsage.getBit()]) {
        throw new GemPkiException(productType, ErrorCode.SE_1016_WRONG_KEYUSAGE);
      }
    }
  }

  /**
   * Get list of KeyUsage(s) to the parameterized certificate profile {@link CertificateProfile}.
   *
   * @param certificateProfile The certificate profile
   * @return List with keyUsage(s)
   */
  private static List<KeyUsage> getIntendedKeyUsagesFromCertificateProfile(
      final CertificateProfile certificateProfile) {
    return CertificateProfile.valueOf(certificateProfile.name()).getKeyUsages();
  }

  // ####################  End KeyUsage ########################################################
  // ####################  Start ExtendedKeyUsage ##############################################

  /**
   * Verify oid of intended ExtendedKeyUsage(s) from certificate profile {@link CertificateProfile}
   * must match with oid(s) from a parameterized end-entity certificate with respect to cardinality.
   *
   * @throws GemPkiException if certificate has a wrong key usage
   */
  public void verifyExtendedKeyUsage() throws GemPkiException {
    final List<String> eeExtendedKeyUsagesOid;
    try {
      eeExtendedKeyUsagesOid = x509EeCert.getExtendedKeyUsage();
    } catch (final CertificateParsingException e) {
      throw new GemPkiRuntimeException(
          "Fehler beim Lesen der ExtendedKeyUsages des Zertifikats: "
              + x509EeCert.getSubjectX500Principal().getName(),
          e);
    }
    final List<String> intendedExtendedKeyUsageOidList =
        getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(certificateProfile);
    if (eeExtendedKeyUsagesOid == null) {
      if (intendedExtendedKeyUsageOidList.isEmpty() || !certificateProfile.isFailOnMissingEku()) {
        return;
      } else {
        throw new GemPkiException(productType, ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE);
      }
    }
    final List<String> filteredList =
        eeExtendedKeyUsagesOid.stream()
            .filter(
                eeOid ->
                    intendedExtendedKeyUsageOidList.stream()
                        .anyMatch(intOid -> intOid.equals(eeOid)))
            .toList();
    if (filteredList.isEmpty()
        || (eeExtendedKeyUsagesOid.size() != intendedExtendedKeyUsageOidList.size())) {
      log.debug("{}", ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
      throw new GemPkiException(productType, ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE);
    }
  }

  /**
   * Get list of oid(s) of ExtendedKeyUsage(s) to the parameterized profile.
   *
   * @param certificateProfile The certificate profile
   * @return List of oid(s) of ExtendedKeyUsages from certificate profile {@link CertificateProfile}
   */
  private static List<String> getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(
      final CertificateProfile certificateProfile) {
    return CertificateProfile.valueOf(certificateProfile.name()).getExtKeyUsages().stream()
        .map(ExtendedKeyUsage::getOid)
        .toList();
  }

  // ####################  End ExtendedKeyUsage #####################
  // ############## Start certificate type checks ###################

  /**
   * Verify type of parameterized end-entity certificate against parameterized certificate profile
   * {@link CertificateProfile}.
   *
   * @throws GemPkiException if certificate type verification fails
   */
  public void verifyCertificateType() throws GemPkiException {
    if (!certificateProfile.equals(CERT_PROFILE_C_TSL_SIG)) {
      final Set<String> certificatePolicyOids = getCertificatePolicyOids(x509EeCert);
      verifyCertificateProfileByCertificateTypeOid(certificatePolicyOids);
      verifyCertificateTypeOidInIssuerTspServiceExtension(certificatePolicyOids);
    }
  }

  /** AFO GS-A_4661-01 (RFC5280#4.2) */
  public void verifyCriticalExtensions() throws GemPkiException {
    final Set<String> certCriticalExtensions = x509EeCert.getCriticalExtensionOIDs();

    // NOTE: as specified in gemSpec_PKI 2.15.0 for all certificate profiles in Kapitel 5
    // X.509-Zertifikate

    final Set<String> expectedCriticalExtensions =
        Set.of(Extension.basicConstraints.getId(), Extension.keyUsage.getId());

    if (!expectedCriticalExtensions.equals(certCriticalExtensions)) {
      log.error(
          "Detected unknown / missing critical extensions in certificate {} vs expected {}",
          new TreeSet<>(certCriticalExtensions),
          new TreeSet<>(expectedCriticalExtensions));
      throw new GemPkiException(productType, ErrorCode.CUSTOM_CERTIFICATE_EXCEPTION);
    }
  }

  /**
   * Check given list of certificate policy type oid(s) contains type oid from parameterized
   * certificate profile {@link CertificateProfile}.
   *
   * @param certificatePolicyOidList list with policy oid(s)
   * @throws GemPkiException if the certificate has a wong cert type
   */
  private void verifyCertificateProfileByCertificateTypeOid(
      final Set<String> certificatePolicyOidList) throws GemPkiException {
    if (!certificatePolicyOidList.contains(certificateProfile.getCertificateType().getOid())) {
      log.debug("ZertifikatsTypOids im Zertifikat: {}", certificatePolicyOidList);
      log.debug(
          "Erwartete ZertifikatsTypOid: {}", certificateProfile.getCertificateType().getOid());
      throw new GemPkiException(productType, ErrorCode.SE_1018_CERT_TYPE_MISMATCH);
    }
  }

  /**
   * Verify that list of extension oid(s) from issuer TspService contains at least one oid of given
   * certificate type oid list.
   *
   * @param certificateTypeOidList a list with certificate type oid(s)
   * @throws GemPkiException if the certificate issuer is not allowed to issue this cert type
   */
  private void verifyCertificateTypeOidInIssuerTspServiceExtension(
      final Set<String> certificateTypeOidList) throws GemPkiException {
    log.debug(
        "Prüfe CA Authorisierung für die Herausgabe des Zertifikatstyps {} ",
        certificateProfile.getCertificateType().getOidReference());
    for (final ExtensionType extensionType : tspServiceSubset.getExtensions()) {
      final List<Object> content = extensionType.getContent();
      for (final Object object : content) {
        if (object instanceof final Node node) {
          final Node firstChild = node.getFirstChild();
          if (certificateTypeOidList.contains(firstChild.getNodeValue().trim())) {
            return;
          }
        }
      }
    }
    throw new GemPkiException(productType, ErrorCode.SE_1061_CERT_TYPE_CA_NOT_AUTHORIZED);
  }

  /**
   * Get policy oids to given end-entity certificate. 1.Test: exists policy extension oid identifier
   * at all (implizit over IllegalArgumentException). 2.Test: extract value from policy extension
   * oid.
   *
   * @param x509EeCert end-entity certificate
   * @return Set<String> policy oids from end-entity certificate
   * @throws GemPkiException if the certificate has no cert type
   */
  private Set<String> getCertificatePolicyOids(final X509Certificate x509EeCert)
      throws GemPkiException {
    try {
      final Policies policies = new Policies(x509EeCert);
      if (policies.getPolicyOids().isEmpty()) {
        throw new GemPkiException(productType, ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING);
      }
      return policies.getPolicyOids();
    } catch (final IllegalArgumentException e) {
      throw new GemPkiException(productType, ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING);
    } catch (final IOException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1019_CERT_READ_ERROR);
    }
  }
  // ############## End certificate type checks
  // #######################################################
}
