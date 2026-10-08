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

package de.gematik.pki.gemlibpki.commons.tsl;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.validation.Validator;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TucPki036Verifier {

  @NonNull protected final String productType;

  @NonNull protected final List<TspService> currentTrustedServices;

  protected final byte @NonNull [] bNetzAVlToCheck;

  @Builder
  protected TucPki036Verifier(
      final @NonNull String productType,
      final @NonNull List<TspService> currentTrustedServices,
      final byte @NonNull [] bNetzAVlToCheck) {
    this.productType = productType;
    this.currentTrustedServices = currentTrustedServices;
    this.bNetzAVlToCheck = bNetzAVlToCheck;
  }

  private static final String[] BNETZA_VL_SCHEMES = {
    "schemas_BNetzAVl/19612_xsd.xsd",
    "schemas_BNetzAVl/19612_additionaltypes_xsd.xsd",
    "schemas_BNetzAVl/19612_sie_xsd.xsd"
  };

  /**
   * Verify the period of validity of a BNetzAVl against a given reference date.
   *
   * @param referenceDate date to check against
   * @param tsl the VL to check
   * @param productType the product type for error reporting
   * @throws GemPkiException if the TSL is not valid in time
   */
  public static void verifyBNetzAVlValidity(
      final ZonedDateTime referenceDate, final TrustStatusListType tsl, final String productType)
      throws GemPkiException {

    final XMLGregorianCalendar xmlNextUpdate =
        tsl.getSchemeInformation().getNextUpdate().getDateTime();

    final ZonedDateTime nextUpdate =
        ZonedDateTime.ofInstant(xmlNextUpdate.toGregorianCalendar().toInstant(), ZoneOffset.UTC);

    if (nextUpdate.isAfter(referenceDate)) {
      return;
    }

    throw new GemPkiException(productType, ErrorCode.TE_1060_VL_UPDATE_ERROR);
  }

  public void performTucPki036Checks() throws GemPkiException {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    validateWellFormedXml();
    validateAgainstXsdSchemas();
    verifyBNetzAVlValidity(
        referenceDate, TslConverter.bytesToTslUnsigned(bNetzAVlToCheck), productType);
    final TspService tspServiceBNetzAVl = findBNetzAVlTspService();
    final X509Certificate bNetzAVlSignerCert = getBNetzAVlSignerCertificate();
    final X509Certificate bNetzAVlSignerCertFromTsl =
        getBNetzAVlSignerCertificateFromTsl(tspServiceBNetzAVl, bNetzAVlSignerCert);
    TslValidator.verifyQesTslSignature(
        bNetzAVlToCheck,
        bNetzAVlSignerCertFromTsl,
        productType,
        ErrorCode.SE_1013_XML_SIGNATURE_ERROR);
  }

  private X509Certificate getBNetzAVlSignerCertificateFromTsl(
      final TspService tspServiceBNetzAVl, final X509Certificate bNetzAVlSignerCert)
      throws GemPkiException {
    return tspServiceBNetzAVl
        .getMatchingCertificate(bNetzAVlSignerCert)
        .orElseThrow(() -> new GemPkiException(productType, ErrorCode.TE_1060_VL_UPDATE_ERROR));
  }

  protected TspService findBNetzAVlTspService() throws GemPkiException {
    return currentTrustedServices.stream()
        .filter(
            tspService ->
                tspService.hasServiceTypeIdentifier(TslConstants.SERVICE_TYPE_IDENTIFIER_BNETZAVL))
        .findFirst()
        .orElseThrow(() -> new GemPkiException(productType, ErrorCode.TE_1060_VL_UPDATE_ERROR));
  }

  protected void validateWellFormedXml() throws GemPkiException {
    TslSchemaValidator.validateWellFormedXml(
        bNetzAVlToCheck, productType, ErrorCode.TE_1060_VL_UPDATE_ERROR);
  }

  protected void validateAgainstXsdSchemas() throws GemPkiException {
    for (final String scheme : BNETZA_VL_SCHEMES) {
      validateAgainstXsd(scheme);
    }
    log.info("Schema validation successful!");
  }

  Validator getValidator(final String scheme) {
    return TslSchemaValidator.getValidator(scheme, TucPki036Verifier.class);
  }

  void validateAgainstXsd(final String scheme) throws GemPkiException {
    TslSchemaValidator.validateAgainstXsd(
        getValidator(scheme), bNetzAVlToCheck, productType, ErrorCode.TE_1060_VL_UPDATE_ERROR);
  }

  protected X509Certificate getBNetzAVlSignerCertificate() throws GemPkiException {
    try {
      return TslUtils.getFirstTslSignerCertificate(
          TslConverter.bytesToTslUnsigned(bNetzAVlToCheck));
    } catch (final RuntimeException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1060_VL_UPDATE_ERROR);
    }
  }
}
