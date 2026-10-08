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

import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_DEFAULT_QES;
import static de.gematik.pki.gemlibpki.commons.utils.ResourceReader.getFileFromResourceAsBytes;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import javax.xml.validation.Validator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.xml.sax.SAXException;

class TucPki036VerifierTest {

  private static final String PRODUCT_TYPE = "testProductType";
  private static List<TspService> tspServicesInTruststore;
  private static byte[] bNetzAVlToCheck;
  private static TrustStatusListType bNetzAVlToCheckTslUnsigned;

  @BeforeAll
  static void start() {
    bNetzAVlToCheckTslUnsigned = TestUtils.getDefaultTslUnsignedQes();
    bNetzAVlToCheck =
        getFileFromResourceAsBytes(FILE_NAME_TSL_DEFAULT_QES, TucPki036VerifierTest.class);
    final X509Certificate bNetzAVlSignerCert =
        TslUtils.getFirstTslSignerCertificate(bNetzAVlToCheckTslUnsigned);
    final TspService bNetzAVlTspService = Mockito.mock(TspService.class);
    Mockito.when(
            bNetzAVlTspService.hasServiceTypeIdentifier(
                TslConstants.SERVICE_TYPE_IDENTIFIER_BNETZAVL))
        .thenReturn(true);
    Mockito.when(bNetzAVlTspService.getMatchingCertificate(bNetzAVlSignerCert))
        .thenReturn(java.util.Optional.of(bNetzAVlSignerCert));
    tspServicesInTruststore = List.of(bNetzAVlTspService);
  }

  @Test
  void validateWellFormedXml_whenBnetzAVlisWellformed_thenDoesNotThrow() throws GemPkiException {

    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(bNetzAVlToCheck)
            .build();

    tucPki036Verifier.validateWellFormedXml();
  }

  @Test
  void validateWellFormedXml_whenBnetzAVlisNotWellformed_thenThrows() throws GemPkiException {
    final String bNetzAVlAsString = new String(bNetzAVlToCheck, StandardCharsets.UTF_8);
    final byte[] notWellFormedBNetzAVlToCheck =
        bNetzAVlAsString
            .substring(0, bNetzAVlAsString.lastIndexOf("</"))
            .getBytes(StandardCharsets.UTF_8);

    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(notWellFormedBNetzAVlToCheck)
            .build();

    assertThatThrownBy(tucPki036Verifier::validateWellFormedXml)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1060_VL_UPDATE_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void validateAgainstXsdSchemas_whenBNetzAVlMatchesSchemas_thenDoesNotThrow() {

    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(bNetzAVlToCheck)
            .build();

    assertDoesNotThrow(tucPki036Verifier::validateAgainstXsdSchemas);
  }

  @Test
  void getValidator_whenValidScheme_thenDoesNotThrow() {
    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(bNetzAVlToCheck)
            .build();

    assertDoesNotThrow(
        () -> tucPki036Verifier.getValidator("schemas_BNetzAVl/19612_additionaltypes_xsd.xsd"));
  }

  @Test
  void getValidator_whenInvalidScheme_thenThrows() {
    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(bNetzAVlToCheck)
            .build();

    assertThatThrownBy(() -> tucPki036Verifier.getValidator("schemas/invalid.xsd"))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error during parsing of schema file.")
        .cause()
        .isInstanceOf(SAXException.class);
  }

  @Test
  void validateAgainstXsd_whenBNetzAVlViolatesSchema_thenThrowsGemPkiException() {
    final byte[] invalidBNetzAVlToCheck =
        new String(
                getFileFromResourceAsBytes(
                    "tsls/qes/valid/Pseudo-BNetzA-VL-valid.xml", TucPki036VerifierTest.class),
                StandardCharsets.UTF_8)
            .replace("<SchemeInformation>", "<SchemeInformationInvalid>")
            .replace("</SchemeInformation>", "</SchemeInformationInvalid>")
            .getBytes(StandardCharsets.UTF_8);

    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(invalidBNetzAVlToCheck)
            .build();

    assertThatThrownBy(() -> tucPki036Verifier.validateAgainstXsd("schemas_BNetzAVl/19612_xsd.xsd"))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1060_VL_UPDATE_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void validateAgainstXsd_whenValidatorThrowsIoException_thenThrowsGemPkiRuntimeException()
      throws IOException, SAXException {
    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(bNetzAVlToCheck)
            .build();

    final Validator validatorSpy = Mockito.spy(Validator.class);
    Mockito.doThrow(IOException.class).when(validatorSpy).validate(Mockito.any());

    final TucPki036Verifier tucPki036VerifierSpy = Mockito.spy(tucPki036Verifier);
    Mockito.doReturn(validatorSpy).when(tucPki036VerifierSpy).getValidator(Mockito.any());

    assertThatThrownBy(
            () -> tucPki036VerifierSpy.validateAgainstXsd("schemas_BNetzAVl/19612_xsd.xsd"))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error reading schema file.")
        .cause()
        .isInstanceOf(IOException.class);
  }

  @Test
  void verifyTslValidity_whenValidationTimeEqualsIssueDate_thenDoesNotThrow() {
    final ZonedDateTime issueDate = TslReader.getIssueDate(bNetzAVlToCheckTslUnsigned);
    assertDoesNotThrow(
        () ->
            TucPki036Verifier.verifyBNetzAVlValidity(
                issueDate, bNetzAVlToCheckTslUnsigned, PRODUCT_TYPE));
  }

  @Test
  void verifyTslValidity_whenValidationTimeExceedsNextUpdate_thenThrowsGemPkiException() {
    final ZonedDateTime nextUpdate = TslReader.getNextUpdate(bNetzAVlToCheckTslUnsigned);
    assertThatThrownBy(
            () ->
                TucPki036Verifier.verifyBNetzAVlValidity(
                    nextUpdate.plusSeconds(1), bNetzAVlToCheckTslUnsigned, PRODUCT_TYPE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1060_VL_UPDATE_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki036Checks() {
    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(bNetzAVlToCheck)
            .build();

    assertDoesNotThrow(tucPki036Verifier::performTucPki036Checks);
  }

  @Test
  void performTucPki036Checks_whenBNetzAVlSignatureIsInvalid_thenThrowsGemPkiException() {
    final byte[] bNetzAVlBytesUnsigned =
        TslConverter.tslUnsignedToBytes(bNetzAVlToCheckTslUnsigned);

    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(bNetzAVlBytesUnsigned)
            .build();

    assertThatThrownBy(tucPki036Verifier::performTucPki036Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1013_XML_SIGNATURE_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void getTslSignerCertificate() {
    final TucPki036Verifier tucPki036Verifier =
        TucPki036Verifier.builder()
            .productType(PRODUCT_TYPE)
            .currentTrustedServices(tspServicesInTruststore)
            .bNetzAVlToCheck(bNetzAVlToCheck)
            .build();

    assertDoesNotThrow(tucPki036Verifier::getBNetzAVlSignerCertificate);
  }
}
