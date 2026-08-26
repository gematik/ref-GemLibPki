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

import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.FILE_NAME_TSL_DEFAULT_NON_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_TSL_CA51;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_DEFAULT_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_QES_MISSING_KEYINFO_IN_SIGNATURE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_QES_MISSING_SIGNER_CERT_IN_SIGNATURE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_QES_SIGNATURE_BROKEN;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.commons.utils.ResourceReader;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslValidatorTest {

  @Test
  void
      checkNonQesTslSignatureWithTrustAnchor_whenRequiredArgumentsAreNull_thenThrowsOnNullParameter() {
    final Document nullTslDoc = null;
    assertNonNullParameter(
        () ->
            TslValidator.checkNonQesTslSignatureWithTrustAnchor(
                nullTslDoc, VALID_ISSUER_CERT_TSL_CA51),
        "tslToVerify");

    final byte[] nullTslBytes = null;
    assertNonNullParameter(
        () ->
            TslValidator.checkNonQesTslSignatureWithTrustAnchor(
                nullTslBytes, VALID_ISSUER_CERT_TSL_CA51),
        "tslToVerify");

    assertNonNullParameter(
        () -> TslValidator.checkNonQesTslSignatureWithTrustAnchor(new byte[] {0}, null),
        "trustAnchor");

    final Document tslAsDoc = TestUtils.getDefaultTslAsDocNonQes();
    assertNonNullParameter(
        () -> TslValidator.checkNonQesTslSignatureWithTrustAnchor(tslAsDoc, null), "trustAnchor");
  }

  @Test
  void checkNonQesTslSignatureWithTrustAnchor_whenTslSignatureIsValid_thenReturnsTrue() {
    final Document tslEcc =
        TslReader.getTslAsDoc(
            ResourceReader.getFilePathFromResources(
                FILE_NAME_TSL_DEFAULT_NON_QES, TestUtils.class));
    assertThat(
            TslValidator.checkNonQesTslSignatureWithTrustAnchor(tslEcc, VALID_ISSUER_CERT_TSL_CA51))
        .isTrue();
  }

  @Test
  void
      checkQesTslSignatureWithTslBasedTrust_whenValidQesTslIsProvided_thenReturnsTrueForDocumentAndBytes() {
    final Document tslQes =
        TslReader.getTslAsDoc(
            ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT_QES, TestUtils.class));
    assertThat(TslValidator.checkQesTslSignatureWithTslBasedTrust(tslQes)).isTrue();
    assertThat(TslValidator.checkQesTslSignatureWithTslBasedTrust(TslConverter.docToBytes(tslQes)))
        .isTrue();
  }

  @Test
  void
      checkQesTslSignatureWithTslBasedTrust_whenValidResignedQesTslIsProvided_thenReturnsTrueForDocumentAndBytes() {
    final Document tslQes =
        TslReader.getTslAsDoc(
            ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT_QES, TestUtils.class));
    assertThat(TslValidator.checkQesTslSignatureWithTslBasedTrust(tslQes)).isTrue();
    assertThat(TslValidator.checkQesTslSignatureWithTslBasedTrust(TslConverter.docToBytes(tslQes)))
        .isTrue();
  }

  @Test
  void checkQesTslSignatureWithTslBasedTrust_whenSignerCertificateIsMissing_thenReturnsFalse() {
    final Document tslQes =
        TslReader.getTslAsDoc(
            ResourceReader.getFilePathFromResources(
                FILE_NAME_TSL_QES_MISSING_SIGNER_CERT_IN_SIGNATURE, TestUtils.class));
    assertThat(TslValidator.checkQesTslSignatureWithTslBasedTrust(tslQes)).isFalse();
  }

  @Test
  void checkQesTslSignatureWithTslBasedTrust_whenSignatureValueIsInvalid_thenReturnsFalse() {
    final Document tslQes =
        TslReader.getTslAsDoc(
            ResourceReader.getFilePathFromResources(
                FILE_NAME_TSL_QES_SIGNATURE_BROKEN, TestUtils.class));
    assertThat(TslValidator.checkQesTslSignatureWithTslBasedTrust(tslQes)).isFalse();
  }

  @Test
  void checkQesTslSignatureWithTslBasedTrust_whenKeyInfoIsMissing_thenReturnsFalse() {
    final Document tslQes =
        TslReader.getTslAsDoc(
            ResourceReader.getFilePathFromResources(
                FILE_NAME_TSL_QES_MISSING_KEYINFO_IN_SIGNATURE, TestUtils.class));
    assertThat(TslValidator.checkQesTslSignatureWithTslBasedTrust(tslQes)).isFalse();
  }

  /**
   * fileTsleccDefault_signatureBroken is a copy of FILE_NAME_TSL_ECC_DEFAULT with modified
   * <ds:SignatureValue> element
   */
  @Test
  void checkNonQesTslSignatureWithTrustAnchor_whenSignatureValueIsBroken_thenReturnsFalse() {
    final String file_tslEccDefault_signatureBroken =
        "tsls/nonqes/invalid/TSL_invalid_Signature_broken.xml";
    final Document tslEcc =
        TslReader.getTslAsDoc(
            ResourceReader.getFilePathFromResources(
                file_tslEccDefault_signatureBroken, TestUtils.class));
    assertThat(
            TslValidator.checkNonQesTslSignatureWithTrustAnchor(tslEcc, VALID_ISSUER_CERT_TSL_CA51))
        .isFalse();
  }
}
