/*
 * Copyright 2025, gematik GmbH
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
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.exception;

import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class GemPkiExceptionTest {

  private String compType;

  @BeforeAll
  void setupFixture() {
    compType = PRODUCT_TYPE + ":PKI";
  }

  @Test
  void testGemPkiExceptionContainsProductType() {

    assertThatThrownBy(
            () -> {
              throw new GemPkiException(PRODUCT_TYPE, ErrorCode.SE_1003_MULTIPLE_TRUST_ANCHOR);
            })
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1003_MULTIPLE_TRUST_ANCHOR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void testGemPkiExceptionContainsPkiPrefix() {

    assertThatThrownBy(
            () -> {
              throw new GemPkiException(PRODUCT_TYPE, ErrorCode.SE_1003_MULTIPLE_TRUST_ANCHOR);
            })
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(compType);
  }

  @Test
  void nonNullTests() {
    assertNonNullParameter(
        () -> new GemPkiException(null, ErrorCode.SE_1003_MULTIPLE_TRUST_ANCHOR), "productType");
    assertThatThrownBy(() -> new GemPkiException(PRODUCT_TYPE, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage(
            "Cannot invoke \"de.gematik.pki.gemlibpki.error.ErrorCode.getErrorMessage(String)\""
                + " because \"error\" is null");

    final Exception exception = new Exception();
    assertNonNullParameter(
        () -> new GemPkiException(null, ErrorCode.SE_1003_MULTIPLE_TRUST_ANCHOR, exception),
        "productType");
    assertThatThrownBy(() -> new GemPkiException(PRODUCT_TYPE, null, exception))
        .isInstanceOf(NullPointerException.class)
        .hasMessage(
            "Cannot invoke \"de.gematik.pki.gemlibpki.error.ErrorCode.getErrorMessage(String)\""
                + " because \"error\" is null");

    assertNonNullParameter(() -> new GemPkiException(null, "blub", exception), "error");
    assertNonNullParameter(
        () -> new GemPkiException(ErrorCode.SE_1003_MULTIPLE_TRUST_ANCHOR, null, exception),
        "message");
  }
}
