/*
 * Copyright (c) 2022 gematik GmbH
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

package de.gematik.pki.gemlibpki.exception;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class GemPkiExceptionTest {

  private String productType;
  private String compType;

  @BeforeAll
  void setupFixture() {
    productType = "IDP";
    compType = productType + ":PKI";
  }

  @Test
  void testGemPkiExceptionContainsProductType() {

    assertThatThrownBy(
            () -> {
              throw new GemPkiException(productType, ErrorCode.SE_1003);
            })
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.SE_1003.getErrorMessage(productType));
  }

  @Test
  void testGemPkiExceptionContainsPkiPrefix() {

    assertThatThrownBy(
            () -> {
              throw new GemPkiException(productType, ErrorCode.SE_1003);
            })
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(compType);
  }
}
