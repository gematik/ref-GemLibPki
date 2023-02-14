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

package de.gematik.pki.gemlibpki.utils;

import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.calculateSha1;
import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.calculateSha256;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.function.BiConsumer;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class GemLibPkiUtilsTest {

  @Test
  void testChangeLast4Bytes() {
    final byte[] originalBytes = {0b0, 0b0, 0b0, 0b0, 0b0, 0b0, 0b0, 0b0};
    final byte[] lastIndexArr0 = {0b0, 0b0, 0b0, 0b0, 0b1, 0b1, 0b1, 0b1};
    final byte[] lastIndexArr1 = {0b0, 0b0, 0b0, 0b1, 0b1, 0b1, 0b1, 0b0};
    final byte[] lastIndexArr2 = {0b0, 0b0, 0b1, 0b1, 0b1, 0b1, 0b0, 0b0};
    final byte[] lastIndexArr3 = {0b0, 0b1, 0b1, 0b1, 0b1, 0b0, 0b0, 0b0};
    final byte[] lastIndexArr4 = {0b1, 0b1, 0b1, 0b1, 0b0, 0b0, 0b0, 0b0};

    final BiConsumer<byte[], Integer> assertFunc =
        (arrExpected, lastIndex) -> {
          final byte[] arrActual = ArrayUtils.clone(originalBytes);
          GemLibPkiUtils.change4Bytes(arrActual, lastIndex);
          assertThat(arrActual)
              .as("change4Bytes with lastIndex = " + lastIndex)
              .isEqualTo(arrExpected);
        };

    final byte[] arrActual = ArrayUtils.clone(originalBytes);
    GemLibPkiUtils.changeLast4Bytes(arrActual);
    assertThat(arrActual).isEqualTo(lastIndexArr0);

    final int length = lastIndexArr0.length;
    assertFunc.accept(lastIndexArr0, length);
    assertFunc.accept(lastIndexArr1, length - 1);
    assertFunc.accept(lastIndexArr2, length - 2);
    assertFunc.accept(lastIndexArr3, length - 3);
    assertFunc.accept(lastIndexArr4, length - 4);
  }

  @Test
  void verifyCalculateSha1() {
    assertThat(
            new String(
                Hex.encode(calculateSha1("test".getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8))
        .isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
  }

  @Test
  void verifyCalculateSha256() {
    assertThat(
            new String(
                Hex.encode(calculateSha256("test".getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8))
        .isEqualTo("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
  }
}
