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

package de.gematik.pki.gemlibpki.ocsp;

import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.cert.X509Certificate;
import lombok.Getter;

public class OcspTestConstants {

  @Getter
  private static final P12Container ocspSignerRsa = TestUtils.readP12("ocsp/rsaOcspSigner.p12");

  @Getter
  private static final P12Container ocspSignerEcc = TestUtils.readP12("ocsp/eccOcspSigner.p12");

  @Getter
  private static final X509Certificate ocspSignerCaEcc =
      TestUtils.readCert("GEM.EGK-CA57/GEM.EGK-CA57-TEST-ONLY.pem");

  public static final int TIMEOUT_DELTA_MILLISECONDS = 1500;
}
