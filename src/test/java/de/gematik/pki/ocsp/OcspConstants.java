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

package de.gematik.pki.ocsp;

import de.gematik.pki.utils.P12Container;
import de.gematik.pki.utils.P12Reader;
import java.nio.file.Path;
import lombok.Getter;

public class OcspConstants {

    public static final Path P12_OCSP_RESPONSE_SIGNER_RSA = Path.of("src/test/resources/certificates/ocsp/rsaOcspSigner.p12");
    public static final Path P12_OCSP_RESPONSE_SIGNER_ECC = Path.of("src/test/resources/certificates/ocsp/eccOcspSigner.p12");
    public static final String P12_PASSWORD = "00";

    @Getter
    private static final P12Container ocspSignerRsa;
    @Getter
    private static final P12Container ocspSignerEcc;

    static {
        ocspSignerRsa = P12Reader.getContentFromP12(P12_OCSP_RESPONSE_SIGNER_RSA, P12_PASSWORD);
        ocspSignerEcc = P12Reader.getContentFromP12(P12_OCSP_RESPONSE_SIGNER_ECC, P12_PASSWORD);
    }

}
