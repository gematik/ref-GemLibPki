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

package de.gematik.pki.gemlibpki;

import static de.gematik.pki.gemlibpki.utils.TestUtils.readCert;

import java.security.cert.X509Certificate;

public class TestConstants {
  public static final String P12_PASSWORD = "00";
  public static final String PRODUCT_TYPE = "Unittest";
  public static final String FILE_NAME_TSL_ECC_DEFAULT = "tsls/ecc/valid/TSL_default.xml";
  public static final String FILE_NAME_TSL_ECC_ALT_CA = "tsls/ecc/valid/TSL_altCA.xml";
  public static final String FILE_NAME_TSL_RSA_DEFAULT = "tsls/rsa/valid/TSL_default.xml";
  public static final String FILE_NAME_TSL_RSA_NOSIG = "tsls/rsa/valid/TSL_default_noSig.xml";
  public static final String FILE_NAME_TSL_RSA_ALT_TA = "tsls/rsa/valid/TSL_altTA.xml";
  public static final String LOCAL_SSP_DIR = "/services/ocsp";
  public static final String OCSP_HOST = "http://localhost:";

  public static final String CERT_DIR = "src/test/resources/certificates/";
  public static final X509Certificate VALID_ISSUER_CERT_SMCB =
      readCert("GEM.SMCB-CA10/GEM.SMCB-CA10_TEST-ONLY.pem");

  public static final X509Certificate VALID_ISSUER_CERT_SMCB_RSA =
      readCert("GEM.SMCB-CA24-RSA/GEM.SMCB-CA24.pem");

  public static final X509Certificate VALID_ISSUER_CERT_HBA =
      readCert("GEM.HBA-CA13/GEM.HBA-CA13_brainpoolIP256r1.pem");

  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA10 =
      readCert("GEM.KOMP-CA10/GEM.KOMP-CA10_brainpoolIP256r1.pem");

  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA50 =
      readCert("GEM.KOMP-CA50/GEM.KOMP-CA50-TEST-ONLY.pem");

  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA54 =
      readCert("GEM.KOMP-CA54/GEM.KOMP-CA54.pem");

  public static final X509Certificate VALID_ISSUER_CERT_TSL_CA8 =
      readCert("GEM.TSL-CA8/GEM.TSL-CA8_brainpoolIP256r1.pem");

  public static final X509Certificate VALID_ISSUER_CERT_EGK =
      readCert("GEM.EGK-CA10/GEM.EGK-CA10-TEST-ONLY.pem");

  public static final String GEMATIK_TEST_TSP_NAME =
      "gematik Gesellschaft für Telematikanwendungen der Gesundheitskarte mbH";
}
