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

package de.gematik.pki.gemlibpki.commons;

import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.readCertNonQes;

import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.security.cert.X509Certificate;

public class TestConstantsNonQes {

  public static final String FILE_NAME_TSL_DEFAULT_NON_QES = "tsls/nonqes/valid/TSL_default.xml";
  public static final String FILE_NAME_TSL_DEFECT_NON_QES_OCSP_SIGNER_TSP_MISSING =
      "tsls/nonqes/defect/TSL_defect_missingOcspSignerTsp.xml";

  public static final String FILE_NAME_TSL_DEFAULT_NON_QES_SIGNER_SSP_LOCALHOST =
      "tsls/nonqes/valid/TSL_default_signer_51_SSP_Localhost.xml";
  public static final String FILE_NAME_TSL_NON_QES_ALT_CA = "tsls/nonqes/valid/TSL_altCA.xml";
  public static final String LOCAL_SSP_DIR = "/services/ocsp";
  public static final String OCSP_HOST = "http://localhost:";

  public static final String CERT_DIR_NON_QES = "src/test/resources/certificates/nonqes/";
  public static final X509Certificate VALID_ISSUER_CERT_SMCB =
      readCertNonQes("GEM.SMCB-CA57/GEM.SMCB-CA57-TEST-ONLY.pem");

  public static final X509Certificate VALID_X509_EE_CERT_SMCB =
      readCertNonQes("GEM.SMCB-CA57/valid/PraxisBabetteBeyer.pem");

  public static final X509Certificate VALID_X509_EE_CERT_SMCB_KZBV =
      readCertNonQes("GEM.SMCB-CA57/valid/Beyer-Zahnarzt.crt");

  public static final X509Certificate VALID_ISSUER_CERT_SMCB_CA41_RSA =
      readCertNonQes("GEM.SMCB-CA41-RSA/GEM.SMCB-CA41.pem");

  public static final X509Certificate VALID_X509_EE_CERT_SMCB_CA41_RSA =
      TestUtils.readCertNonQes("GEM.SMCB-CA41-RSA/Aschoffsche_Apotheke-AUT-RSA.pem");
  public static final X509Certificate VALID_ISSUER_CERT_HBA =
      readCertNonQes("GEM.HBA-CA57/GEM.HBA-CA57-TEST-ONLY.pem");

  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA57 =
      readCertNonQes("GEM.KOMP-CA57/GEM.KOMP-CA57-TEST-ONLY.pem");
  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA41 =
      readCertNonQes("GEM.KOMP-CA41/GEM.KOMP-CA41-TEST-ONLY.pem");
  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA51 =
      readCertNonQes("GEM.KOMP-CA51/GEM.KOMP-CA51.pem");
  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA61 =
      readCertNonQes("GEM.KOMP-CA61/GEM.KOMP-CA61-TEST-ONLY.pem");
  public static final X509Certificate VALID_X509_EE_CERT_ALT_CA =
      readCertNonQes("GEM.SMCB-CA59/80276001011699802021-Beyer-Zahnarzt-SMCB59.crt");

  public static final X509Certificate VALID_ISSUER_CERT_TSL_CA51 =
      readCertNonQes("GEM.TSL-CA51/GEM.TSL-CA51-TEST-ONLY.pem");

  public static final X509Certificate VALID_ISSUER_CERT_EGK =
      readCertNonQes("GEM.EGK-CA51/GEM.EGK-CA51-TEST-ONLY.pem");

  public static final X509Certificate VALID_X509_EE_CERT_INVALID_KEY_USAGE =
      TestUtils.readCertNonQes("GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-keyusage.pem");

  public static final X509Certificate VALID_HBA_AUT_ECC =
      readCertNonQes("GEM.HBA-CA57/BabetteBeyer.pem");

  public static final X509Certificate INVALID_CERT_TYPE =
      TestUtils.readCertNonQes("GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-certificate-type.pem");

  public static final X509Certificate MISSING_CERT_TYPE =
      TestUtils.readCertNonQes("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-certificate-type.pem");

  public static final X509Certificate MISSING_EXT_KEY_USAGE_EE_CERT =
      TestUtils.readCertNonQes("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-extKeyUsage.pem");

  public static final X509Certificate MISSING_POLICY_ID_CERT =
      TestUtils.readCertNonQes("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-policyId.pem");

  public static final X509Certificate INVALID_EXTENSION_NOT_CRIT_CERT =
      TestUtils.readCertNonQes("GEM.SMCB-CA57/valid/BabetteBeyer-invalid-extension-not-crit.pem");

  public static final String GEMATIK_TEST_TSP_NAME =
      "gematik Gesellschaft für Telematikanwendungen der Gesundheitskarte mbH";

  public static final X509Certificate TI20_VALID_X509_EE_CERT_SMCB =
      readCertNonQes("ti20/GEM.SMCB-CA57/Arztpraxis-Olga-Olbricht-Internet-TEST-ONLY.pem");
}
