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

import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.readCertQes;

import java.security.cert.X509Certificate;

public class TestConstantsQes {

  public static final String CERT_DIR_QES = "src/test/resources/certificates/qes/";
  public static final String FILE_NAME_TSL_DEFAULT_QES =
      "tsls/qes/valid/Pseudo-BNetzA-VL-valid.xml";
  public static final String FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA =
      "tsls/qes/valid/Pseudo-BNetzA-VL-valid-additionalCA.xml";
  // Alternative CA ist withdrawn, hat aber einen passenden GRANTED history-Eintrag für
  // entsprechendes EE-Zertifikat (ist also gültig)
  public static final String FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_BUT_GRANTED_HISTORY =
      "tsls/qes/valid/Pseudo-BNetzA-VL-valid-additionalCA-withdrawn-but-granted_in-history.xml";
  public static final String FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_AND_WITHOUT_HISTORY =
      "tsls/qes/valid/Pseudo-BNetzA-VL-valid-additionalCA-withdrawn-and-without-history.xml";
  public static final String FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_OCSP_SIGNER =
      "tsls/qes/valid/Pseudo-BNetzA-VL-valid-additionalOcspSigner.xml";

  public static final String FILE_NAME_TSL_QES_MISSING_KEYINFO_IN_SIGNATURE =
      "tsls/qes/invalid/Pseudo-BNetzA-VL-MissingKeyInfoInSignature.xml";
  public static final String FILE_NAME_TSL_QES_MISSING_SIGNER_CERT_IN_SIGNATURE =
      "tsls/qes/invalid/Pseudo-BNetzA-VL-MissingSignerCertInSignature.xml";
  public static final String
      FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_HISTORYENTRY_DOES_NOT_MATCH_EE_CERTIFICATE =
          "tsls/qes/valid/Pseudo-BNetzA-VL-valid-additionalCA-withdrawn-historyEntry-does-not-match-EE-certificate.xml";
  public static final String FILE_NAME_TSL_QES_SIGNATURE_BROKEN =
      "tsls/qes/invalid/Pseudo-BNetzA-VL-SignatureBroken.xml";

  // invalid certificates
  public static final X509Certificate X509_EE_CERT_QES_EXPIRED =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_expired.pem");
  public static final X509Certificate X509_EE_CERT_QES_MISSING_ADMISSION =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_missingAdmission.pem");
  public static final X509Certificate X509_EE_CERT_QES_MISSING_KEY_USAGE =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_missingKeyusage.pem");
  public static final X509Certificate X509_EE_CERT_QES_MISSING_OCSP_URL =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_MissingOCSPUrl.pem");
  public static final X509Certificate X509_EE_CERT_QES_MISSING_QC_STATEMENT =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_missingQCStatement.pem");
  public static final X509Certificate X509_EE_CERT_QES_MISSING_ROLE =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_missingRole.pem");
  public static final X509Certificate X509_EE_CERT_QES_NO_OCSP_IN_TSL =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_NoOCSPinTsl.pem");
  public static final X509Certificate X509_EE_CERT_QES_NOT_YET_VALID =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_notYetValid.pem");
  public static final X509Certificate X509_EE_CERT_QES_SIGNATURE_ERROR =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_SignaturError.pem");
  public static final X509Certificate X509_EE_CERT_QES_WRONG_ISSUER =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_wrongIssuer.pem");
  public static final X509Certificate X509_EE_CERT_QES_WRONG_KEY_USAGE =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_wrongKeyusage.pem");
  public static final X509Certificate X509_EE_CERT_QES_WRONG_QC_STATEMENT =
      readCertQes("default-CA/invalid/Apotheker-pkits-C_HP_QES_E256_wrongQCStatement.pem");

  // valid certificates
  // default CA
  public static final X509Certificate VALID_ISSUER_CERT_QES_DEFAULT_CA =
      readCertQes("default-CA/valid/GEM.HBA-qCA51-TEST-ONLY.pem");

  public static final X509Certificate VALID_X509_EE_CERT_QES =
      readCertQes("default-CA/valid/Apotheker-pkits-C_HP_QES_E256.pem");
  public static final X509Certificate VALID_X509_EE_CERT_QES_PSYCHO_TWO_ADMISSIONS =
      readCertQes("default-CA/valid/Psycho-pkits-C_HP_QES_E256_TwoAdmissions.pem");

  // alternative CA
  public static final X509Certificate VALID_ISSUER_CERT_QES_ALT_CA =
      readCertQes("alt-CA/valid/GEM.HBA-qCA57-TEST-ONLY.pem");
  public static final X509Certificate VALID_X509_EE_CERT_QES_ALT_CA =
      readCertQes("alt-CA/valid/Apotheker-pkits-C_HP_QES_E256_alternativeCA.pem");
  public static final X509Certificate VALID_X509_EE_CERT_QES_ALT_CA_CA_ISSUER =
      readCertQes("alt-CA/valid/Apotheker-pkits-C_HP_QES_E256_altCA_extensionAIA_CA_Issuer.pem");
  public static final X509Certificate VALID_X509_EE_CERT_QES_OCSP_SIGNER =
      readCertQes("ocsp/OcspSigner57Qes.pem");
}
