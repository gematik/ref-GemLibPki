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

package de.gematik.pki.gemlibpki.error;

import static de.gematik.pki.gemlibpki.error.ErrorClassifier.SECURITY_ERROR;
import static de.gematik.pki.gemlibpki.error.ErrorClassifier.SECURITY_WARNING;
import static de.gematik.pki.gemlibpki.error.ErrorClassifier.TECHNICAL_ERROR;
import static de.gematik.pki.gemlibpki.error.ErrorClassifier.TECHNICAL_WARNING;
import static de.gematik.pki.gemlibpki.error.ErrorSeverity.SEVERITY_ERROR;
import static de.gematik.pki.gemlibpki.error.ErrorSeverity.SEVERITY_WARNING;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Enum that host {@link ErrorCode} information. refer to document "Übergreifende Spezifikation PKI"
 * [gemSpec_PKI]
 *
 * @see <a
 *     href="https://fachportal.gematik.de/downloadcenter/releases">fachportal.gematik.de/downloadcenter/releases</a>
 */
@RequiredArgsConstructor
@Getter
public enum ErrorCode {
  TE_1001_TSL_INIT_ERROR(
      SEVERITY_ERROR, TECHNICAL_ERROR, "TSL_INIT_ERROR", "Es liegt keine gültige TSL vor"),
  TE_1002_TSL_CERT_EXTRACTION_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "TSL_CERT_EXTRACTION_ERROR",
      "Zertifikate lassen sich nicht extrahieren"),
  SE_1003_MULTIPLE_TRUST_ANCHOR(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "MULTIPLE_TRUST_ANCHOR",
      "Mehr als ein markierter V-Anker gefunden"),
  TE_1004_TSL_SIG_CERT_EXTRACTION_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "TSL_SIG_CERT_EXTRACTION_ERROR",
      "TSL-Signer-CA lässt sich nicht extrahieren"),
  TE_1005_TSL_DOWNLOAD_ADDRESS_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "TSL_DOWNLOAD_ADDRESS_ERROR",
      "Element „PointersTo OtherTSL“ nicht vorhanden"),
  TE_1006_TSL_DOWNLOAD_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "TSL_DOWNLOAD_ERROR",
      "TSL-Download-adressen wiederholt nicht erreichbar"),
  SE_1007_TSL_ID_INCORRECT(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "TSL_ID_INCORRECT",
      "Vergleich der ID und Sequence-Number entspricht nicht der Vergleichsvariante 6a"),
  SW_1008_VALIDITY_WARNING_1(
      SEVERITY_WARNING, SECURITY_WARNING, "VALIDITY_WARNING_1", "Die TSL ist nicht mehr aktuell"),
  SW_1009_VALIDITY_WARNING_2(
      SEVERITY_WARNING,
      SECURITY_WARNING,
      "VALIDITY_WARNING_2",
      "Überschreitung des Elements NextUpdate um TSL-Grace-Period"),
  TE_1011_TSL_NOT_WELLFORMED(
      SEVERITY_ERROR, TECHNICAL_ERROR, "TSL_NOT_WELLFORMED", "TSL-Datei nicht wellformed"),
  TE_1012_TSL_SCHEMA_NOT_VALID(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "TSL_SCHEMA_NOT_VALID",
      "Schemata der TSL-Datei nicht korrekt"),
  SE_1013_XML_SIGNATURE_ERROR(
      SEVERITY_ERROR, SECURITY_ERROR, "XML_SIGNATURE_ERROR", "Signatur ist nicht gültig"),
  SE_1016_WRONG_KEYUSAGE(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "WRONG_KEYUSAGE",
      "KeyUsage ist nicht vorhanden bzw. entspricht nicht der vorgesehenen KeyUsage"),
  SE_1017_WRONG_EXTENDEDKEYUSAGE(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "WRONG_EXTENDEDKEYUSAGE",
      "Extended-KeyUsage entspricht nicht der vorgesehenen Extended-KeyUsage"),
  SE_1018_CERT_TYPE_MISMATCH(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CERT_TYPE_MISMATCH",
      "Zertifikatstyp-OID stimmt nicht überein"),
  TE_1019_CERT_READ_ERROR(
      SEVERITY_ERROR, TECHNICAL_ERROR, "CERT_READ_ERROR", "Zertifikat nicht lesbar"),
  SE_1021_CERTIFICATE_NOT_VALID_TIME(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CERTIFICATE_NOT_VALID_TIME",
      "Zertifikat ist zeitlich nicht gültig"),
  SE_1023_AUTHORITYKEYID_DIFFERENT(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "AUTHORITYKEYID_DIFFERENT",
      "Authority-Key-Identifier des End-Entity-Zertifikats von Subject-Key-Identifier des"
          + " CA-Zertifikats unterschiedlich"),
  SE_1024_CERTIFICATE_NOT_VALID_MATH(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CERTIFICATE_NOT_VALID_MATH",
      "Zertifikats-Signatur ist mathematisch nicht gültig"),
  TE_1026_SERVICESUPPLYPOINT_MISSING(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "SERVICESUPPLYPOINT_MISSING",
      "Das Element „Service-Supply Point“ konnte nicht gefunden werden"),
  TE_1027_CA_CERT_MISSING(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "CA_CERT_MISSING",
      "CA kann nicht in den TSL-Informationen ermittelt werden"),
  TW_1028_OCSP_CHECK_REVOCATION_FAILED(
      SEVERITY_WARNING,
      TECHNICAL_WARNING,
      "OCSP_CHECK_REVOCATION_FAILED",
      "Die OCSP-Prüfung konnte nicht durchgeführt werden (1)"),
  TE_1029_OCSP_CHECK_REVOCATION_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "OCSP_CHECK_REVOCATION_ERROR",
      "Die OCSP-Prüfung konnte nicht durchgeführt werden (2)"),
  SE_1030_OCSP_CERT_MISSING(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "OCSP_CERT_MISSING",
      "OCSP-Zertifikat nicht in TSL-Informationen enthalten"),
  SE_1031_OCSP_SIGNATURE_ERROR(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "OCSP_SIGNATURE_ERROR",
      "Signatur der Response ist nicht gültig"),
  TE_1032_OCSP_NOT_AVAILABLE(
      SEVERITY_ERROR, TECHNICAL_ERROR, "OCSP_NOT_AVAILABLE", "OCSP-Responder nicht verfügbar"),
  SE_1033_CERT_TYPE_INFO_MISSING(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CERT_TYPE_INFO_MISSING",
      "Kein Element PolicyIdentifier vorhanden"),
  SE_1036_CA_CERTIFICATE_REVOKED_IN_TSL(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CA_CERTIFICATE_REVOKED_IN_TSL",
      "Das Zertifikat ist ungültig. Es wurde nach der Sperrung der ausgebenden CA ausgestellt"),
  SW_1039_NO_OCSP_CHECK(
      SEVERITY_WARNING,
      SECURITY_WARNING,
      "NO_OCSP_CHECK",
      "Warnung, dass Offline-Modus aktiviert ist und keine OCSP-Statusabfrage durchgeführt wurde"),
  SE_1040_CERTHASH_EXTENSION_MISSING(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CERTHASH_EXTENSION_MISSING",
      "Bei der Onlinestatusprüfung ist ENFORCE_CERTHASH_CHECK auf ´true´ gesetzt, die OCSP-Response"
          + " enthält jedoch keine certHash-Erweiterung"),
  SE_1041_CERTHASH_MISMATCH(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CERTHASH_MISMATCH",
      "Der certHash in der OCSP-Response stimmt nicht mit dem certHash des vorliegenden Zertifikats"
          + " überein"),
  TE_1042_TSL_CA_NOT_LOADED(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "TSL_CA_NOT_LOADED",
      "Das TSL-SignerCA-Zertifikat kann nicht aus dem sicheren Speicher des Systems geladen"
          + " werden"),
  TE_1043_CRL_CHECK_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "CRL_CHECK_ERROR",
      "CRL kann aus technischen Gründen nicht ausgewertet werden"),
  TW_1044_CERT_UNKNOWN(
      SEVERITY_WARNING,
      TECHNICAL_WARNING,
      "CERT_UNKNOWN",
      "Warnung, dass zum angefragten Zertifikat keine Statusinformationen verfügbar sind"),
  SW_1047_CERT_REVOKED(
      SEVERITY_WARNING,
      SECURITY_WARNING,
      "CERT_REVOKED",
      "Das Zertifikat wurde vor oder zum Referenzzeitpunkt widerrufen"),
  TE_1048_QC_STATEMENT_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "QC_STATEMENT_ERROR",
      "Es ist ein Fehler bei der Prüfung des QC-Statements aufgetreten (z.B. nicht vorhanden,"
          + " obwohl gefordert)"),
  TW_1050_PROVIDED_OCSP_RESPONSE_NOT_VALID(
      SEVERITY_WARNING,
      TECHNICAL_WARNING,
      "PROVIDED_OCSP_RESPONSE_NOT_VALID",
      "Die einem TUC zur Zertifikatsprüfung beigefügte OCSP-Response zu dem zu prüfenden Zertifikat"
          + " kann nicht erfolgreich gegen das Zertifikat validiert werden"),
  SE_1051_OCSP_NONCE_MISMATCH(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "OCSP_NONCE_MISMATCH",
      "Die in einem OCSP-Response zurückgelieferte Nonce stimmt nicht mit der Nonce des"
          + " OCSP-Requests überein"),
  SE_1052_ATTR_CERT_MISMATCH(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "ATTR_CERT_MISMATCH",
      "Attribut-Zertifikat kann dem übergebenen Basis-Zertifikat nicht zugeordnet werden"),
  TE_1053_CRL_DOWNLOAD_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "CRL_DOWNLOAD_ERROR",
      "Die CRL kann nicht heruntergeladen werden"),
  TE_1054_CRL_OUTDATED_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "CRL_OUTDATED_ERROR",
      "Eine verwendete CRL ist zum aktuellen Zeitpunkt nicht mehr gültig"),
  SE_1055_CRL_SIGNER_CERT_MISSING(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CRL_SIGNER_CERT_MISSING",
      "CRL-Signer-Zertifikat nicht in TSL-Informationen enthalten"),
  SE_1057_CRL_SIGNATURE_ERROR(
      SEVERITY_ERROR, SECURITY_ERROR, "CRL_SIGNATURE_ERROR", "Signatur der CRL ist nicht gültig"),
  TE_1058_OCSP_STATUS_ERROR(
      SEVERITY_ERROR,
      TECHNICAL_ERROR,
      "OCSP_STATUS_ERROR",
      "Die OCSP-Response enthält eine Exception-Meldung"),
  SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CA_CERTIFICATE_NOT_QES_QUALIFIED",
      "CA-Zertifikat für QES-Zertifikatsprüfung nicht qualifiziert"),
  TE_1060_VL_UPDATE_ERROR(
      SEVERITY_ERROR, TECHNICAL_ERROR, "VL_UPDATE_ERROR", "Die VL kann nicht aktualisiert werden"),
  SE_1061_CERT_TYPE_CA_NOT_AUTHORIZED(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CERT_TYPE_CA_NOT_AUTHORIZED",
      "CA (laut TSL) nicht autorisiert für die Herausgabe dieses Zertifikatstyps"),
  SE_1062_CA_CERTIFICATE_REVOKED_IN_BNETZA_VL(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CA_CERTIFICATE_REVOKED_IN_BNETZA_VL",
      "Das QES-EE-Zertifikat ist ungültig. Es wurde nach der Sperrung der ausgebenden QES-CA"
          + " ausgestellt"),

  CUSTOM_CERTIFICATE_EXCEPTION(
      SEVERITY_ERROR,
      SECURITY_ERROR,
      "CUSTOM_CERTIFICATE_EXCEPTION",
      "Custom certificate exception");

  private final ErrorSeverity errorSeverity;
  private final ErrorClassifier errorClassifier;
  private final String errorTextShort;
  private final String errorTextDesc;

  /**
   * Generates a gemSpec_PKI-conform error message
   *
   * @param productType type of the product
   * @return error message
   */
  public String getErrorMessage(@NonNull final String productType) {
    return "\n%s:PKI - %s %s - %s %s"
        .formatted(
            productType,
            getErrorClassifier().name(),
            name(),
            getErrorTextShort(),
            getErrorTextDesc());
  }
}
