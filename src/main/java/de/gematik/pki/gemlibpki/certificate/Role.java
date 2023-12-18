/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.certificate;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/** Enum that host {@link Role} information. */
@RequiredArgsConstructor
@Getter
public enum Role {
  // GS-A_4442-02 - OID-Festlegung Rolle für Berufsgruppen
  OID_ARZT("Ärztin/Arzt", "1.2.276.0.76.4.30"),
  OID_ZAHNARZT("Zahnärztin/Zahnarzt", "1.2.276.0.76.4.31"),
  OID_APOTHEKER("Apotheker/-in", "1.2.276.0.76.4.32"),
  OID_APOTHEKERASSISTENT("Apothekerassistent/-in", "1.2.276.0.76.4.33"),
  OID_PHARMAZIEINGENIEUR("Pharmazieingenieur/-in", "1.2.276.0.76.4.34"),
  OID_PHARM_TECHN_ASSISTENT("pharmazeutisch-technische/-r Assistent/-in", "1.2.276.0.76.4.35"),
  OID_PHARM_KAUFM_ANGESTELLTER("pharmazeutisch-kaufmännische/-r Angestellte", "1.2.276.0.76.4.36"),
  OID_APOTHEKENHELFER("Apothekenhelfer/-in", "1.2.276.0.76.4.37"),
  OID_APOTHEKENASSISTENT("Apothekenassistent/-in", "1.2.276.0.76.4.38"),
  OID_PHARM_ASSISTENT("Pharmazeutische/-r Assistent/-in", "1.2.276.0.76.4.39"),
  OID_APOTHEKENFACHARBEITER("Apothekenfacharbeiter/-in", "1.2.276.0.76.4.40"),
  OID_PHARMAZIEPRAKTIKANT("Pharmaziepraktikant/-in", "1.2.276.0.76.4.41"),
  OID_FAMULANT("Stud.pharm. oder Famulant/-in", "1.2.276.0.76.4.42"),
  OID_PTA_PRAKTIKANT("PTA-Praktikant/-in", "1.2.276.0.76.4.43"),
  OID_PKA_AUSZUBILDENDER("PKA Auszubildende/-r", "1.2.276.0.76.4.44"),
  OID_PSYCHOTHERAPEUT("Psychotherapeut/-in", "1.2.276.0.76.4.45"),
  OID_PS_PSYCHOTHERAPEUT("Psychologische/-r Psychotherapeut/-in", "1.2.276.0.76.4.46"),
  OID_KUJ_PSYCHOTHERAPEUT("Kinder- und Jugendlichenpsychotherapeut/-in", "1.2.276.0.76.4.47"),
  OID_RETTUNGSASSISTENT("Rettungsassistent/-in", "1.2.276.0.76.4.48"),
  OID_VERSICHERTER("Versicherte/-r", "1.2.276.0.76.4.49"),
  OID_NOTFALLSANITAETER("Notfallsanitäter/-in", "1.2.276.0.76.4.178"),
  OID_PFLEGER_HPC(
      "Gesundheits- und Krankenpfleger/-in, Gesundheits- und Kinderkrankenpfleger/-in",
      "1.2.276.0.76.4.232"),
  OID_ALTENPFLEGER_HPC("Altenpfleger/-in", "1.2.276.0.76.4.233"),
  OID_PFLEGEFACHKRAFT_HPC("Pflegefachfrauen und Pflegefachmänner", "1.2.276.0.76.4.234"),
  OID_HEBAMME_HPC("Hebamme ", "1.2.276.0.76.4.235"),
  OID_PHYSIOTHERAPEUT_HPC("Physiotherapeut/-in ", "1.2.276.0.76.4.236"),
  OID_AUGENOPTIKER_HPC("Augenoptiker/-in und Optometrist/-in ", "1.2.276.0.76.4.237"),
  OID_HOERAKUSTIKER_HPC("Hörakustiker/-in", "1.2.276.0.76.4.238"),
  OID_ORTHOPAEDIESCHUHMACHER_HPC("Orthopädieschuhmacher/-in ", "1.2.276.0.76.4.239"),
  OID_ORTHOPAEDIETECHNIKER_HPC("Orthopädietechniker/-in ", "1.2.276.0.76.4.240"),
  OID_ZAHNTECHNIKER_HPC("Zahntechniker/-in ", "1.2.276.0.76.4.241"),
  OID_ERGOTHERAPEUT_HPC("Ergotherapeut/-in", "1.2.276.0.76.4.274"),
  OID_LOGOPAEDE_HPC("Logopäde/Logopädin", "1.2.276.0.76.4.275"),
  OID_PODOLOGE_HPC("Podologe/Podologin", "1.2.276.0.76.4.276"),
  OID_ERNAEHRUNGSTHERAPEUT_HPC("Ernährungstherapeut/-in", "1.2.276.0.76.4.27"),

  // GS-A_4443-07 - OID-Festlegung für Institutionen
  OID_PRAXIS_ARZT("Betriebsstätte Arzt", "1.2.276.0.76.4.50"),
  OID_ZAHNARZTPRAXIS("Zahnarztpraxis", "1.2.276.0.76.4.51"),
  OID_PRAXIS_PSYCHOTHERAPEUT("Betriebsstätte Psychotherapeut", "1.2.276.0.76.4.52"),
  OID_KRANKENHAUS("Krankenhaus", "1.2.276.0.76.4.53"),
  OID_OEFFENTLICHE_APOTHEKE("Öffentliche Apotheke", "1.2.276.0.76.4.54"),
  OID_KRANKENHAUSAPOTHEKE("Krankenhausapotheke", "1.2.276.0.76.4.55"),
  OID_BUNDESWEHRAPOTHEKE("Bundeswehrapotheke", "1.2.276.0.76.4.56"),
  OID_MOBILE_EINRICHTUNG_RETTUNGSDIENST(
      "Betriebsstätte Mobile Einrichtung Rettungsdienst", "1.2.276.0.76.4.57"),
  OID_BS_GEMATIK("Betriebsstätte gematik", "1.2.276.0.76.4.58"),
  OID_KOSTENTRAEGER("Betriebsstätte Kostenträger", "1.2.276.0.76.4.59"),
  OID_LEO_ZAHNAERZTE(
      "Betriebsstätte Leistungserbringerorganisation Vertragszahnärzte", "1.2.276.0.76.4.187"),
  OID_ADV_KTR("AdV-Umgebung bei Kostenträger", "1.2.276.0.76.4.190"),
  OID_LEO_KASSENAERZTLICHE_VEREINIGUNG(
      "Betriebsstätte Leistungserbringerorganisation Kassenärztliche Vereinigung",
      "1.2.276.0.76.4.210"),
  OID_BS_GKV_SPITZENVERBAND("Betriebsstätte GKV-Spitzenverband", "1.2.276.0.76.4.223"),
  OID_LEO_KRANKENHAUSVERBAND(
      "Betriebsstätte Mitgliedsverband der Krankenhäuser", "1.2.276.0.76.4.226"),
  OID_LEO_DKTIG(
      "Betriebsstätte der Deutsche Krankenhaus TrustCenter und Informationsverarbeitung GmbH",
      "1.2.276.0.76.4.227"),
  OID_LEO_DKG("Betriebsstätte der Deutschen Krankenhausgesellschaft", "1.2.276.0.76.4.228"),
  OID_LEO_APOTHEKERVERBAND("Betriebsstätte Apothekerverband", "1.2.276.0.76.4.224"),
  OID_LEO_DAV("Betriebsstätte Deutscher Apothekerverband", "1.2.276.0.76.4.225"),
  OID_LEO_BAEK("Betriebsstätte der Bundesärztekammer", "1.2.276.0.76.4.229"),
  OID_LEO_AERZTEKAMMER("Betriebsstätte einer Ärztekammer", "1.2.276.0.76.4.230"),
  OID_LEO_ZAHNAERZTEKAMMER("Betriebsstätte einer Zahnärztekammer", "1.2.276.0.76.4.231"),
  OID_LEO_KBV("Betriebsstätte der Kassenärztlichen Bundesvereinigung", "1.2.276.0.76.4.242"),
  OID_LEO_BZAEK("Betriebsstätte der Bundeszahnärztekammer", "1.2.276.0.76.4.243"),
  OID_LEO_KZBV("Betriebsstätte der Kassenzahnärztlichen Bundesvereinigung", "1.2.276.0.76.4.244"),
  OID_INSTITUTION_PFLEGE(
      "Betriebsstätte Gesundheits-, Kranken- und Altenpflege", "1.2.276.0.76.4.245"),
  OID_INSTITUTION_GEBURTSHILFE("Betriebsstätte Geburtshilfe", "1.2.276.0.76.4.246"),
  OID_PRAXIS_PHYSIOTHERAPEUT("Betriebsstätte Physiotherapie", "1.2.276.0.76.4.247"),
  OID_INSTITUTION_AUGENOPTIKER("Betriebsstätte Augenoptiker", "1.2.276.0.76.4.248"),
  OID_INSTITUTION_HOERAKUSTIKER("Betriebsstätte Hörakustiker", "1.2.276.0.76.4.249"),
  OID_INSTITUTION_ORTHOPAEDIESCHUHMACHER(
      "Betriebsstätte Orthopädieschuhmacher", "1.2.276.0.76.4.250"),
  OID_INSTITUTION_ORTHOPAEDIETECHNIKER("Betriebsstätte Orthopädietechniker", "1.2.276.0.76.4.251"),
  OID_INSTITUTION_ZAHNTECHNIKER("Betriebsstätte Zahntechniker", "1.2.276.0.76.4.252"),
  OID_INSTITUTION_RETTUNGSLEITSTELLEN("Rettungsleitstelle", "1.2.276.0.76.4.253"),
  OID_SANITAETSDIENST_BUNDESWEHR("Betriebsstätte Sanitätsdienst Bundeswehr", "1.2.276.0.76.4.254"),
  OID_INSTITUTION_OEGD("Betriebsstätte Öffentlicher Gesundheitsdienst", "1.2.276.0.76.4.255"),
  OID_INSTITUTION_ARBEITSMEDIZIN("Betriebsstätte Arbeitsmedizin", "1.2.276.0.76.4.256"),
  OID_INSTITUTION_VORSORGE_REHA(
      "Betriebsstätte Vorsorge- und Rehabilitation", "1.2.276.0.76.4.257"),
  OID_EPA_KTR("ePA KTR-Zugriffsautorisierung", "1.2.276.0.76.4.273"),
  OID_PFLEGEBERATUNG("Betriebsstätte Pflegeberatung nach § 7a SGB XI", "1.2.276.0.76.4.262"),
  OID_LEO_PSYCHOTHERAPEUTEN("Betriebsstätte Psychotherapeutenkammer", "1.2.276.0.76.4.263"),
  OID_LEO_BPTK("Betriebsstätte Bundespsychotherapeutenkammer", "1.2.276.0.76.4.264"),
  OID_LEO_LAK("Betriebsstätte Landesapothekerkammer", "1.2.276.0.76.4.265"),
  OID_LEO_BAK("Betriebsstätte Bundesapothekerkammer", "1.2.276.0.76.4.266"),
  OID_LEO_EGBR("Betriebsstätte elektronisches Gesundheitsberuferegister", "1.2.276.0.76.4.267"),
  OID_LEO_HANDWERKSKAMMER("Betriebsstätte Handwerkskammer", "1.2.276.0.76.4.268"),
  OID_GESUNDHEITSDATENREGISTER(
      "Betriebsstätte Register für Gesundheitsdaten", "1.2.276.0.76.4.269"),
  OID_ABRECHNUNGSDIENSTLEISTER("Betriebsstätte Abrechnungsdienstleister", "1.2.276.0.76.4.270"),
  OID_PKV_VERBAND("Betriebsstätte PKV-Verband", "1.2.276.0.76.4.271"),
  OID_PRAXIS_ERGOTHERAPEUT("Ergotherapiepraxis", "1.2.276.0.76.4.278"),
  OID_PRAXIS_LOGOPAEDE("Logopaedische Praxis", "1.2.276.0.76.4.279"),
  OID_PRAXIS_PODOLOGE("Podologiepraxis", "1.2.276.0.76.4.280"),
  OID_PRAXIS_ERNAEHRUNGSTHERAPEUT("Ernährungstherapeutische Praxis", "1.2.276.0.76.4.281"),
  OID_BS_WEITERE_KOSTENTRAEGER(
      "Betriebsstätte Weitere Kostenträger im Gesundheitswesen", "1.2.276.0.76.4.284"),
  OID_ORG_GESUNDHEITSVERSORGUNG(
      "Weitere Organisationen der Gesundheitsversorgung", "1.2.276.0.76.4.285"),
  OID_KIM_ANBIETER("KIM-Hersteller und -Anbieter", "1.2.276.0.76.4.286"),
  OID_DIGA("DiGA-Hersteller und -Anbieter", "1.2.276.0.76.4.282"),
  OID_TIM_ANBIETER("TIM-Hersteller und -Anbieter", "1.2.276.0.76.4.295"),
  OID_NCPEH("NCPeH Fachdienst", "1.2.276.0.76.4.292"),

  // GS-A_4446-10 - OID-Festlegung für technische Rollen
  OID_VSDD("Versichertenstammdatendienst", "1.2.276.0.76.4.97"),
  OID_OCSP("Online Certificate Status Protocol", "1.2.276.0.76.4.99"),
  OID_CMS("Card Management System", "1.2.276.0.76.4.100"),
  OID_UFS("Update Flag Service", "1.2.276.0.76.4.101"),
  OID_AK("Anwendungskonnektor", "1.2.276.0.76.4.103"),
  OID_NK("Netzkonnektor", "1.2.276.0.76.4.104"),
  OID_KT("Kartenterminal", "1.2.276.0.76.4.105"),
  OID_SAK("Signaturanwendungs-komponente", "1.2.276.0.76.4.119"),
  OID_INT_VSDM("Intermediär VSDM", "1.2.276.0.76.4.159"),
  OID_KONFIGDIENST("Konfigurationsdienst", "1.2.276.0.76.4.160"),
  OID_VPNZ_TI("VPN-Zugangsdienst-TI", "1.2.276.0.76.4.161"),
  OID_VPNZ_SIS("VPN-Zugangsdienst-SIS", "1.2.276.0.76.4.166"),
  OID_CMFD("Clientmodul", "1.2.276.0.76.4.174"),
  OID_VZD_TI("Verzeichnisdienst-TI", "1.2.276.0.76.4.171"),
  OID_KOMLE("KOM-LE Fachdienst", "1.2.276.0.76.4.172"),
  OID_KOMLE_RECIPIENT_EMAILS("KOM-LE S/MIME Attribut recipient-emails", "1.2.276.0.76.4.173"),
  OID_STAMP("Störungsampel", "1.2.276.0.76.4.184"),
  OID_TSL_TI("TSL-Dienst-TI", "1.2.276.0.76.4.189"),
  OID_WADG(
      "Weitere elektronische Anwendungen des Gesundheitswesens sowie für die Gesundheitsforschung"
          + " n. P. 291a Abs. 7 Satz 3 SGB V",
      "1.2.276.0.76.4.198"),
  OID_EPA_AUTHN("ePA Authentisierung", "1.2.276.0.76.4.204"),
  OID_EPA_AUTHZ("ePA Autorisierung", "1.2.276.0.76.4.205"),
  OID_EPA_DVW("ePA Dokumentenverwaltung", "1.2.276.0.76.4.206"),
  OID_EPA_MGMT("ePA Management", "1.2.276.0.76.4.207"),
  OID_EPA_RECOVERY("ePA automatisierter Berechtigungserhalt", "1.2.276.0.76.4.208"),
  OID_EPA_VAU("ePA vertrauenswürdige Ausführungsumgebung", "1.2.276.0.76.4.209"),
  OID_VZ_TSP("Zertifikatsverzeichnis TSP X.509", "1.2.276.0.76.4.215"),
  OID_WHK1_HSM("HSM Wiederherstellungskomponente 1", "1.2.276.0.76.4.216"),
  OID_WHK2_HSM("HSM Wiederherstellungskomponente 2", "1.2.276.0.76.4.217"),
  OID_WHK("Wiederherstellungskomponente", "1.2.276.0.76.4.218"),
  OID_SGD1_HSM("HSM Schlüsselgenerierungsdienst 1", "1.2.276.0.76.4.219"),
  OID_SGD2_HSM("HSM Schlüsselgenerierungsdienst 2", "1.2.276.0.76.4.220"),
  OID_SGD("Schlüsselgenerierungsdienst", "1.2.276.0.76.4.221"),
  OID_ERP_VAU("E-Rezept vertrauenswürdige Ausführungsumgebung", "1.2.276.0.76.4.258"),
  OID_EREZEPT("E-Rezept", "1.2.276.0.76.4.259"),
  OID_IDPD("IDP-Dienst", "1.2.276.0.76.4.260"),
  OID_EPA_LOGGING("ePA-Aktensystem-Logging", "1.2.276.0.76.4.261"),
  OID_BESTANDSNETZE("Bestandsnetze.xml Signatur", "1.2.276.0.76.4.288"),
  OID_EPA_VST("ePA Vertrauensstelle", "1.2.276.0.76.4.289"),
  OID_EPA_FDZ("ePA Forschungsdatenzentrum", "1.2.276.0.76.4.290"),
  OID_TIM("TI-Messenger", "1.2.276.0.76.4.294"),
  OID_HSK("Highspeed-Konnektor", "1.2.276.0.76.4.302"),

  // misc
  ROLE_NONE("", "");

  private final String professionItem;
  private final String professionOid;
}
