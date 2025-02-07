#!/bin/bash
set -e
set -x

mvn org.codehaus.mojo:license-maven-plugin:2.5.0:aggregate-third-party-report -ntp

if [[ ! -f target/reports/aggregate-third-party-report.html ]]; then
    echo "❌ Fehler: Die Datei fehlt!"
    exit 1
fi

COMPATIBLE_LICENSES=(
    "GNU\\s+Lesser\\s+General\\s+Public\\s+License"
    "With\\s+Classpath\\s+Exception"
    "Apache\\s+License"
    "Apache-2.0"
    "GPL2\\s+w/\\s+CPE"
    "GPL-2.0-with-classpath-exception"
    "GPLv2\\+CE"
    "CDDL\\+GPL"
)

# create Regex
IFS="|"
COMPATIBLE_REGEX="${COMPATIBLE_LICENSES[*]}"
unset IFS

PROBLEMATIC_LICENSES=$(grep -iE "GPL|AGPL|SSPL|proprietary" target/reports/aggregate-third-party-report.html | grep -viE "$COMPATIBLE_REGEX" || true)

if [[ -n "$PROBLEMATIC_LICENSES" ]]; then
    echo "❌ Nicht kompatible Lizenzen gefunden:"
    echo "PROBLEMATIC_LICENSES: $PROBLEMATIC_LICENSES"
    exit 1
else
    echo "✅ Alle verwendeten Lizenzen sind kompatibel."
fi
