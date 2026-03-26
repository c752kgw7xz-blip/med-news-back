#!/bin/bash
# test_failing_feeds.sh
# Teste les URLs RSS candidates pour les sociétés sans feed validé.
# Colle ce script dans ton terminal et copie-colle le résultat.

BASE="https://med-news-back-fmgu.onrender.com/admin/sources/test-feed"
SECRET="mon-secret-admin"

test_feed() {
  local label="$1"
  local url="$2"
  result=$(curl -s -X POST "$BASE?url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url', safe='')")" \
    -H "x-admin-secret: $SECRET" 2>/dev/null)
  entries=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_entries',0))" 2>/dev/null)
  if [ "$entries" -gt "0" ] 2>/dev/null; then
    echo "✅ [$label] $url → $entries articles"
  else
    echo "❌ [$label] $url"
  fi
}

echo "=== SFMG ==="
test_feed "SFMG" "http://www.sfmg.org/rss/actualites_2-4-5-10-14-18.xml"
test_feed "SFMG" "http://www.sfmg.org/spip.php?page=backend"
test_feed "SFMG" "http://www.sfmg.org/?page=backend"

echo "=== Cardio-online ==="
test_feed "Cardio" "https://www.cardio-online.fr/feed/"
test_feed "Cardio" "https://www.cardio-online.fr/rss/"
test_feed "Cardio" "https://www.cardio-online.fr/?page=backend"

echo "=== SRLF ==="
test_feed "SRLF" "https://www.srlf.org/feed/"
test_feed "SRLF" "https://www.srlf.org/spip.php?page=backend"
test_feed "SRLF" "https://www.srlf.org/?page=backend"
test_feed "SRLF" "https://www.srlf.org/rss.xml"

echo "=== SFD Dermatologie ==="
test_feed "SFDermato" "https://dermato-info.fr/feed/"
test_feed "SFDermato" "https://www.sfdermato.org/spip.php?page=backend"
test_feed "SFDermato" "https://www.sfdermato.org/?page=backend"
test_feed "SFDermato" "https://www.sfdermato.org/?type=9818"

echo "=== SFO Ophtalmologie ==="
test_feed "SFO" "https://www.sfo-online.fr/?type=9818"
test_feed "SFO" "https://www.sfo-online.fr/index.php?type=9818"
test_feed "SFO" "https://www.sfo.asso.fr/feed/"
test_feed "SFO" "https://www.sfo-online.fr/spip.php?page=backend"

echo "=== SPILF Infectiologie ==="
test_feed "SPILF" "http://www.infectiologie.com/spip.php?page=backend"
test_feed "SPILF" "https://www.infectiologie.com/spip.php?page=backend"
test_feed "SPILF" "http://www.infectiologie.com/?page=backend"

echo "=== SFR Radiologie ==="
test_feed "SFR" "https://www.sfrnet.org/feed/"
test_feed "SFR" "https://www.radiologie.fr/spip.php?page=backend"
test_feed "SFR" "https://www.radiologie.fr/?type=9818"
test_feed "SFR" "https://www.radiologie.fr/rss.xml"

echo "=== SFH Hématologie ==="
test_feed "SFH" "http://sfh.hematologie.net/spip.php?page=backend"
test_feed "SFH" "https://sfh.hematologie.net/spip.php?page=backend"
test_feed "SFH" "https://sfh.hematologie.net/?page=backend"
test_feed "SFH" "https://www.hematologie.net/feed/"

echo "=== SFRO ==="
test_feed "SFRO" "https://www.sfro.fr/spip.php?page=backend"
test_feed "SFRO" "https://www.sfro.fr/?page=backend"
test_feed "SFRO" "https://www.sfro.fr/rss.xml"
test_feed "SFRO" "https://www.sfro.fr/?type=9818"

echo "=== FFCD ==="
test_feed "FFCD" "https://www.ffcd.fr/feed/"
test_feed "FFCD" "https://www.ffcd.fr/spip.php?page=backend"
test_feed "FFCD" "https://www.ffcd.fr/?page=backend"
test_feed "FFCD" "https://www.ffcd.fr/?type=9818"

echo "=== UNICANCER ==="
test_feed "UNICANCER" "https://www.unicancer.fr/feed/"
test_feed "UNICANCER" "https://www.unicancer.fr/rss/"

echo "=== SCV Chirurgie vasculaire ==="
test_feed "SCV" "https://www.sfcv.org/feed/"
test_feed "SCV" "https://www.sfcv.org/spip.php?page=backend"
test_feed "SCV" "https://www.chirurgievasculaire.fr/feed/"
test_feed "SCV" "https://www.chirurgievasculaire.fr/?page=backend"

echo "=== SOFCPRE Chirurgie plastique ==="
test_feed "SOFCPRE" "https://www.sofcpre.fr/feed/"
test_feed "SOFCPRE" "https://www.sofcpre.fr/spip.php?page=backend"
test_feed "SOFCPRE" "https://www.sfcpre.fr/feed/"

echo "=== SOFMER MPR ==="
test_feed "SOFMER" "https://www.sofmer.com/feed/"
test_feed "SOFMER" "https://sofmer.com/feed/"
test_feed "SOFMER" "https://www.sofmer.com/spip.php?page=backend"

echo "=== SFA Allergologie ==="
test_feed "SFA-allergo" "https://www.sfa-allergologie.org/feed/"
test_feed "SFA-allergo" "https://sfa-allergologie.org/feed/"
test_feed "SFA-allergo" "https://www.sfa-allergologie.org/spip.php?page=backend"

echo "=== SFMV Médecine vasculaire ==="
test_feed "SFMV" "https://www.sf-mv.fr/feed/"
test_feed "SFMV" "https://sf-mv.fr/feed/"
test_feed "SFMV" "https://www.sfmv.fr/feed/"
test_feed "SFMV" "https://www.sf-mv.fr/spip.php?page=backend"

echo "=== SFMS Médecine du sport ==="
test_feed "SFMS" "https://www.sfms.asso.fr/feed/"
test_feed "SFMS" "https://sfms.asso.fr/feed/"
test_feed "SFMS" "https://www.sfms.asso.fr/spip.php?page=backend"

echo "=== SFA Alcoologie/Addictologie ==="
test_feed "SFA-addicto" "https://www.sfalcoologie.asso.fr/feed/"
test_feed "SFA-addicto" "https://www.sfalcoologie.asso.fr/spip.php?page=backend"
test_feed "SFA-addicto" "https://www.fsfa.fr/feed/"

echo "=== SFP Pathologie ==="
test_feed "SFPath" "https://www.sfpathol.org/feed/"
test_feed "SFPath" "https://sfpathol.org/feed/"
test_feed "SFPath" "https://www.sfpathol.org/spip.php?page=backend"

echo "=== SFMN Médecine nucléaire ==="
test_feed "SFMN" "https://www.sfmn.org/feed/"
test_feed "SFMN" "https://sfmn.org/feed/"
test_feed "SFMN" "https://www.sfmn.org/spip.php?page=backend"
test_feed "SFMN" "https://www.sfmn.org/?type=9818"

echo "=== FNCGM Gynécologie médicale ==="
test_feed "FNCGM" "https://www.gynecologie-medicale.com/feed/"
test_feed "FNCGM" "https://gynecologie-medicale.com/feed/"
test_feed "FNCGM" "https://www.gynecologie-medicale.com/spip.php?page=backend"

echo "=== SFSCMF Maxillo-faciale ==="
test_feed "SFSCMF" "https://www.sfscmf.fr/feed/"
test_feed "SFSCMF" "https://sfscmf.fr/feed/"
test_feed "SFSCMF" "https://www.sfscmf.fr/spip.php?page=backend"

echo "=== SFMU Médecine d'urgence ==="
test_feed "SFMU" "https://www.sfmu.org/fr/actualites/feed/"
test_feed "SFMU" "https://www.sfmu.org/spip.php?page=backend"
test_feed "SFMU" "https://www.sfmu.org/?page=backend"
test_feed "SFMU" "https://www.sfmu.org/fr/?page=backend"

echo "=== SFP Pédiatrie ==="
test_feed "SFPed" "https://www.sfpediatrie.com/spip.php?page=backend"
test_feed "SFPed" "https://www.sfpediatrie.com/?page=backend"
test_feed "SFPed" "https://sfpediatrie.com/feed/"

echo "=== SFNN Néonatologie ==="
test_feed "SFNN" "https://www.sfnn.fr/feed/"
test_feed "SFNN" "https://sfnn.fr/feed/"
test_feed "SFNN" "https://www.sfnn.fr/spip.php?page=backend"

echo "=== SFSP Santé publique ==="
test_feed "SFSP" "https://www.sfsp.fr/feed/"
test_feed "SFSP" "https://sfsp.fr/feed/"
test_feed "SFSP" "https://www.sfsp.fr/spip.php?page=backend"

echo ""
echo "=== DONE ==="
