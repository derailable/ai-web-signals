#!/usr/bin/env bash
set -euo pipefail

DOWNLOAD_URL="${TRANCO_DOWNLOAD_URL:-https://tranco-list.eu/top-1m.csv.zip}"
ID_URL="${TRANCO_ID_URL:-https://tranco-list.eu/top-1m-id}"
SOURCE_FILE="${TRANCO_SOURCE_FILE:-data/input/top-1m.csv}"
PREPARED_FILE="${TRANCO_PREPARED_FILE:-data/input/tranco-top-100000.csv}"
METADATA_FILE="${TRANCO_METADATA_FILE:-data/input/tranco-metadata.json}"
LIMIT="${TRANCO_LIMIT:-100000}"

[ "$#" -eq 0 ] || {
  printf 'fetch_tranco.sh accepts no arguments; run ./scripts/fetch_tranco.sh\n' >&2
  exit 2
}

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/tranco-fetch.XXXXXX")
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

zip_path="$tmp_dir/top-1m.csv.zip"
extracted_path="$tmp_dir/top-1m.csv"

mkdir -p "$(dirname "$SOURCE_FILE")" "$(dirname "$PREPARED_FILE")" "$(dirname "$METADATA_FILE")"

list_id=$(curl -fsSL "$ID_URL" | awk 'NR == 1 { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }')
curl -fsSL "$DOWNLOAD_URL" -o "$zip_path"
unzip -p "$zip_path" top-1m.csv > "$extracted_path"
mv "$extracted_path" "$SOURCE_FILE"

{
  printf 'rank,domain\n'
  awk -F, -v limit="$LIMIT" '
    NR == 1 && $1 == "rank" && $2 == "domain" { next }
    count < limit {
      count += 1
      gsub(/\r$/, "", $2)
      print $1 "," $2
    }
  ' "$SOURCE_FILE"
} > "$PREPARED_FILE"

source_count=$(awk -F, '
  NR == 1 && $1 == "rank" && $2 == "domain" { next }
  NF >= 1 { count += 1 }
  END { print count + 0 }
' "$SOURCE_FILE")

retrieved_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
generated_on="null"
if [ "${TRANCO_GENERATED_ON:-}" != "" ]; then
  generated_on="\"${TRANCO_GENERATED_ON}\""
elif [ "$list_id" = "PYGVJ" ]; then
  generated_on='"2026-07-29"'
fi

cat > "$METADATA_FILE" <<EOF
{
  "source": "Tranco",
  "list_type": "standard",
  "subdomains": false,
  "list_id": "$list_id",
  "list_url": "https://tranco-list.eu/list/$list_id",
  "download_url": "$DOWNLOAD_URL",
  "generated_on": $generated_on,
  "retrieved_at": "$retrieved_at",
  "source_domain_count": $source_count,
  "selected_domain_count": $LIMIT,
  "source_file": "$SOURCE_FILE",
  "prepared_file": "$PREPARED_FILE"
}
EOF

printf 'Prepared %s rows from Tranco list %s into %s\n' "$LIMIT" "$list_id" "$PREPARED_FILE"
