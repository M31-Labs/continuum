#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-dev}"
dist_dir="${DIST_DIR:-dist}"
artifact="audit-schema-docs-${version}"
work_dir="${dist_dir}/${artifact}"
archive="${dist_dir}/${artifact}.tar.gz"
checksum="${dist_dir}/${artifact}.sha256"

rm -rf "${work_dir}" "${archive}" "${checksum}"
mkdir -p "${work_dir}"

cp docs/audit-schema.md "${work_dir}/README.md"
cp docs/audit-schema.json "${work_dir}/audit-schema.json"

cat > "${work_dir}/MANIFEST.txt" <<EOF
name: audit-schema-docs
version: ${version}
schema: audit-schema.json
docs: README.md
checksum: ${artifact}.sha256
signature-bundle: ${artifact}.sha256.sigstore.json
EOF

tar -C "${dist_dir}" -czf "${archive}" "${artifact}"

(
	cd "${dist_dir}"
	sha256sum "${artifact}.tar.gz" > "${artifact}.sha256"
)

printf '%s\n' "${archive}"
printf '%s\n' "${checksum}"
