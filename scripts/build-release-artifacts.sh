#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-dev}"
dist_dir="${DIST_DIR:-dist}"
commit="${COMMIT:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
build_date="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
checksum_file="${dist_dir}/continuum-${version}-checksums.txt"
targets=(
	"linux/amd64"
	"linux/arm64"
	"darwin/amd64"
	"darwin/arm64"
)

mkdir -p "${dist_dir}"
rm -f "${checksum_file}"

ldflags="-s -w -X main.version=${version} -X main.commit=${commit} -X main.buildDate=${build_date}"

for target in "${targets[@]}"; do
	os="${target%/*}"
	arch="${target#*/}"
	artifact="continuum-${version}-${os}-${arch}"
	work_dir="${dist_dir}/${artifact}"
	archive="${dist_dir}/${artifact}.tar.gz"

	rm -rf "${work_dir}" "${archive}"
	mkdir -p "${work_dir}"

	CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build -trimpath -ldflags "${ldflags}" -o "${work_dir}/continuum" ./cmd/continuum
	CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build -trimpath -ldflags "${ldflags}" -o "${work_dir}/continuum-agent" ./cmd/continuum-agent

	cp README.md LICENSE "${work_dir}/"
	cat > "${work_dir}/MANIFEST.txt" <<EOF
name: continuum
version: ${version}
commit: ${commit}
build_date: ${build_date}
target_os: ${os}
target_arch: ${arch}
binaries:
  - continuum
  - continuum-agent
status: observe-mode pilot; no kernel enforcement claim
EOF

	tar -C "${dist_dir}" -czf "${archive}" "${artifact}"
	(
		cd "${dist_dir}"
		sha256sum "${artifact}.tar.gz" >> "$(basename "${checksum_file}")"
	)
done

printf '%s\n' "${checksum_file}"
