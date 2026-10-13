#!/bin/sh
# Call only after this image has been pushed successfully. Does not build or push.
set +x
set -eu
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
. "$script_dir/common.sh"
xil_require docker
image= prefix= download= version= version_file= notes= mode= seen=
while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || xil_fail 2 '命令参数缺少值'
    case " $seen " in *" $1 "*) xil_fail 2 '命令参数重复' ;; esac
    seen="$seen $1"
    case "$1" in
        --image) image=$2 ;;
        --platform-prefix) prefix=$2 ;;
        --download-url) download=$2 ;;
        --version) [ -n "$2" ] || xil_fail 2 '版本不能为空'; version=$2 ;;
        --version-file) [ -n "$2" ] || xil_fail 2 '版本文件路径不能为空'; version_file=$2 ;;
        --changelog-file) [ -n "$2" ] || xil_fail 2 '更新说明路径不能为空'; notes=$2 ;;
        --changelog-mode) [ -n "$2" ] || xil_fail 2 '更新说明模式不能为空'; mode=$2 ;;
        *) xil_fail 2 '不支持的命令参数' ;;
    esac
    shift 2
done
[ -n "$image" ] && [ -n "$prefix" ] || xil_fail 2 '需要镜像和平台前缀'
xil_temp
raw_arch=$(docker image inspect "$image" --format '{{.Architecture}}' 2> "$xil_tmp/docker.error") || xil_fail 2 '无法读取本地镜像架构'
case "$raw_arch" in
    amd64|x86_64) arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) xil_fail 2 '不支持的镜像架构' ;;
esac
XIL_PLATFORM_CODE=$prefix-$arch; export XIL_PLATFORM_CODE
set -- --out "$xil_tmp/release.json" --image "$image" --arch "$arch"
[ -z "$download" ] || set -- "$@" --download-url "$download"
[ -z "$version" ] || set -- "$@" --version "$version"
[ -z "$version_file" ] || set -- "$@" --version-file "$version_file"
[ -z "$notes" ] || set -- "$@" --changelog-file "$notes"
[ -z "$mode" ] || set -- "$@" --changelog-mode "$mode"
sh "$script_dir/prepare-release-json.sh" "$@"
sh "$script_dir/publish-version.sh" validate --input "$xil_tmp/release.json"
sh "$script_dir/publish-version.sh" publish --input "$xil_tmp/release.json"
