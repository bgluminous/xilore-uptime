#!/bin/sh
# Prepare a release from an authoritative version source; never change that source.
set +x
set -eu
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
. "$script_dir/common.sh"
xil_require awk
project_root=$(CDPATH= cd -P "$script_dir/../.." && pwd)
out= version= version_file= notes= image= arch= download= seen=
changelog_mode=sections
while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || xil_fail 2 '命令参数缺少值'
    case " $seen " in *" $1 "*) xil_fail 2 '命令参数重复' ;; esac
    seen="$seen $1"
    case "$1" in
        --out) out=$2 ;;
        --version) version=$2 ;;
        --version-file) [ -n "$2" ] || xil_fail 2 '版本文件路径不能为空'; version_file=$2 ;;
        --changelog-file) [ -n "$2" ] || xil_fail 2 '更新说明路径不能为空'; notes=$2 ;;
        --changelog-mode) changelog_mode=$2 ;;
        --image) image=$2 ;;
        --arch) arch=$2 ;;
        --download-url) download=$2 ;;
        *) xil_fail 2 '不支持的命令参数' ;;
    esac
    shift 2
done
[ -n "$out" ] || xil_fail 2 '需要 --out'
case " $seen " in
    *' --version '*)
        [ -n "$version" ] || xil_fail 2 '--version 不能为空'
        case " $seen " in *' --version-file '*) xil_fail 2 '两个版本来源不能同时指定' ;; esac ;;
esac
case "$changelog_mode" in sections|plain) ;; *) xil_fail 2 '更新说明模式必须是 sections 或 plain' ;; esac
xil_temp
if [ -n "$version" ]; then
    XV_VERSION=$version; export XV_VERSION
    version=$(xil_json semver /dev/null 2> "$xil_tmp/error") || xil_fail 2 '权威版本不是有效的 X.Y.Z（各段 0 到 99）'
else
    version_file=${version_file:-$project_root/package.json}
    xil_readable "$version_file"
    version=$(xil_json version "$version_file" 2> "$xil_tmp/error") || xil_fail 2 '无法读取权威版本源的顶层 version'
fi
notes=${notes:-$project_root/docs/UPDATE_NOTE.md}
[ -f "$notes" ] && [ -r "$notes" ] || xil_fail 2 '缺少更新说明文件'
XV_VERSION=$version; export XV_VERSION
if [ "$changelog_mode" = plain ]; then
    cp "$notes" "$xil_tmp/notes" || xil_fail 2 '无法读取更新说明'
else
    LC_ALL=C awk '
        { sub(/\r$/, "") }
        /^## / {
            section=""; heading=substr($0,4); target="版本 " ENVIRON["XV_VERSION"]
            if(heading=="未发布" || heading ~ /^未发布([[:space:]]|[-（(])/) section="unreleased"
            else if(substr(heading,1,length(target))==target) {
                tail=substr(heading,length(target)+1)
                if(tail=="" || tail ~ /^([[:space:]]|（|\()/) section="version"
            }
            next
        }
        section=="unreleased" { u=u $0 "\n" }
        section=="version" { v=v $0 "\n" }
        END {
            gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", u)
            gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", v)
            printf "%s", (u!="" ? u : v)
        }
    ' "$notes" > "$xil_tmp/notes" || xil_fail 2 '无法提取更新说明'
fi
xil_readable "$xil_tmp/notes"
XV_TEXT_SIZE=$(wc -c < "$xil_tmp/notes")
XV_IMAGE=$image XV_ARCH=$arch XV_DOWNLOAD=$download XV_TAG=
export XV_TEXT_SIZE XV_IMAGE XV_ARCH XV_DOWNLOAD XV_TAG
xil_json build "$xil_tmp/notes" > "$xil_tmp/release.json" 2> "$xil_tmp/error" || xil_fail 2 '登记数据格式或字段长度无效'
out_dir=$(CDPATH= cd -P "$(dirname "$out")" && pwd) || xil_fail 2 '输出目录不存在'
out_path=$out_dir/$(basename "$out")
[ ! -L "$out_path" ] && [ ! -d "$out_path" ] || xil_fail 2 '输出必须是普通文件路径'
for source_path in "$version_file" "$notes" "$project_root/package.json"; do
    [ -n "$source_path" ] && [ -f "$source_path" ] || continue
    source_dir=$(CDPATH= cd -P "$(dirname "$source_path")" && pwd)
    [ "$out_path" != "$source_dir/$(basename "$source_path")" ] || xil_fail 2 '不得覆盖版本源或更新说明'
done
mv -f "$xil_tmp/release.json" "$out_path" || xil_fail 2 '无法保存登记数据'
printf 'prepared version=%s\n' "$version"
