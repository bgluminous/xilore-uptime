#!/bin/sh
# Offline validation and idempotent registration. Secrets never enter argv or logs.
set +x
set -eu
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
. "$script_dir/common.sh"
xil_require awk
command_name=${1:-}
case "$command_name" in validate|publish) shift ;; *) xil_fail 2 '用法：publish-version.sh validate|publish --input <JSON文件> [--tag <标签>]' ;; esac
input= tag= seen=
while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || xil_fail 2 '命令参数缺少值'
    case " $seen " in *" $1 "*) xil_fail 2 '命令参数重复' ;; esac
    seen="$seen $1"
    case "$1" in
        --input) input=$2 ;;
        --tag) tag=$2 ;;
        *) xil_fail 2 '不支持的命令参数' ;;
    esac
    shift 2
done
[ -n "$input" ] || xil_fail 2 '需要 --input'
xil_readable "$input"
xil_temp
XV_TAG=$tag; export XV_TAG
if ! xil_json validate "$input" > "$xil_tmp/request.json" 2> "$xil_tmp/error"; then
    detail=$(cat "$xil_tmp/error")
    case "$detail" in
        E_PROJECT|E_PLATFORM|E_INPUT|E_DEPTH|E_FIELDS|E_VERSION|E_VERSION_CODE|E_TAG|E_CHANGELOG|E_DOWNLOAD_URL|E_EXTRA|E_FORCE_UPDATE|E_OVERWRITE)
            xil_fail 2 "输入预检失败：$detail" ;;
        *) xil_fail 2 '输入预检失败' ;;
    esac
fi
version=$(xil_json version "$xil_tmp/request.json")
if [ "$command_name" = validate ]; then
    printf 'validated project=%s platform=%s version=%s\n' "$XIL_PROJECT_CODE" "$XIL_PLATFORM_CODE" "$version"
    exit 0
fi
xil_require curl
xil_json origin /dev/null 2> "$xil_tmp/error" || xil_fail 2 'XIL_SERVICE_URL 必须是不含凭据或路径的 HTTP(S) origin'
[ -n "${XIL_PUBLISH_KEY:-}" ] || xil_fail 2 '缺少 XIL_PUBLISH_KEY'
# --config supports older curl versions too. Escape its own grammar, not JSON.
LC_ALL=C awk 'BEGIN {
    s=ENVIRON["XIL_PUBLISH_KEY"]
    if(s ~ /[\r\n]/) exit 2
    print "header = \"Content-Type: application/json\""
    printf "header = \"X-Publish-Key: "
    for(i=1;i<=length(s);i++) {
        c=substr(s,i,1)
        if(c=="\\" || c=="\"") printf "\\"
        printf "%s",c
    }
    print "\""
}' > "$xil_tmp/curl.conf" || xil_fail 2 '无效的 XIL_PUBLISH_KEY'
endpoint=${XIL_SERVICE_URL%/}/ver/$XIL_PROJECT_CODE/$XIL_PLATFORM_CODE
XV_VERSION=$version; export XV_VERSION
attempt=1
while [ "$attempt" -le 3 ]; do
    transport=0
    http=$(curl -q --silent --show-error --globoff --connect-timeout 10 --max-time 30 \
        --request POST --config "$xil_tmp/curl.conf" --data-binary "@$xil_tmp/request.json" \
        --output "$xil_tmp/response.json" --write-out '%{http_code}' --url "$endpoint" \
        2> "$xil_tmp/curl.error") || transport=$?
    if [ "$transport" -eq 0 ]; then
        case "$http" in
            200|201)
                [ -f "$xil_tmp/response.json" ] && [ "$(wc -c < "$xil_tmp/response.json")" -le 262144 ] || xil_fail 3 '发布响应无效'
                XV_HTTP=$http; export XV_HTTP
                outcome=$(xil_json response "$xil_tmp/response.json" 2> "$xil_tmp/error") || xil_fail 3 '发布响应未确认成功，请检查服务端'
                printf '%s project=%s platform=%s version=%s\n' "$outcome" "$XIL_PROJECT_CODE" "$XIL_PLATFORM_CODE" "$version"
                exit 0 ;;
        esac
    fi
    retry=false
    if [ "$transport" -ne 0 ]; then
        case "$transport" in 5|6|7|18|28|52|55|56) retry=true ;; esac
    else
        case "$http" in 408|429|500|502|503|504) retry=true ;; esac
    fi
    if [ "$retry" = true ] && [ "$attempt" -lt 3 ]; then
        printf '发布结果未确认，将重试（%s/3）\n' "$((attempt + 1))" >&2
        sleep "$attempt"
        attempt=$((attempt + 1))
        continue
    fi
    [ "$transport" -eq 0 ] || xil_fail 3 "发布网络请求失败（curl=$transport），未确认成功"
    err_code=0
    if [ -f "$xil_tmp/response.json" ] && [ "$(wc -c < "$xil_tmp/response.json")" -le 262144 ]; then
        err_code=$(xil_json error "$xil_tmp/response.json" 2>/dev/null) || err_code=0
    fi
    case "$http" in
        409) xil_fail 4 "发布冲突（HTTP 409, errCode=$err_code），请检查平台最高版本及内容差异" ;;
        401|403) xil_fail 4 "发布鉴权失败（HTTP $http, errCode=$err_code）" ;;
        *) case "$http" in [0-9][0-9][0-9]) ;; *) http=000 ;; esac
           xil_fail 4 "发布失败（HTTP $http, errCode=$err_code），未确认成功" ;;
    esac
done
