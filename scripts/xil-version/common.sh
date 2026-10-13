#!/bin/sh
# Shared POSIX helpers. Source from an entry point; do not enable tracing.
set +x

xil_fail() { printf '%s\n' "$2" >&2; exit "$1"; }
xil_require() { command -v "$1" >/dev/null 2>&1 || xil_fail 2 "缺少依赖：$1"; }
xil_temp() {
    umask 077
    xil_tmp=$(mktemp -d "${TMPDIR:-/tmp}/xil-version.XXXXXXXX") || xil_fail 2 '无法创建临时目录'
    trap 'rm -rf "$xil_tmp"' 0
    trap 'exit 130' INT
    trap 'exit 143' TERM
}
xil_readable() {
    [ -f "$1" ] && [ -r "$1" ] || xil_fail 2 '输入文件不可读'
    [ "$(wc -c < "$1")" -le 262144 ] || xil_fail 2 '输入文件超过 256 KiB'
}

# The parser stores strings as UTF-16 code units, not shell strings. This keeps
# escaped NULs, surrogate pairs and lone surrogates intact on all supported awks.
# JSON objects use encoded keys, so control characters cannot collide with SUBSEP.
# Environment variables carry arguments without awk -v backslash interpretation.
xil_json() (
    XV_MODE=$1
    export XV_MODE
    LC_ALL=C awk '
function fail(reason) { print reason > "/dev/stderr"; failed=1; exit 2 }
function alloc(t,    id) { id=++nodes; kind[id]=t; first[id]=1; size[id]=0; return id }
function space() { while (substr(src,pos,1) ~ /^[ \t\r\n]$/) pos++ }
function white(c) {
    return (c>=9 && c<=13) || c==32 || c==160 || c==5760 ||
        (c>=8192 && c<=8202) || c==8232 || c==8233 || c==8239 ||
        c==8287 || c==12288 || c==65279
}
function addunit(id,c) { units[id,++size[id]]=c }
function addpoint(id,c) {
    if (c>65535) { c-=65536; addunit(id,55296+int(c/1024)); addunit(id,56320+c%1024) }
    else addunit(id,c)
}
function utf8point(s,at,    b,n,c,j,v,min) {
    b=ord[substr(s,at,1)]; width=1
    if (b<128) return b
    if (b>=194 && b<=223) { n=2; c=b-192; min=128 }
    else if (b>=224 && b<=239) { n=3; c=b-224; min=2048 }
    else if (b>=240 && b<=244) { n=4; c=b-240; min=65536 }
    else fail("E_INPUT")
    for (j=1;j<n;j++) {
        if (at+j>length(s)) fail("E_INPUT")
        v=ord[substr(s,at+j,1)]
        if (v<128 || v>191) fail("E_INPUT")
        c=c*64+v-128
    }
    if (c<min || c>1114111 || (c>=55296 && c<=57343)) fail("E_INPUT")
    width=n; return c
}
function textnode(s,    id,j,c) {
    id=alloc("string")
    for (j=1;j<=length(s);j+=width) { c=utf8point(s,j); addpoint(id,c) }
    return id
}
function hex4(s,    j,n,h) {
    if (length(s)!=4 || s ~ /[^0-9a-fA-F]/) fail("E_INPUT")
    n=0
    for(j=1;j<=4;j++) { h=index("0123456789abcdef",tolower(substr(s,j,1)))-1; n=n*16+h }
    return n
}
function string(    id,c,e,v) {
    id=alloc("string"); pos++
    while (pos<=length(src)) {
        c=substr(src,pos,1)
        if (c=="\"") { pos++; return id }
        if (c=="\\") {
            e=substr(src,++pos,1); pos++
            if (e=="u") { v=hex4(substr(src,pos,4)); pos+=4 }
            else if (e=="\"" || e=="\\" || e=="/") v=ord[e]
            else if (e=="b") v=8
            else if (e=="f") v=12
            else if (e=="n") v=10
            else if (e=="r") v=13
            else if (e=="t") v=9
            else fail("E_INPUT")
            addunit(id,v)
        } else {
            v=utf8point(src,pos)
            if (v<32) fail("E_INPUT")
            addpoint(id,v); pos+=width
        }
    }
    fail("E_INPUT")
}
function quoted(id,    j,c,d,s) {
    s="\""
    for(j=first[id];j<=size[id];j++) {
        c=units[id,j]
        if (c==34 || c==92) s=s "\\" sprintf("%c",c)
        else if (c==8) s=s "\\b"
        else if (c==9) s=s "\\t"
        else if (c==10) s=s "\\n"
        else if (c==12) s=s "\\f"
        else if (c==13) s=s "\\r"
        else if (c>=55296 && c<=57343) {
            d=units[id,j+1]
            if(c<=56319 && j<size[id] && d>=56320 && d<=57343) {
                s=s utf8(65536+(c-55296)*1024+d-56320); j++
            } else s=s sprintf("\\u%04x",c)
        }
        else if (c<32) s=s sprintf("\\u%04x",c)
        else s=s utf8(c)
    }
    return s "\""
}
function utf8(c) {
    if(c<128) return sprintf("%c",c)
    if(c<2048) return sprintf("%c%c",192+int(c/64),128+c%64)
    if(c<65536) return sprintf("%c%c%c",224+int(c/4096),128+int(c/64)%64,128+c%64)
    return sprintf("%c%c%c%c",240+int(c/262144),128+int(c/4096)%64,128+int(c/64)%64,128+c%64)
}
function text(id,    s,j,c,d) {
    if (kind[id]!="string") return ""
    s=""
    for(j=first[id];j<=size[id];j++) {
        c=units[id,j]
        if(c>=55296 && c<=56319 && j<size[id]) {
            d=units[id,j+1]
            if(d>=56320 && d<=57343) { c=65536+(c-55296)*1024+d-56320; j++ }
        }
        s=s utf8(c)
    }
    return s
}
function trim(id) {
    while(first[id]<=size[id] && white(units[id,first[id]])) first[id]++
    while(first[id]<=size[id] && white(units[id,size[id]])) size[id]--
}
function blank(id,    j) {
    for(j=first[id];j<=size[id];j++) if(!white(units[id,j])) return 0
    return 1
}
function get(id,k) { return member[id,"\"" k "\""] }
function put(id,k,v,    q) {
    q=quoted(k)
    if(!((id SUBSEP q) in member)) key[id,++size[id]]=k
    member[id,q]=v
}
function field(id,k,v) { put(id,textnode(k),v) }
function value(depth,    id,c,k,v,t,n) {
    if(depth>128) fail("E_DEPTH")
    space(); c=substr(src,pos,1)
    if(c=="\"") return string()
    if(c=="{" || c=="[") {
        id=alloc(c=="{" ? "object" : "array"); pos++; space()
        if(substr(src,pos,1)==(c=="{" ? "}" : "]")) { pos++; return id }
        while(1) {
            if(c=="{") {
                if(substr(src,pos,1)!="\"") fail("E_INPUT")
                k=string(); space()
                if(substr(src,pos++,1)!=":") fail("E_INPUT")
                v=value(depth+1); put(id,k,v)
            } else child[id,++size[id]]=value(depth+1)
            space(); t=substr(src,pos++,1)
            if(t==(c=="{" ? "}" : "]")) return id
            if(t!=",") fail("E_INPUT")
            space()
        }
    }
    if(match(substr(src,pos),/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/)) {
        t=substr(src,pos,RLENGTH); pos+=RLENGTH
        n=t+0
        if(tolower(sprintf("%g",n)) ~ /inf|nan/) fail("E_INPUT")
        id=alloc("number"); scalar[id]=t; return id
    }
    t=substr(src,pos,4)
    if(t=="null" || t=="true") { pos+=4; id=alloc(t=="null" ? "null" : "boolean"); scalar[id]=t; return id }
    if(substr(src,pos,5)=="false") { pos+=5; id=alloc("boolean"); scalar[id]="false"; return id }
    fail("E_INPUT")
}
function parse() {
    pos=1; root=value(0); space()
    if(pos<=length(src)) fail("E_INPUT")
    return root
}
function serial(id,    t,s,j,k) {
    t=kind[id]
    if(t=="string") return quoted(id)
    if(t=="number" || t=="boolean") return scalar[id]
    if(t=="null") return "null"
    s=(t=="object" ? "{" : "[")
    for(j=1;j<=size[id];j++) {
        if(j>1) s=s ","
        if(t=="object") { k=key[id,j]; s=s quoted(k) ":" serial(member[id,quoted(k)]) }
        else s=s serial(child[id,j])
    }
    return s (t=="object" ? "}" : "]")
}
# Shortest round-tripping decimal, with the JSON.stringify exponent boundaries.
function numbertext(token,    n,p,s,a,e,d,point,sign,j) {
    n=token+0
    if(n==0) return "0"
    for(p=1;p<=17;p++) { s=sprintf("%.*g",p,n); if(s+0==n) break }
    sign=""; if(substr(s,1,1)=="-") { sign="-"; s=substr(s,2) }
    split(s,a,/[eE]/); e=a[2]+0; d=a[1]; point=index(d,".")
    if(!point) point=length(d)+1
    point=point-1+e; gsub(/\./,"",d)
    while(length(d)>1 && substr(d,1,1)=="0") { d=substr(d,2); point-- }
    if((n<0 ? -n : n)>=0.000001 && (n<0 ? -n : n)<1e21) {
        if(point<=0) { s="0."; for(j=0;j>point;j--) s=s "0"; s=s d }
        else if(point>=length(d)) { s=d; for(j=length(d);j<point;j++) s=s "0" }
        else s=substr(d,1,point) "." substr(d,point+1)
    } else {
        s=substr(d,1,1); if(length(d)>1) s=s "." substr(d,2)
        e=point-1; s=s "e" (e>=0 ? "+" : "") e
    }
    return sign s
}
function compactlen(id,    t,n,j,c,d,k) {
    t=kind[id]
    if(t=="number") return length(numbertext(scalar[id]))
    if(t=="null") return 4
    if(t=="boolean") return length(scalar[id])
    n=2
    if(t=="string") {
        for(j=first[id];j<=size[id];j++) {
            c=units[id,j]
            if(c==34 || c==92 || c==8 || c==9 || c==10 || c==12 || c==13) n+=2
            else if(c<32) n+=6
            else if(c>=55296 && c<=57343) {
                d=units[id,j+1]
                if(c<=56319 && j<size[id] && d>=56320 && d<=57343) { n+=2; j++ }
                else n+=6
            } else n++
        }
    } else for(j=1;j<=size[id];j++) {
        if(j>1) n++
        if(t=="object") { k=key[id,j]; n+=compactlen(k)+1+compactlen(member[id,quoted(k)]) }
        else n+=compactlen(child[id,j])
    }
    return n
}
function version(id,    s,a,j) {
    if(kind[id]!="string") fail("E_VERSION")
    trim(id); s=text(id)
    if(s !~ /^[0-9]+\.[0-9]+\.[0-9]+$/) fail("E_VERSION")
    split(s,a,".")
    for(j=1;j<=3;j++) if(a[j]+0>99) fail("E_VERSION")
    return sprintf("%d.%d.%d",a[1]+0,a[2]+0,a[3]+0)
}
function code(v,    a) { split(v,a,"."); return 10000000+a[1]*131072+a[2]*1024+a[3]*8+1 }
function url(id,origin,    s,authority,rest,port,j,c,at) {
    if(kind[id]!="string") return 0
    trim(id); s=text(id)
    if(s !~ /^https?:\/\//) return 0
    for(j=first[id];j<=size[id];j++) {
        c=units[id,j]
        if(c<33 || c==92 || c==127 || white(c)) return 0
        if(c>=55296 && c<=57343) {
            if(c>56319 || j>=size[id] || units[id,j+1]<56320 || units[id,j+1]>57343) return 0
            j++
        }
    }
    sub(/^https?:\/\//,"",s); authority=s; sub(/[\/?#].*$/,"",authority)
    rest=substr(s,length(authority)+1)
    if(origin && rest!="" && rest!="/") return 0
    if(origin && index(authority,"@")) return 0
    at=index(authority,"@")
    if(at) { authority=substr(authority,at+1); if(index(authority,"@")) return 0 }
    if(authority=="") return 0
    if(substr(authority,1,1)=="[") {
        if(authority !~ /^\[[0-9A-Fa-f:.]+\](:[0-9]+)?$/) return 0
        sub(/^\[[^]]+\]/,"",authority)
    } else {
        if(authority !~ /^[^:@]+(:[0-9]+)?$/) return 0
        sub(/^[^:]+/,"",authority)
    }
    if(authority!="") { port=substr(authority,2); if(port+0>65535) return 0 }
    return 1
}
function validate(id,identities,    j,k,v,n,tag) {
    if(kind[id]!="object") fail("E_INPUT")
    if(identities) {
        if(project !~ /^[a-zA-Z][a-zA-Z0-9_-]*$/ || length(project)>64) fail("E_PROJECT")
        if(platform !~ /^[a-zA-Z0-9._-]+$/ || length(platform)>32 || platform=="." || platform=="..") fail("E_PLATFORM")
    }
    for(j=1;j<=size[id];j++) {
        k=text(key[id,j])
        if(k !~ /^(version|versionCode|changelog|downloadUrl|extra|forceUpdate|overwrite)$/) fail("E_FIELDS")
    }
    v=version(get(id,"version")); field(id,"version",textnode(v))
    n=get(id,"versionCode")
    if(n && (kind[n]!="number" || scalar[n]+0!=code(v))) fail("E_VERSION_CODE")
    tag=ENVIRON["XV_TAG"]
    if(tag!="") { sub(/^v/,"",tag); if(version(textnode(tag))!=v) fail("E_TAG") }
    n=get(id,"changelog")
    if(n && kind[n]!="null") {
        if(kind[n]!="string" || size[n]-first[n]+1>16000) fail("E_CHANGELOG")
        if(blank(n)) field(id,"changelog",alloc("null"))
    }
    n=get(id,"downloadUrl")
    if(n && kind[n]!="null") {
        if(kind[n]!="string") fail("E_DOWNLOAD_URL")
        trim(n)
        if(blank(n)) field(id,"downloadUrl",alloc("null"))
        else if(size[n]-first[n]+1>16000 || !url(n,0)) fail("E_DOWNLOAD_URL")
    }
    n=get(id,"extra"); if(n && compactlen(n)>16000) fail("E_EXTRA")
    n=get(id,"forceUpdate"); if(n && kind[n]!="boolean") fail("E_FORCE_UPDATE")
    n=get(id,"overwrite"); if(n && kind[n]!="boolean") fail("E_OVERWRITE")
    return id
}
BEGIN {
    for(i=0;i<256;i++) ord[sprintf("%c",i)]=i
    project=ENVIRON["XIL_PROJECT_CODE"]; platform=ENVIRON["XIL_PLATFORM_CODE"]
    mode=ENVIRON["XV_MODE"]; src=""
}
{ src=src $0 "\n" }
END {
    if(failed) exit 2
    if(mode=="semver") print version(textnode(ENVIRON["XV_VERSION"]))
    else if(mode=="origin") {
        id=textnode(ENVIRON["XIL_SERVICE_URL"])
        if(!url(id,1) || text(id)!=ENVIRON["XIL_SERVICE_URL"]) fail("E_SERVICE")
    } else if(mode=="build") {
        id=alloc("object"); field(id,"version",textnode(ENVIRON["XV_VERSION"]))
        src=substr(src,1,ENVIRON["XV_TEXT_SIZE"]+0)
        if(src!="") field(id,"changelog",textnode(src))
        if(ENVIRON["XV_DOWNLOAD"]!="") field(id,"downloadUrl",textnode(ENVIRON["XV_DOWNLOAD"]))
        if(ENVIRON["XV_IMAGE"]!="" || ENVIRON["XV_ARCH"]!="") {
            ext=alloc("object")
            if(ENVIRON["XV_IMAGE"]!="") field(ext,"image",textnode(ENVIRON["XV_IMAGE"]))
            if(ENVIRON["XV_ARCH"]!="") field(ext,"arch",textnode(ENVIRON["XV_ARCH"]))
            field(id,"extra",ext)
        }
        print serial(validate(id,0))
    } else {
        id=parse()
        if(mode=="validate") print serial(validate(id,1))
        else if(mode=="version") {
            if(kind[id]!="object") fail("E_VERSION")
            print version(get(id,"version"))
        } else if(mode=="response") {
            v=ENVIRON["XV_VERSION"]; data=get(id,"data"); n=get(id,"code"); vc=get(data,"versionCode")
            if(kind[id]!="object" || kind[n]!="number" || scalar[n]+0!=0 || kind[data]!="object" ||
                text(get(data,"projectCode"))!=project || text(get(data,"platformCode"))!=platform ||
                text(get(data,"version"))!=v || kind[vc]!="number" || scalar[vc]+0!=code(v)) fail("E_RESPONSE")
            remark=text(get(id,"remark"))
            if(ENVIRON["XV_HTTP"]=="201" ? remark!="created" : (remark!="unchanged" && remark!="overwritten")) fail("E_RESPONSE")
            print remark
        } else if(mode=="error") {
            n=get(id,"errCode")
            if(kind[n]=="number" && scalar[n] ~ /^[0-9]+$/ && length(scalar[n])<=10) print scalar[n]
            else print "0"
        } else fail("E_MODE")
    }
}' "$2"
)
