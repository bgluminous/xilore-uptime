# Validate reviewed Markdown without rewriting it or guessing which sections to remove.
# Run with LC_ALL=C so the same rules apply in every publisher shell.
function trim(s) { gsub(/^[ \t\r]+|[ \t\r]+$/, "", s); return s }
function uncomment(s,    out, at) {
    out = ""
    while (s != "") {
        if (comment) {
            at = index(s, "-->")
            if (!at) return out
            comment = 0; s = substr(s, at + 3)
        } else {
            at = index(s, "<!--")
            if (!at) return out s
            out = out substr(s, 1, at - 1); s = substr(s, at + 4); comment = 1
        }
    }
    return out
}
{
    line = uncomment($0)
    # Normalize Unicode whitespace only for validation; the original text is retained.
    gsub(/\302\240|\341\232\200|\342\200[\200-\212\250\251\257]|\342\201\237|\343\200\200|\357\273\277/, " ", line)
    line = trim(line)
    if (line == "" || line ~ /^([-_*][ \t]*)+$/ || line ~ /^(```|~~~)/) next
    heading = line ~ /^#+[ \t]+/
    sub(/^#+[ \t]+/, "", line)
    sub(/[ \t]+#+$/, "", line)
    sub(/^([-*+]|[0-9]+[.)])[ \t]+/, "", line)
    sub(/^\[[ xX]\][ \t]*/, "", line)
    gsub(/[*_`]/, "", line)
    line = tolower(trim(line))
    if (line ~ /^(变更|更新日志|更新说明|changelog|change log|changes|release notes)$/) {
        print "E_CHANGELOG_REDUNDANT_TITLE" > "/dev/stderr"; invalid = 1; exit 2
    }
    if (heading) next
    sub(/([.!?:;]|。|！|？|：|；|…)+$/, "", line)
    line = trim(line)
    if (line == "" || line ~ /^(todo|tbd|tba|fixme|placeholder|null|none|n\/a|待补充|待完善|待填写|待编写|待更新|待定|暂无|暂无更新|暂无内容|无|占位|占位内容|首个发布版本|initial release)$/) next
    meaningful = 1
}
END {
    if (!invalid && (!meaningful || comment)) {
        print "E_CHANGELOG_EMPTY_OR_PLACEHOLDER" > "/dev/stderr"; exit 2
    }
}
