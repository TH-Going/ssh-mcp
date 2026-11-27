use std::sync::LazyLock;

use regex::Regex;

use crate::models::{ApprovalRiskLevel, ControlMode, Server, ToolOperation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationCategory {
    Read,
    Write,
    Delete,
    ServiceControl,
    Sudo,
    ArbitraryShell,
}

impl OperationCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::ServiceControl => "service_control",
            Self::Sudo => "sudo",
            Self::ArbitraryShell => "arbitrary_shell",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApprovalPolicyContext {
    pub cleanup_includes_volumes: bool,
    pub policy_summary: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApprovalPolicyDecision {
    pub requires_approval: bool,
    pub approval_reason: String,
    pub matched_policy: String,
    pub risk_level: ApprovalRiskLevel,
    pub category: OperationCategory,
    pub policy_summary: Option<String>,
}

static DELETE_SHELL_1_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:sudo\s+)?(?:rm|rmdir|unlink|shred)\b").unwrap());
static DELETE_SHELL_2_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:sudo\s+)?docker\s+\S+\s+(?:rm|remove|prune)\b").unwrap());
static SERVICE_SHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:sudo\s+)?systemctl\s+(?:start|stop|restart|reload|enable|disable|mask|unmask)\b")
        .unwrap()
});
static WRITE_SHELL_1_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:sudo\s+)?(?:cp|mv|touch|mkdir|chmod|chown|ln|truncate|tee)\b").unwrap()
});
static WRITE_SHELL_2_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:sudo\s+)?sed\s+[^\r\n]*\s-i(?:\s|$)").unwrap());
static INLINE_SUDO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[|;&])\s*(?:/usr/bin/|/bin/)?sudo\b").unwrap());

pub fn evaluate_approval_policy(
    server: &Server,
    operation: &ToolOperation,
    ctx: &ApprovalPolicyContext,
) -> ApprovalPolicyDecision {
    if matches!(operation, ToolOperation::DockerCleanupExecute { .. }) && ctx.cleanup_includes_volumes {
        return make_decision(
            true,
            "清理计划包含未使用卷删除，卷删除必须显式启用并独立审批",
            "docker.cleanup.volume_delete",
            ApprovalRiskLevel::High,
            OperationCategory::Delete,
            ctx.policy_summary.clone(),
        );
    }

    let classified = classify_operation(operation, ctx.policy_summary.clone());

    if server.control_mode == ControlMode::Direct {
        return ApprovalPolicyDecision {
            requires_approval: false,
            approval_reason: format!(
                "服务器为全自动模式；操作仍按 {} 风险审计",
                classified.category.as_str()
            ),
            matched_policy: format!("server.direct.{}", classified.matched_policy),
            ..classified
        };
    }

    classified
}

fn classify_operation(
    operation: &ToolOperation,
    policy_summary: Option<String>,
) -> ApprovalPolicyDecision {
    // 1. Dedicated read-only tools (even with sudo: true) are always exempt from approval.
    if operation.is_read_only_tool() {
        return make_decision(
            false,
            "专用只读工具仅读取受限状态，免人工审批",
            "tool.read_only",
            ApprovalRiskLevel::Low,
            OperationCategory::Read,
            policy_summary,
        );
    }

    match operation {
        ToolOperation::ShellExecute { command, sudo, .. } => {
            if is_recognized_read_only_shell(command) {
                return make_decision(
                    false,
                    "命令经词法与白名单校验确认为只读查询，免人工审批",
                    "shell.read_only.exempt",
                    ApprovalRiskLevel::Low,
                    OperationCategory::Read,
                    policy_summary,
                );
            }

            if *sudo || INLINE_SUDO_RE.is_match(command) {
                return make_decision(
                    true,
                    "操作请求 sudo 提权且包含非只读或未识别语义，必须人工审批",
                    "operation.sudo",
                    ApprovalRiskLevel::High,
                    OperationCategory::Sudo,
                    policy_summary,
                );
            }

            if DELETE_SHELL_1_RE.is_match(command) || DELETE_SHELL_2_RE.is_match(command) {
                make_decision(
                    true,
                    "Shell 命令包含删除语义，必须人工审批",
                    "shell.delete",
                    ApprovalRiskLevel::High,
                    OperationCategory::Delete,
                    policy_summary,
                )
            } else if SERVICE_SHELL_RE.is_match(command) {
                make_decision(
                    true,
                    "Shell 命令包含服务控制语义，必须人工审批",
                    "shell.service_control",
                    ApprovalRiskLevel::High,
                    OperationCategory::ServiceControl,
                    policy_summary,
                )
            } else if WRITE_SHELL_1_RE.is_match(command) || WRITE_SHELL_2_RE.is_match(command) {
                make_decision(
                    true,
                    "Shell 命令包含写入语义，必须人工审批",
                    "shell.write",
                    ApprovalRiskLevel::High,
                    OperationCategory::Write,
                    policy_summary,
                )
            } else {
                make_decision(
                    true,
                    "任意 Shell 无法证明为纯只读，必须人工审批",
                    "shell.arbitrary",
                    ApprovalRiskLevel::High,
                    OperationCategory::ArbitraryShell,
                    policy_summary,
                )
            }
        }
        other => {
            if other.uses_sudo() {
                return make_decision(
                    true,
                    "变更操作请求 sudo 提权，必须人工审批",
                    "operation.sudo",
                    ApprovalRiskLevel::High,
                    OperationCategory::Sudo,
                    policy_summary,
                );
            }
            match other {
                ToolOperation::ServiceControl { .. } => make_decision(
                    true,
                    "systemd 服务控制会改变远端状态，必须人工审批",
                    "tool.service_control",
                    ApprovalRiskLevel::Medium,
                    OperationCategory::ServiceControl,
                    policy_summary,
                ),
                ToolOperation::DockerCleanupExecute { .. } => make_decision(
                    true,
                    "Docker 清理会删除预览计划中的对象，必须人工审批",
                    "docker.cleanup.delete",
                    ApprovalRiskLevel::High,
                    OperationCategory::Delete,
                    policy_summary,
                ),
                ToolOperation::FileUpload { .. } | ToolOperation::FileDownload { .. } => {
                    make_decision(
                        true,
                        "文件传输会写入远端或本机文件，必须人工审批",
                        "tool.file_write",
                        ApprovalRiskLevel::Medium,
                        OperationCategory::Write,
                        policy_summary,
                    )
                }
                _ => make_decision(
                    true,
                    "操作会改变状态，必须人工审批",
                    "tool.write",
                    ApprovalRiskLevel::Medium,
                    OperationCategory::Write,
                    policy_summary,
                ),
            }
        }
    }
}

/// Checks whether a shell command string consists strictly of read-only inspection commands
/// connected only by safe pipelines (`|`) or short-circuit operators (`&&`, `||`), with zero
/// redirection, command substitution, subshells, or mutating flags/subcommands.
pub fn is_recognized_read_only_shell(command: &str) -> bool {
    let trimmed = command.trim();
    if trimmed.is_empty()
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains('\0')
    {
        return false;
    }

    let Ok(segments) = lex_safe_shell_segments(trimmed) else {
        return false;
    };
    if segments.is_empty() {
        return false;
    }

    segments.iter().all(|seg| is_read_only_segment(seg))
}

#[derive(Debug, PartialEq, Eq)]
enum LexToken {
    Word(String),
    Separator, // `|`, `&&`, `||`
}

fn lex_safe_shell_segments(input: &str) -> Result<Vec<Vec<String>>, ()> {
    let mut tokens: Vec<LexToken> = Vec::new();
    let mut current = String::new();
    let mut in_word = false;

    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];
        match ch {
            ' ' | '\t' => {
                if in_word {
                    tokens.push(LexToken::Word(std::mem::take(&mut current)));
                    in_word = false;
                }
                i += 1;
            }
            '\'' => {
                // Single-quoted literal: everything until next `'` is completely literal in POSIX sh.
                in_word = true;
                i += 1;
                let mut closed = false;
                while i < len {
                    if chars[i] == '\'' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    current.push(chars[i]);
                    i += 1;
                }
                if !closed {
                    return Err(());
                }
            }
            '"' => {
                // Double-quoted string: forbid `$` and `` ` `` unconditionally to prevent any expansion/substitution.
                in_word = true;
                i += 1;
                let mut closed = false;
                while i < len {
                    match chars[i] {
                        '"' => {
                            closed = true;
                            i += 1;
                            break;
                        }
                        '$' | '`' => return Err(()),
                        '\\' => {
                            if i + 1 >= len {
                                return Err(());
                            }
                            let next = chars[i + 1];
                            if matches!(next, '$' | '`') {
                                return Err(());
                            }
                            if matches!(next, '"' | '\\') {
                                current.push(next);
                            } else {
                                current.push('\\');
                                current.push(next);
                            }
                            i += 2;
                        }
                        other => {
                            current.push(other);
                            i += 1;
                        }
                    }
                }
                if !closed {
                    return Err(());
                }
            }
            '\\' => {
                if i + 1 >= len {
                    return Err(());
                }
                in_word = true;
                current.push(chars[i + 1]);
                i += 2;
            }
            '|' => {
                if in_word {
                    tokens.push(LexToken::Word(std::mem::take(&mut current)));
                    in_word = false;
                }
                if i + 1 < len && chars[i + 1] == '|' {
                    tokens.push(LexToken::Separator);
                    i += 2;
                } else if i + 1 < len && chars[i + 1] == '&' {
                    // Reject bash-specific `|&` to keep semantics portable and strict
                    return Err(());
                } else {
                    tokens.push(LexToken::Separator);
                    i += 1;
                }
            }
            '&' => {
                if i + 1 < len && chars[i + 1] == '&' {
                    if in_word {
                        tokens.push(LexToken::Word(std::mem::take(&mut current)));
                        in_word = false;
                    }
                    tokens.push(LexToken::Separator);
                    i += 2;
                } else {
                    // Single `&` (background execution or `&>` redirection) is forbidden
                    return Err(());
                }
            }
            // Reject command chaining `;`, redirections `<` `>`, expansions `$` `` ` ``, subshells `(` `)`, braces `{` `}`
            ';' | '<' | '>' | '$' | '`' | '(' | ')' | '{' | '}' => {
                return Err(());
            }
            other => {
                in_word = true;
                current.push(other);
                i += 1;
            }
        }
    }

    if in_word {
        tokens.push(LexToken::Word(current));
    }

    let mut segments: Vec<Vec<String>> = Vec::new();
    let mut seg: Vec<String> = Vec::new();
    for tok in tokens {
        match tok {
            LexToken::Word(w) => seg.push(w),
            LexToken::Separator => {
                if seg.is_empty() {
                    return Err(());
                }
                segments.push(std::mem::take(&mut seg));
            }
        }
    }
    if seg.is_empty() {
        return Err(());
    }
    segments.push(seg);

    Ok(segments)
}

const ALLOWED_BIN_PREFIXES: &[&str] = &[
    "/bin/",
    "/usr/bin/",
    "/sbin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
];

const PURE_READ_ONLY_COMMANDS: &[&str] = &[
    "ls",
    "ll",
    "dir",
    "vdir",
    "pwd",
    "whoami",
    "id",
    "groups",
    "logname",
    "uname",
    "hostname",
    "uptime",
    "date",
    "cal",
    "df",
    "du",
    "free",
    "vmstat",
    "mpstat",
    "iostat",
    "sar",
    "pidstat",
    "numastat",
    "lscpu",
    "lsmem",
    "lsblk",
    "lspci",
    "lsusb",
    "lshw",
    "dmidecode",
    "lsmod",
    "modinfo",
    "nproc",
    "arch",
    "getconf",
    "locale",
    "w",
    "who",
    "users",
    "last",
    "lastlog",
    "stat",
    "file",
    "realpath",
    "readlink",
    "basename",
    "dirname",
    "which",
    "whereis",
    "type",
    "cat",
    "tac",
    "nl",
    "od",
    "hexdump",
    "xxd",
    "strings",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "cksum",
    "b2sum",
    "diff",
    "cmp",
    "comm",
    "tree",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "zgrep",
    "zegrep",
    "zfgrep",
    "zcat",
    "bzcat",
    "xzcat",
    "cut",
    "tr",
    "paste",
    "join",
    "column",
    "fold",
    "fmt",
    "rev",
    "jq",
    "ps",
    "pgrep",
    "pidof",
    "pstree",
    "top",
    "lsof",
    "lsns",
    "lsipc",
    "lslocks",
    "ss",
    "netstat",
    "ping",
    "ping6",
    "traceroute",
    "tracepath",
    "mtr",
    "dig",
    "nslookup",
    "host",
    "whois",
    "arp",
    "printenv",
    "echo",
    "printf",
    "true",
    "false",
    "test",
];

fn normalize_executable(raw: &str) -> Option<&str> {
    if raw.is_empty() || raw.starts_with('-') || raw.contains("..") {
        return None;
    }
    if !raw.contains('/') {
        return Some(raw);
    }
    for prefix in ALLOWED_BIN_PREFIXES {
        if let Some(rest) = raw.strip_prefix(prefix) {
            if !rest.is_empty() && !rest.contains('/') {
                return Some(rest);
            }
            return None;
        }
    }
    None
}

fn strip_safe_sudo(tokens: &[String]) -> Option<&[String]> {
    let first = normalize_executable(tokens.first()?.as_str())?;
    if first != "sudo" {
        return Some(tokens);
    }

    let mut idx = 1;
    while idx < tokens.len() {
        match tokens[idx].as_str() {
            "-n" | "--non-interactive" => idx += 1,
            "--" => {
                idx += 1;
                break;
            }
            other if other.starts_with('-') || other.contains('=') => {
                // Reject sudo user/shell switching (`-u`, `-i`, `-s`, `-E`, etc.) or env overrides
                return None;
            }
            _ => break,
        }
    }

    let rest = &tokens[idx..];
    if rest.is_empty() {
        return None;
    }
    if normalize_executable(&rest[0]) == Some("sudo") {
        return None;
    }
    Some(rest)
}

fn short_flag_contains(arg: &str, ch: char) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(ch)
}

fn is_read_only_segment(raw_tokens: &[String]) -> bool {
    let Some(tokens) = strip_safe_sudo(raw_tokens) else {
        return false;
    };
    let Some(cmd) = tokens.first().and_then(|s| normalize_executable(s)) else {
        return false;
    };
    let args = &tokens[1..];

    if PURE_READ_ONLY_COMMANDS.contains(&cmd) {
        return true;
    }

    match cmd {
        "env" => args.is_empty(),
        "find" => !args.iter().any(|a| {
            matches!(
                a.as_str(),
                "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir" | "-fls"
            ) || a.starts_with("-fprint")
        }),
        "sed" => {
            !args.iter().any(|a| {
                a == "-i"
                    || a.starts_with("-i")
                    || a.starts_with("--in-place")
                    || short_flag_contains(a, 'i')
                    || (!a.starts_with('-') && (a.starts_with("w ") || a.contains("/w ")))
            })
        }
        "awk" | "gawk" | "mawk" | "nawk" => {
            !args.iter().any(|a| {
                a == "-f"
                    || a.starts_with("-f")
                    || a.starts_with("--file")
                    || short_flag_contains(a, 'f')
                    || a.contains("system(")
                    || a.contains('>')
                    || a.contains('|')
            })
        }
        "sort" => !args.iter().any(|a| {
            a == "-o"
                || a.starts_with("-o")
                || a.starts_with("--output")
                || short_flag_contains(a, 'o')
        }),
        "uniq" => {
            // Allow flags + at most 1 input file (2nd positional file in `uniq` is an output file!)
            let mut positional = 0usize;
            let mut skip_next = false;
            for a in args {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if matches!(a.as_str(), "-f" | "-s" | "-w") {
                    skip_next = true;
                } else if !a.starts_with('-') {
                    positional += 1;
                }
            }
            positional <= 1
        }
        "yq" => !args.iter().any(|a| {
            a == "-i" || a.starts_with("--inplace") || short_flag_contains(a, 'i')
        }),
        "dmesg" => !args.iter().any(|a| {
            matches!(
                a.as_str(),
                "-c" | "-C"
                    | "--clear"
                    | "--read-clear"
                    | "--console-off"
                    | "--console-on"
                    | "--console-level"
            ) || short_flag_contains(a, 'c')
                || short_flag_contains(a, 'C')
        }),
        "fuser" => !args
            .iter()
            .any(|a| a == "-k" || a == "--kill" || short_flag_contains(a, 'k')),
        "sysctl" => !args.iter().any(|a| {
            matches!(
                a.as_str(),
                "-w" | "--write" | "-p" | "--load" | "--system"
            ) || short_flag_contains(a, 'w')
                || short_flag_contains(a, 'p')
                || a.contains('=')
        }),
        "ulimit" => args
            .iter()
            .all(|a| matches!(a.as_str(), "-a" | "-H" | "-S" | "-aH" | "-aS")),
        "systemctl" => is_read_only_systemctl(args),
        "journalctl" => !args.iter().any(|a| {
            a.starts_with("--vacuum")
                || matches!(
                    a.as_str(),
                    "--rotate"
                        | "--flush"
                        | "--relinquish-var"
                        | "--smart-relinquish-var"
                        | "--sync"
                        | "--setup-keys"
                        | "--update-catalog"
                )
        }),
        "hostnamectl" | "timedatectl" | "localectl" => {
            let pos: Vec<&str> = args
                .iter()
                .map(String::as_str)
                .filter(|a| !a.starts_with('-'))
                .collect();
            !args.iter().any(|a| a.starts_with("--set"))
                && (pos.is_empty()
                    || (pos.len() == 1 && matches!(pos[0], "status" | "show")))
        }
        "resolvectl" => {
            let pos: Vec<&str> = args
                .iter()
                .map(String::as_str)
                .filter(|a| !a.starts_with('-'))
                .collect();
            pos.is_empty()
                || matches!(pos[0], "status" | "statistics")
                || (pos[0] == "query" && pos.len() >= 2)
        }
        "service" => {
            args == ["--status-all"]
                || (args.len() == 2 && !args[0].starts_with('-') && args[1] == "status")
        }
        "ip" => is_read_only_ip(args),
        "ifconfig" => {
            args.is_empty()
                || (args.len() == 1 && (args[0] == "-a" || !args[0].starts_with('-')))
        }
        "route" => args.iter().all(|a| {
            matches!(
                a.as_str(),
                "-n" | "-e" | "-ee" | "-v" | "-4" | "-6" | "-F" | "-C"
            )
        }),
        "docker" | "podman" => is_read_only_docker(args),
        "docker-compose" => is_read_only_compose(args),
        "kubectl" => is_read_only_kubectl(args),
        "crictl" => is_read_only_crictl(args),
        "git" => is_read_only_git(args),
        "dpkg" => args.first().is_some_and(|a| {
            matches!(
                a.as_str(),
                "-l" | "--list"
                    | "-s"
                    | "--status"
                    | "-L"
                    | "--listfiles"
                    | "-S"
                    | "--search"
                    | "--print-architecture"
            )
        }),
        "apt-cache" => args.first().is_some_and(|a| {
            matches!(
                a.as_str(),
                "policy" | "show" | "search" | "madison" | "depends" | "rdepends" | "stats"
            )
        }),
        "rpm" => args.first().is_some_and(|a| {
            (a.starts_with("-q") || a == "--query")
                && !args.iter().any(|x| {
                    matches!(
                        x.as_str(),
                        "-i" | "--install" | "-U" | "--upgrade" | "-e" | "--erase" | "--rebuilddb" | "--initdb"
                    )
                })
        }),
        "nginx" => {
            args.len() == 1 && matches!(args[0].as_str(), "-v" | "-V" | "-t" | "-T")
        }
        "redis-cli" => {
            args == ["ping"]
                || (args.first().map(String::as_str) == Some("info")
                    && args.len() <= 2
                    && args.iter().all(|a| !a.starts_with('-')))
        }
        "python" | "python3" | "node" | "npm" | "pnpm" | "yarn" | "java" | "javac" | "go"
        | "rustc" | "cargo" | "gcc" | "g++" | "clang" | "curl" | "wget" | "openssl" | "ssh"
        | "sshd" | "tar" | "gzip" | "unzip" | "tmux" | "screen" => {
            args.len() == 1
                && matches!(
                    args[0].as_str(),
                    "-v" | "-V" | "--version" | "-version" | "version"
                )
        }
        _ => false,
    }
}

fn is_read_only_systemctl(args: &[String]) -> bool {
    if args.is_empty() {
        // Bare `systemctl` lists active units in systemd (read-only)
        return true;
    }
    if args.iter().any(|a| a.starts_with("--root")) {
        return false;
    }

    let mut subcmd: Option<&str> = None;
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        match a.as_str() {
            "-t" | "--type" | "-p" | "--property" | "-n" | "--lines" | "-o" | "--output"
            | "--state" => {
                skip_next = true;
            }
            s if s.starts_with('-') => {}
            s => {
                subcmd = Some(s);
                break;
            }
        }
    }

    match subcmd {
        Some(sc) => matches!(
            sc,
            "status"
                | "is-active"
                | "is-enabled"
                | "is-failed"
                | "list-units"
                | "list-unit-files"
                | "list-timers"
                | "list-sockets"
                | "list-dependencies"
                | "list-machines"
                | "list-jobs"
                | "show"
                | "cat"
                | "help"
        ),
        None => args
            .iter()
            .any(|a| matches!(a.as_str(), "--version" | "--failed")),
    }
}

fn is_read_only_ip(args: &[String]) -> bool {
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "-4" | "-6" | "-s" | "-stats" | "-statistics" | "-d" | "-details" | "-h"
            | "-human" | "-br" | "-brief" | "-c" | "-color" | "-j" | "-json" | "-p"
            | "-pretty" | "-o" | "-oneline" | "-r" | "-resolve" => {
                idx += 1;
            }
            "-f" | "-family" => {
                if idx + 1 >= args.len() {
                    return false;
                }
                idx += 2;
            }
            "-V" | "-Version" => return idx + 1 == args.len(),
            s if s.starts_with('-') => return false,
            _ => break,
        }
    }

    if idx >= args.len() {
        return false;
    }
    let obj = args[idx].as_str();
    if !matches!(
        obj,
        "a" | "addr"
            | "address"
            | "l"
            | "link"
            | "r"
            | "route"
            | "n"
            | "neigh"
            | "neighbour"
            | "rule"
            | "maddr"
            | "vrf"
            | "netns"
    ) {
        return false;
    }

    if idx + 1 >= args.len() {
        return obj != "netns"; // `ip netns` without subcommand lists netns, allow `ip netns list` below too
    }
    let act = args[idx + 1].as_str();
    matches!(act, "show" | "list" | "lst" | "s" | "l" | "get")
}

fn is_read_only_docker(args: &[String]) -> bool {
    if args.is_empty() {
        return false;
    }
    if args == ["--version"] || args == ["-v"] {
        return true;
    }
    if args.iter().any(|a| {
        matches!(a.as_str(), "-H" | "--host" | "-c" | "--context")
            || a.starts_with("--host=")
            || a.starts_with("--context=")
    }) {
        return false;
    }

    let sub = args[0].as_str();
    if matches!(
        sub,
        "ps" | "images"
            | "logs"
            | "inspect"
            | "stats"
            | "top"
            | "port"
            | "version"
            | "info"
            | "history"
            | "diff"
            | "search"
    ) {
        return true;
    }

    if args.len() < 2 {
        return false;
    }
    let sub2 = args[1].as_str();
    match sub {
        "container" => matches!(
            sub2,
            "ls" | "ps" | "list" | "inspect" | "logs" | "stats" | "top" | "port" | "diff"
        ),
        "image" => matches!(sub2, "ls" | "list" | "inspect" | "history"),
        "volume" | "network" => matches!(sub2, "ls" | "list" | "inspect"),
        "system" => matches!(sub2, "df" | "info"),
        "compose" => is_read_only_compose(&args[1..]),
        _ => false,
    }
}

fn is_read_only_compose(args: &[String]) -> bool {
    if args == ["--version"] || args == ["-v"] {
        return true;
    }
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "-f" | "--file" | "-p" | "--project-name" | "--project-directory" | "--env-file"
            | "--profile" => {
                if idx + 1 >= args.len() {
                    return false;
                }
                idx += 2;
            }
            s if s.starts_with("--file=")
                || s.starts_with("--project-name=")
                || s.starts_with("--project-directory=") =>
            {
                idx += 1;
            }
            s if s.starts_with('-') => return false,
            _ => break,
        }
    }
    if idx >= args.len() {
        return false;
    }
    matches!(
        args[idx].as_str(),
        "ps" | "ls" | "logs" | "config" | "images" | "top" | "version" | "port"
    )
}

fn is_read_only_kubectl(args: &[String]) -> bool {
    if args.iter().any(|a| {
        a == "--kubeconfig"
            || a.starts_with("--kubeconfig=")
            || a == "--server"
            || a.starts_with("--server=")
    }) {
        return false;
    }
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "-n" | "--namespace" | "-o" | "--output" | "-l" | "--selector" => {
                if idx + 1 >= args.len() {
                    return false;
                }
                idx += 2;
            }
            "-A" | "--all-namespaces" => idx += 1,
            s if s.starts_with("--namespace=")
                || s.starts_with("--output=")
                || s.starts_with("--selector=") =>
            {
                idx += 1;
            }
            s if s.starts_with('-') => return false,
            _ => break,
        }
    }
    if idx >= args.len() {
        return false;
    }
    matches!(
        args[idx].as_str(),
        "get"
            | "describe"
            | "logs"
            | "top"
            | "version"
            | "cluster-info"
            | "api-resources"
            | "api-versions"
            | "explain"
            | "events"
    )
}

fn is_read_only_crictl(args: &[String]) -> bool {
    let Some(first) = args.first().map(String::as_str) else {
        return false;
    };
    matches!(
        first,
        "ps" | "pods"
            | "images"
            | "inspect"
            | "inspectp"
            | "inspecti"
            | "logs"
            | "stats"
            | "statsp"
            | "info"
            | "version"
            | "--version"
            | "-v"
    )
}

fn is_read_only_git(args: &[String]) -> bool {
    if args == ["--version"] || args == ["-v"] {
        return true;
    }
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "-C" => {
                if idx + 1 >= args.len() {
                    return false;
                }
                idx += 2;
            }
            "--no-pager" => idx += 1,
            s if s.starts_with('-') => return false,
            _ => break,
        }
    }
    if idx >= args.len() {
        return false;
    }
    let sub = args[idx].as_str();
    let rest = &args[idx + 1..];
    match sub {
        "status" | "log" | "diff" | "show" | "rev-parse" | "ls-files" | "describe"
        | "shortlog" | "blame" => !rest
            .iter()
            .any(|a| a == "--output" || a.starts_with("--output=")),
        "remote" => {
            rest.is_empty()
                || rest == ["-v"]
                || rest == ["--verbose"]
                || rest.first().map(String::as_str) == Some("show")
        }
        "branch" => rest.iter().all(|a| {
            matches!(
                a.as_str(),
                "-a" | "--all"
                    | "-r"
                    | "--remotes"
                    | "-v"
                    | "-vv"
                    | "--list"
                    | "--show-current"
                    | "--merged"
                    | "--no-merged"
            )
        }),
        "tag" => rest.is_empty() || rest == ["-l"] || rest == ["--list"],
        _ => false,
    }
}

fn make_decision(
    requires_approval: bool,
    approval_reason: impl Into<String>,
    matched_policy: &str,
    risk_level: ApprovalRiskLevel,
    category: OperationCategory,
    policy_summary: Option<String>,
) -> ApprovalPolicyDecision {
    ApprovalPolicyDecision {
        requires_approval,
        approval_reason: approval_reason.into(),
        matched_policy: matched_policy.to_string(),
        risk_level,
        category,
        policy_summary,
    }
}
