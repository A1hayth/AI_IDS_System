# -*- coding: utf-8 -*-
"""
AI-IDS 正则特征匹配引擎 (Regex Detection Engine)

基于正则表达式的流量载荷内容扫描引擎，与 XGBoost 统计模型形成双因子协同检测。

设计原则:
    - 独立模块：不依赖 XGBoost 模型，可作为独立检测层或降级方案
    - 高优先级：正则命中意味着已知攻击特征，可信度高于统计推断
    - 可扩展：规则通过 signatures.json 加载，支持热更新
    - 异常隔离：单条规则/载荷解析失败不影响整体检测流程

内置规则覆盖:
    - SQL 注入 (SQLi): UNION SELECT, OR 1=1, AND SLEEP, 注释符等
    - 跨站脚本 (XSS): <script>, onerror=, javascript: 等
    - 路径遍历: ../, ..\\, /etc/passwd 等
    - WebShell: eval($_POST, system(), exec() 等
    - 命令注入: ;wget, |bash, `cmd` 等
    - 文件包含: php://input, expect:// 等
    - XXE: <!ENTITY, SYSTEM "file:// 等
    - 扫描探测: nikto, sqlmap, dirbuster User-Agent

用法:
    from src.ai_engine.regex_detector import RegexDetector

    detector = RegexDetector()
    result = detector.analyze_payload({
        "uri": "/products.php?id=1 UNION SELECT NULL--",
        "body": "",
        "user_agent": "Mozilla/5.0",
        "method": "GET",
    })
    if result["is_attack"]:
        print(f"检测到 {result['type']}: {result['matched']}")
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 路径注入
# ---------------------------------------------------------------------------
_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_logger = logging.getLogger("regex_detector")
_logger.setLevel(logging.DEBUG)
if not _logger.handlers:
    _ch = logging.StreamHandler(sys.stdout)
    _ch.setLevel(logging.INFO)
    _ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S"))
    _logger.addHandler(_ch)

# ---------------------------------------------------------------------------
# 内置正则规则库
# ---------------------------------------------------------------------------

BUILTIN_RULES: List[Dict[str, Any]] = [
    # ======================== SQL 注入 (SQLi) ========================
    {
        "id": "SQLI-001",
        "name": "UNION SELECT 注入",
        "type": "SQL Injection",
        "severity": "HIGH",
        "patterns": [
            r"(?i)UNION\s+(ALL\s+)?SELECT\b",
            r"(?i)UNION\s+(ALL\s+)?SELECT\s+(NULL|CHAR|0x)",
        ],
        "description": "检测 UNION SELECT 联合查询注入",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "SQLI-002",
        "name": "布尔/时间盲注",
        "type": "SQL Injection",
        "severity": "HIGH",
        "patterns": [
            r"(?i)OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
            r"(?i)AND\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
            r"(?i)AND\s+SLEEP\s*\(\s*\d+\s*\)",
            r"(?i)OR\s+SLEEP\s*\(\s*\d+\s*\)",
            r"(?i)BENCHMARK\s*\(\s*\d+\s*,\s*MD5\s*\([^)]+\)\s*\)",
            r"(?i)WAITFOR\s+DELAY\s+",
        ],
        "description": "检测布尔盲注和时间盲注",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "SQLI-003",
        "name": "SQL 注释绕过",
        "type": "SQL Injection",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)--[-\s]*$",
            r"(?i)#\s*$",
            r"/\*!.*?\*/",
            r"(?i)['\"]\s*--\s*",
        ],
        "description": "检测 SQL 行注释和特殊注释绕过",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "SQLI-004",
        "name": "系统表/过程访问",
        "type": "SQL Injection",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(INFORMATION_SCHEMA|mysql\.|sys\.|pg_)",
            r"(?i)(xp_cmdshell|sp_executesql|xp_reg)",
            r"(?i)(sqlmap|sql注入)",
        ],
        "description": "检测对数据库系统表/存储过程的访问",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "SQLI-005",
        "name": "万能密码/认证绕过",
        "type": "SQL Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)['\"]\s*OR\s+['\"]\s*=\s*['\"]",
            r"(?i)['\"]\s*OR\s+1\s*=\s*1\s*--",
            r"(?i)admin['\"]\s*--",
            r"(?i)or\s+true\s*=\s*true",
        ],
        "description": "检测经典万能密码和认证绕过",
        "target_fields": ["uri", "body", "payload"],
    },

    # ======================== 跨站脚本 (XSS) ========================
    {
        "id": "XSS-001",
        "name": "Script 标签注入",
        "type": "Cross-Site Scripting",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)<script[^>]*/?>",
            r"(?i)<script[^>]*src\s*=",
        ],
        "description": "检测 <script> 标签注入",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "XSS-002",
        "name": "事件处理器 XSS",
        "type": "Cross-Site Scripting",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)on(error|load|click|mouse|focus|blur|submit|change|key)\s*=",
            r"(?i)on\w+\s*=\s*['\"]?\s*(alert|prompt|confirm|eval)\b",
        ],
        "description": "检测 onerror/onload 等事件处理器注入",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "XSS-003",
        "name": "伪协议/编码 XSS",
        "type": "Cross-Site Scripting",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)javascript\s*:",
            r"(?i)data\s*:\s*text/html",
            r"(?i)vbscript\s*:",
            r"%3Cscript%3E",
            r"(?i)<svg[^>]*onload\s*=",
            r"(?i)<img[^>]*onerror\s*=",
        ],
        "description": "检测 javascript: 伪协议、data URI、编码绕过和 SVG/IMG 注入",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "XSS-004",
        "name": "DOM XSS 源/汇",
        "type": "Cross-Site Scripting",
        "severity": "LOW",
        "patterns": [
            r"(?i)(document\.(write|cookie|domain|url|referrer)|window\.(location|name)|eval\s*\(|setTimeout\s*\(|setInterval\s*\()",
        ],
        "description": "检测潜在 DOM XSS 源和汇（需结合上下文判断）",
        "target_fields": ["uri", "body", "payload"],
    },

    # ======================== 路径遍历 ========================
    {
        "id": "PT-001",
        "name": "目录遍历",
        "type": "Path Traversal",
        "severity": "HIGH",
        "patterns": [
            r"\.\./\.\./",
            r"\.\.\\\.\.\\",
            r"\.\.%2f\.\.%2f",
            r"\.\.%5c\.\.%5c",
            r"\.\.;/\.\.;/",
        ],
        "description": "检测 ../ 目录遍历攻击",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "PT-002",
        "name": "敏感文件访问",
        "type": "Path Traversal",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)/etc/(passwd|shadow|hosts|group)",
            r"(?i)(C:\|/Windows/System32/)",
            r"(?i)(win\.ini|boot\.ini)",
            r"(?i)/proc/self/environ",
            r"(?i)WEB-INF/web\.xml",
            r"(?i)\.env\b",
            r"(?i)\.git/(config|HEAD)",
        ],
        "description": "检测对系统敏感文件的直接访问",
        "target_fields": ["uri", "body", "payload"],
    },

    # ======================== WebShell ========================
    {
        "id": "WS-001",
        "name": "PHP WebShell",
        "type": "WebShell",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[",
            r"(?i)assert\s*\(\s*\$_(POST|GET|REQUEST)\s*\[",
            r"(?i)system\s*\(\s*\$_(POST|GET|REQUEST)\s*\[",
            r"(?i)exec\s*\(\s*\$_(POST|GET|REQUEST)\s*\[",
            r"(?i)passthru\s*\(\s*\$_(POST|GET|REQUEST)\s*\[",
            r"(?i)shell_exec\s*\(\s*\$_(POST|GET|REQUEST)\s*\[",
            r"(?i)`\s*\$_(POST|GET|REQUEST)\s*\[",
            r'(?i)\$_(POST|GET|REQUEST)\s*\[\s*["\'].*?["\']\s*\]\s*\(\s*\$_(POST|GET|REQUEST)\s*\[',
        ],
        "description": "检测 PHP 一句话木马和 WebShell 特征",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "WS-002",
        "name": "命令执行函数",
        "type": "WebShell",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*['\"]?(whoami|id|uname|ls|dir|cat|wget|curl|ifconfig|ipconfig)",
            r"(?i)(system|exec|passthru|shell_exec)\s*\(\s*['\"].*?[/\\]",
        ],
        "description": "检测直接命令执行函数调用",
        "target_fields": ["uri", "body", "payload"],
    },
    {
        "id": "WS-003",
        "name": "中国菜刀/蚁剑/冰蝎",
        "type": "WebShell",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(chopper|caidao|antsword|behinder|godzilla)",
            r'(?i)@ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']0["\']\s*\)',
            r"(?i)base64_decode\s*\(\s*\$_(POST|GET|REQUEST)\s*\[",
        ],
        "description": "检测常见 WebShell 管理工具特征",
        "target_fields": ["uri", "body", "payload"],
    },

    # ======================== 命令注入 ========================
    {
        "id": "CI-001",
        "name": "Shell 命令注入",
        "type": "Command Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i);\s*(wget|curl|nc|bash|sh|powershell|cmd)\s+",
            r"(?i)\|\s*(wget|curl|nc|bash|sh|powershell|cmd)\b",
            r"(?i)`[^`]*(wget|curl|cat|ls|id|whoami)[^`]*`",
            r'(?i)\$\(\s*(wget|curl|cat|ls|id|whoami)',
        ],
        "description": "检测 Shell 命令注入（管道、命令替换）",
        "target_fields": ["uri", "body", "payload"],
    },

    # ======================== 文件包含 ========================
    {
        "id": "FI-001",
        "name": "本地/远程文件包含",
        "type": "File Inclusion",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(php|expect|glob|phar|ogg|data|zip|ftp|http|https)://(input|filter)",
            r"(?i)php://filter/convert\.base64-encode/resource=",
            r"(?i)expect://(whoami|id|ls|cat)",
            r"(?i)\.\./\.\./.*?\.php%00",
        ],
        "description": "检测 PHP LFI/RFI 攻击",
        "target_fields": ["uri", "body", "payload"],
    },

    # ======================== XXE ========================
    {
        "id": "XXE-001",
        "name": "XML 外部实体注入",
        "type": "XXE Injection",
        "severity": "HIGH",
        "patterns": [
            r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"]file://",
            r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"]http://",
            r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"]expect://",
            r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"]php://",
        ],
        "description": "检测 XML 外部实体注入 (XXE)",
        "target_fields": ["body", "payload"],
    },

    # ======================== 扫描探测 ========================
    {
        "id": "SCAN-001",
        "name": "自动化扫描工具",
        "type": "Scanning Probe",
        "severity": "LOW",
        "patterns": [
            r"(?i)(sqlmap|nikto|nessus|acunetix|appscan|burpsuite|w3af|nmap|masscan|dirbuster|gobuster|hydra|medusa)",
            r"(?i)(zgrab|zgrab2|whatweb|wappalyzer)",
        ],
        "description": "检测常见自动化安全扫描工具 User-Agent",
        "target_fields": ["user_agent", "payload"],
    },
    {
        "id": "SCAN-002",
        "name": "扫描路径探测",
        "type": "Scanning Probe",
        "severity": "LOW",
        "patterns": [
            r"(?i)^/(admin|wp-admin|phpmyadmin|\.env|\.git|config|backup)/?",
            r"(?i)^/(wp-login|administrator|manager|jenkins)/?",
        ],
        "description": "检测常见管理后台/敏感路径探测",
        "target_fields": ["uri"],
    },
]


# ============================================================================
# RegexDetector
# ============================================================================

class RegexDetector:
    """基于正则表达式的流量载荷检测引擎。

    与 XGBoost 统计模型形成互补:
        - XGBoost: 检测流层统计异常 (DoS/DDoS/PortScan/Bot)
        - RegexDetector: 检测应用层攻击载荷 (SQLi/XSS/WebShell/Path Traversal)

    使用示例::

        detector = RegexDetector()
        result = detector.analyze_payload({
            "uri": "/products.php?id=1 UNION SELECT NULL--",
            "body": "username=admin' OR '1'='1",
            "user_agent": "Mozilla/5.0",
            "method": "GET",
        })
        # result = {"is_attack": True, "type": "SQL Injection", "matched": "...", ...}
    """

    def __init__(
        self,
        rules: Optional[List[Dict[str, Any]]] = None,
        signatures_path: Optional[str] = None,
        enable_builtin: bool = True,
    ) -> None:
        """初始化正则检测引擎。

        Args:
            rules: 自定义规则列表。若为 None，从 signatures.json 或内置规则加载。
            signatures_path: 签名 JSON 文件路径。
            enable_builtin: 是否加载内置规则库。
        """
        self._rules: List[Dict[str, Any]] = []
        self._compiled: List[Dict[str, Any]] = []
        self._enabled: bool = True
        self._stats: Dict[str, int] = {"scanned": 0, "matched": 0, "errors": 0}

        # 加载签名文件
        if signatures_path:
            loaded = self._load_signatures_file(signatures_path)
            if loaded:
                self._rules.extend(loaded)
                _logger.info("从 %s 加载了 %d 条规则", signatures_path, len(loaded))

        # 加载内置规则
        if enable_builtin and not self._rules:
            self._rules = list(BUILTIN_RULES)
            _logger.info("加载内置规则库: %d 条", len(self._rules))

        # 加载自定义规则
        if rules:
            self._rules.extend(rules)
            _logger.info("加载自定义规则: %d 条", len(rules))

        # 编译所有正则
        self._compile_rules()

    # ==================================================================
    # 规则加载
    # ==================================================================

    def _load_signatures_file(self, path: str) -> Optional[List[Dict[str, Any]]]:
        """从 signatures.json 加载规则定义。

        文件格式:
            {
                "rules": [
                    {
                        "id": "CUSTOM-001",
                        "name": "...",
                        "type": "...",
                        "severity": "HIGH",
                        "patterns": ["regex1", "regex2"],
                        "description": "...",
                        "target_fields": ["uri", "body"]
                    }
                ]
            }
        """
        try:
            if not os.path.exists(path):
                _logger.warning("签名文件不存在: %s", path)
                return None
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            rules = data.get("rules", [])
            _logger.info("从 %s 加载了 %d 条自定义规则", path, len(rules))
            return rules
        except json.JSONDecodeError as e:
            _logger.error("签名文件 JSON 解析失败: %s", e)
            return None
        except Exception as e:
            _logger.error("加载签名文件异常: %s", e)
            return None

    def _compile_rules(self) -> None:
        """预编译所有规则的正则表达式。"""
        self._compiled = []
        compile_errors = 0
        for rule in self._rules:
            compiled_patterns = []
            for pat in rule.get("patterns", []):
                try:
                    compiled_patterns.append(re.compile(pat))
                except re.error as e:
                    _logger.warning("规则 %s 正则编译失败: %s → %s", rule.get("id"), pat, e)
                    compile_errors += 1
            if compiled_patterns:
                rule_copy = dict(rule)
                rule_copy["_compiled"] = compiled_patterns
                self._compiled.append(rule_copy)
        if compile_errors:
            _logger.warning("共 %d 个正则编译失败", compile_errors)

    def reload_rules(self, rules: Optional[List[Dict[str, Any]]] = None,
                     signatures_path: Optional[str] = None) -> int:
        """重新加载规则（支持热更新）。

        Returns:
            成功编译的规则数量。
        """
        self._rules = []
        self._compiled = []
        if signatures_path:
            loaded = self._load_signatures_file(signatures_path)
            if loaded:
                self._rules.extend(loaded)
        if rules:
            self._rules.extend(rules)
        if not self._rules:
            self._rules = list(BUILTIN_RULES)
        self._compile_rules()
        return len(self._compiled)

    # ==================================================================
    # 核心检测
    # ==================================================================

    def analyze_payload(self, payload_data: Dict[str, Optional[str]]) -> Dict[str, Any]:
        """对载荷数据进行正则特征扫描。

        Args:
            payload_data: 载荷数据字典，应包含以下可选字段:
                - uri:        HTTP 请求 URI (如 /products.php?id=1)
                - body:       HTTP 请求体 / POST 数据
                - payload:    原始载荷（兜底字段）
                - method:     HTTP 方法 (GET/POST/...)
                - user_agent: User-Agent 头
                - host:       HTTP Host 头

        Returns:
            {
                "is_attack": bool,          # 是否命中攻击规则
                "type": str,                # 攻击类型（命中时）
                "rule_id": str,             # 命中的规则 ID（命中时）
                "rule_name": str,           # 规则名称（命中时）
                "severity": str,            # 严重程度 (CRITICAL/HIGH/MEDIUM/LOW)
                "matched": str,             # 匹配到的明文片段（截断 200 字符）
                "description": str,         # 规则描述（命中时）
                "all_matches": list[dict],  # 全部命中规则列表
            }
        """
        if not self._enabled:
            return self._empty_result()

        self._stats["scanned"] += 1
        all_matches: List[Dict[str, Any]] = []

        # 构建待扫描文本（合并所有目标字段）
        scan_targets = self._build_scan_targets(payload_data)

        # 逐规则扫描
        for rule in self._compiled:
            target_fields = rule.get("target_fields", ["uri", "body", "payload"])
            for field_name in target_fields:
                text = scan_targets.get(field_name, "")
                if not text:
                    continue
                try:
                    for pat in rule.get("_compiled", []):
                        match = pat.search(text)
                        if match:
                            matched_text = match.group(0)
                            all_matches.append({
                                "rule_id": rule.get("id", ""),
                                "rule_name": rule.get("name", ""),
                                "type": rule.get("type", "Unknown"),
                                "severity": rule.get("severity", "MEDIUM"),
                                "description": rule.get("description", ""),
                                "matched": matched_text[:200],
                                "field": field_name,
                            })
                            break  # 同一规则在同一字段只需一次命中
                except Exception:
                    _logger.debug("规则 %s 在字段 %s 扫描异常", rule.get("id"), field_name)
                    self._stats["errors"] += 1

        if all_matches:
            self._stats["matched"] += 1
            # 取最高严重度的命中作为首要结果
            primary = self._select_primary_match(all_matches)
            return {
                "is_attack": True,
                "type": primary["type"],
                "rule_id": primary["rule_id"],
                "rule_name": primary["rule_name"],
                "severity": primary["severity"],
                "matched": primary["matched"],
                "description": primary["description"],
                "all_matches": all_matches,
            }

        return self._empty_result()

    def analyze_batch(self, payloads: List[Dict[str, Optional[str]]]) -> List[Dict[str, Any]]:
        """批量扫描多条载荷。"""
        return [self.analyze_payload(p) for p in payloads]

    # ==================================================================
    # 属性
    # ==================================================================

    @property
    def rule_count(self) -> int:
        """已编译的有效规则数量。"""
        return len(self._compiled)

    @property
    def stats(self) -> Dict[str, int]:
        """检测统计。"""
        return dict(self._stats)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    # ==================================================================
    # 内部方法
    # ==================================================================

    def _build_scan_targets(self, payload_data: Dict[str, Optional[str]]) -> Dict[str, str]:
        """构建扫描目标文本字典，处理 None 值和 URL 解码。"""
        targets: Dict[str, str] = {}
        field_map = {
            "uri": ["uri", "http_uri"],
            "body": ["body", "post_data", "form_data"],
            "payload": ["payload", "raw_payload"],
            "user_agent": ["user_agent", "ua"],
            "method": ["method", "http_method"],
            "host": ["host", "http_host"],
        }
        for target_key, source_keys in field_map.items():
            value = ""
            for sk in source_keys:
                raw = payload_data.get(sk, "")
                if raw:
                    value = str(raw)
                    break
            # 尝试 URL 解码
            if value and "%" in value:
                try:
                    from urllib.parse import unquote
                    value = unquote(value, errors="replace")
                except Exception:
                    pass
            targets[target_key] = value
        return targets

    @staticmethod
    def _empty_result() -> Dict[str, Any]:
        return {
            "is_attack": False,
            "type": "",
            "rule_id": "",
            "rule_name": "",
            "severity": "LOW",
            "matched": "",
            "description": "",
            "all_matches": [],
        }

    @staticmethod
    def _select_primary_match(matches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """从多个命中中选取首要结果（严重度优先）。"""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return min(matches, key=lambda m: severity_order.get(m.get("severity", "LOW"), 99))


# ============================================================================
# 便捷函数
# ============================================================================

def create_detector(signatures_path: Optional[str] = None) -> RegexDetector:
    """工厂函数：创建并返回预初始化的 RegexDetector。

    Args:
        signatures_path: 自定义签名文件路径。若为 None，自动搜索:
            1. models/signatures.json
            2. config/signatures.json

    Returns:
        初始化完成的 RegexDetector 实例。
    """
    if signatures_path is None:
        # 自动搜索
        candidates = [
            os.path.join(_PROJECT_DIR, "models", "signatures.json"),
            os.path.join(_PROJECT_DIR, "config", "signatures.json"),
            os.path.join(_PROJECT_DIR, "signatures.json"),
        ]
        for cand in candidates:
            if os.path.exists(cand):
                signatures_path = cand
                break

    return RegexDetector(signatures_path=signatures_path, enable_builtin=True)


# ============================================================================
# 自测
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  RegexDetector — 自测")
    print("=" * 60)

    detector = RegexDetector()

    test_cases = [
        # SQLi
        ({"uri": "/products.php?id=1 UNION SELECT NULL--", "method": "GET"},
         "SQL Injection"),
        ({"body": "username=admin' OR '1'='1", "method": "POST"},
         "SQL Injection"),
        ({"uri": "/?id=1 AND SLEEP(5)", "method": "GET"},
         "SQL Injection"),

        # XSS
        ({"uri": "/?q=<script>alert(1)</script>", "method": "GET"},
         "Cross-Site Scripting"),
        ({"body": "comment=<img src=x onerror=alert('XSS')>", "method": "POST"},
         "Cross-Site Scripting"),

        # Path Traversal
        ({"uri": "/../../../etc/passwd", "method": "GET"},
         "Path Traversal"),
        ({"uri": "/.env", "method": "GET"},
         "Path Traversal"),

        # WebShell
        ({"body": "<?php eval($_POST['cmd']);?>", "method": "POST"},
         "WebShell"),

        # Command Injection
        ({"uri": "/ping?ip=127.0.0.1;cat /etc/passwd", "method": "GET"},
         "Command Injection"),

        # Scanning
        ({"user_agent": "sqlmap/1.7.10#stable", "uri": "/", "method": "GET"},
         "Scanning Probe"),

        # Normal traffic (should NOT trigger)
        ({"uri": "/index.html", "method": "GET",
          "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"},
         "BENIGN"),
    ]

    print(f"\n已加载 {detector.rule_count} 条规则\n")
    passed = 0
    failed = 0

    for payload, expected in test_cases:
        result = detector.analyze_payload(payload)
        actual = result["type"] if result["is_attack"] else "BENIGN"
        ok = (expected == actual) or (expected != "BENIGN" and result["is_attack"])
        status = "[PASS]" if ok else "[FAIL]"
        if ok:
            passed += 1
        else:
            failed += 1

        print(f"  {status} expected={expected:<25s} actual={actual:<25s} "
              f"rule={result.get('rule_id', '-'):<12s} matched='{result.get('matched', '')[:60]}'")

    print(f"\n  Result: {passed}/{passed+failed} passed")
    print(f"  Stats: scanned={detector.stats['scanned']} "
          f"matched={detector.stats['matched']} errors={detector.stats['errors']}")
    print("=" * 60)
