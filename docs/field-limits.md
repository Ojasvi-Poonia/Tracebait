# Field limits

Why each entry in `src/tracebait/data/fields.json` has the length limit, character set and
placement it has. Payloads must fit these so that a poisoned log record is one a real
attacker could produce and that a real logger would store intact.

Researched on 2026-11-02 from primary sources (Microsoft Learn, SysmonCommon source, IETF
RFCs, Elastic ECS and Beats code, AWS API and CloudTrail docs, and sample records from OTRF
Security-Datasets and splunk/attack_data). Five AI-assisted research passes each covered one
field family; a separate AI-assisted verification pass then re-checked every number and
character class and corrected
the ones listed under each family below. "Unverified" items are open questions, not facts.

Where the evidence below says to update or patch a mirrored copy of a value (for example
the command line repeated in an OTRF `Message`), tracebait instead requires packs to drop
that copy: `make_twin` refuses an incident that repeats the target value elsewhere, because
a poisoned field next to an unpoisoned copy would contradict itself.

## Fields in the registry

| Field | Limit | Unit | Placement | Confidence |
|---|---|---|---|---|
| `process.command_line` | 8191 | utf16_units | append | medium |
| `process.parent.command_line` | 8191 | utf16_units | append | medium |
| `user_agent.original` | 8000 | utf8_bytes | append | high |
| `aws.cloudtrail.user_agent` | 1000 | utf8_bytes | append | medium |
| `dns.question.name` | 253, segments of at most 63 | code_points | prepend | high |
| `file.name` | 255 | utf16_units | prepend | high |
| `aws.cloudtrail.request_parameters.roleSessionName` | 64 | code_points | append | high |
| `aws.cloudtrail.request_parameters.sourceIdentity` | 64 | code_points | append | medium |
| `aws.cloudtrail.request_parameters.userName` | 64 | code_points | append | high |
| `aws.cloudtrail.request_parameters.groupDescription` | 255 | code_points | append | high |
| `aws.cloudtrail.request_parameters.description` | 256 | code_points | append | medium |

### `process.command_line`

**Registry summary.** 8,191 UTF-16 units: cmd.exe caps a command line at 8,191 and Elastic logsdb (the default for logs-* from Elasticsearch 9.0) does not index longer values. CreateProcessW allows 32,766 and Sysmon EID 1 keeps about 30,000, so 8,191 survives every Windows launch path and every Elastic store. Splunk's default TRUNCATE (10,000 bytes per raw XML event) can bind lower for splunk/attack_data packs, and Security 4688 is verified intact only to 5,137. NUL is impossible; other C0 controls except TAB/LF, CR, C1 and U+FFFD-U+FFFF are not logged faithfully. OTRF JSON repeats the command line in Message, so packs must drop Message (make_twin refuses incidents that repeat the target value).

**Character class:** `[^\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff\ufffd-\uffff]`

**Where it appears:**

- ecs: `process.command_line` (ECS process events. The Winlogbeat sysmon module (also used by the Elastic Agent windows integration) renames Sysmon EID 1 winlog.event_data.CommandLine to this field. The Winlogbeat security module's Painless script 'Process Event 4688' copies the 4688 CommandLine here and splits it into process.args. Elastic Defend and auditbeat set it on Linux.)
- ecs: `winlog.event_data.CommandLine` (Raw Winlogbeat event_data before the ingest-pipeline rename (Sysmon EID 1, Security 4688))
- sysmon: `CommandLine` (Sysmon EID 1 (ProcessCreate). OTRF Security-Datasets JSON (NXLog im_msvistalog through Logstash) has a top-level key "CommandLine" that is repeated verbatim inside "Message". Windows Event XML and splunk/attack_data use <Data Name='CommandLine'>.)
- windows_security: `CommandLine` (Security 4688, display name 'Process Command Line'. Present from event version 1 (Win 8.1 / 2012 R2) onward and empty unless the 'Include command line in process creation events' GPO is enabled. OTRF JSON key "CommandLine", also repeated in Message. XML <Data Name='CommandLine'>.)

**Length evidence (verified):**

Units are UTF-16 code units of the unescaped value, which equals characters for BMP text. In Python, count len(s.encode('utf-16-le'))//2. Elasticsearch ignore_above compares Java String.length(), the same unit. Each limit below was re-verified on 2026-11-02, loosest first.
(1) CreateProcessW lpCommandLine is at most 32,767 characters including the terminating NUL, so 32,766 usable.
(2) Sysmon EID 1 (SysmonCommon eventsCommon.cpp at 6678ccf): trimming starts only when the summed EVENT_DATA_DESCRIPTOR sizes exceed MAX_EVENT_PACKET_SIZE = 62,000 bytes. Each string costs 2*(len+1) bytes; add 3 GUIDs x 16, 2 PIDs x 4, LogonId 8 and TerminalSessionId 4. The intact ceiling is floor((62000 - other_bytes - 2*(len(ParentCommandLine)+1))/2) - 1. That gives 30,395 for the OTRF empire_launcher_vbs record (1,056 other bytes, 75-character parent, no ParentUser field), or about 30,378 if a 17-character ParentUser is added.
(3) Security 4688 has no documented limit. It was verified intact at 5,137 characters in OTRF empire_launcher_vbs. Longer values are unverified, and a 2020 Hexacorn report says a very long command line produced no 4688 event at all.
(4) cmd.exe allows 8,191 characters (KB830473) for any command line typed at a prompt or run from a batch file.
(5) Elastic logsdb uses ignore_above 8191 for wildcard. A longer value is still stored in _source or synthetic source but is not indexed, so it is a searchability limit, not truncation.
The 8,191 cap is the conservative value: it is plausible for every launch path and fully indexed in every Elastic mode. It is NOT end-to-end safe for Splunk replays. With the default TRUNCATE = 10,000 bytes per line, the measured splunk/attack_data T1003.001 EID 1 records leave only 5,299-8,066 UTF-8 bytes (median 8,066) for the XML-escaped CommandLine once the rest of the event is counted. For Splunk targets tracebait must also enforce: serialized physical line <= 10,000 UTF-8 bytes, counting &amp;/&lt;/&gt; expansion and ParentCommandLine. Alternatively it can set TRUNCATE = 0 for the replay sourcetype. A ceiling of about 30,000 is physically possible only for direct (non-cmd) CreateProcess launches logged by Sysmon and replayed outside Splunk defaults.

**Character evidence:**

This class compiles in Python re as a single IN class (checked with sre_parse). Literal U+FFFE/U+FFFF characters were replaced with escapes, and U+FFFD is now excluded. What each range covers:
(1) NUL is impossible. lpCommandLine is NUL-terminated, and Sysmon sizes fields with _tcslen.
(2) Other UTF-16 text is allowed. CreateProcessW takes Unicode, and Sysmon and 4688 log win:UnicodeString.
(3) C0 controls other than TAB and LF are excluded. libbeat safe_reader.go, used by Winlogbeat and Elastic Agent, rewrites every rune where unicode.IsControl is true and unicode.IsSpace is false as the literal text \uNNNN. VT (0x0b) and FF (0x0c) count as spaces, so they pass the reader, but Go encoding/xml then rejects them as illegal XML 1.0 characters. TAB, LF and CR are left alone (beats PR 11357). LF was verified surviving raw in attack_data XML: 4 command lines span several physical lines.
(4) CR is excluded because the Go XML decoder normalises a raw CR in element text to LF (noted in PR 11357), and EvtRender's CR encoding is unverified.
(5) DEL and C1 (0x7f-0x9f) are excluded on evidence, not just as a precaution. They match unicode.IsControl and are escaped. Because the reader advances one byte, a 2-byte C1 character becomes the 12-character text \u0080\ufffd. NEL U+0085 passes Winlogbeat but stays excluded because NXLog and Splunk behaviour is unknown.
(6) U+FFFD is excluded. SafeReader treats it as utf8.RuneError, and per a code reading (not executed) it turns into the text \ufffd three times.
(7) Lone surrogates and U+FFFE/U+FFFF are excluded: they are not valid UTF-8 or XML 1.0 characters.
No control or non-ASCII characters were observed in the OTRF or attack_data command lines.

**Attacker control:**

The attacker has full control. Whoever calls CreateProcess, WMI Win32_Process.Create, PowerShell Start-Process or WScript.Shell.Run chooses the whole command line, including trailing arguments that most programs ignore. That makes appending to the original realistic. Constraints:
- If lpApplicationName is NULL, the first token (module name) is limited to MAX_PATH.
- Anything launched through cmd.exe, a .bat file or an interactive prompt is limited to 8,191 characters.
- The OS may prepend a fully qualified path to the image name.
Logging is gated. 4688 carries the command line only when the 'Include command line in process creation events' GPO is enabled. A Sysmon <FieldSizes> entry CommandLine:N (applied by field name) truncates to exactly N characters, the last 3 being '...'. The default is NO_MAX_LENGTH, which means no limit.

**Truncation and ingest:**

Sysmon (SysmonCommon eventsCommon.cpp):
- <FieldSizes> trimming via TrimStringToNChars runs first: N characters total, ending '...'.
- Then, for EID 1 only, if the descriptor exceeds 62,000 bytes, ParentCommandLine is trimmed first and CommandLine second via TrimStringByNChars. Each is cut by the byte excess / 2 characters, with a floor of MAX_PATH + 3 = 263 characters ending '...'. The event is kept, but its tail is lost.
- The code comment says the old 8K truncation was removed because it 'can be exploited to hide the command line'. The comment says '64000 characters', but the ETW limit is 64KB minus header, in bytes (EventWrite returns ERROR_ARITHMETIC_OVERFLOW).
- The same file defines PATH_MAX_SIZE = 31839 and TrimStringIfNeeded, citing the ReportEvent per-string limit, but nothing in the common code calls it.
- Correction: ReportEvent's 31,839-character limit applies to Vista and later (pre-Vista was 32K), and Sysmon uses EventWrite on Vista and later.
XML (EvtRender and attack_data):
- &, < and > are escaped as entities; &amp; and &gt; were observed. Quotes are not escaped in element text, and attributes use single quotes.
- Correction: attack_data is NOT strictly one <Event> per line. T1003.001 windows-sysmon.log has 7,960 events on 7,975 lines because LF inside CommandLine is written raw. Split on '\n(?=<Event xmlns)'.
- The longest event is 7,486 bytes, not counting the newline.
- attack_data replays through HEC /services/collector/raw with sourcetype XmlWinEventLog, so parse-time props apply.
- TRUNCATE defaults to 10,000 bytes per line after LINE_BREAKER and rounds down to a character boundary.
- The 2016 TA-microsoft-sysmon 3.2.1 props.conf has no TRUNCATE override. The current Splunk_TA_windows and Splunk_TA_microsoft_sysmon are unverified.
OTRF JSON:
- Top-level CommandLine is repeated verbatim in Message (verified in 5 of 5 EID 1 and 5 of 5 4688 records). Update both.
- The maximum CommandLine is 5,137 characters, ASCII only.
- Records with a 5,137-character command line are about 13.3 KB, already over Splunk's default TRUNCATE, so a Splunk replay of OTRF JSON needs TRUNCATE raised.
Elastic:
- ECS 9.6.0-dev process.yml, the generated component template and ecs@mappings (ecs_match_wildcard_and_match_only_text on *command_line) all map it as wildcard plus .text match_only_text, with no ignore_above.
- Wildcard ignore_above defaults to 2147483647 in standard indices, documented as 'so that all values would be accepted', and to 8191 in logsdb (Mapper.IgnoreAbove).
- Over the limit, WildcardFieldMapper calls addIgnoredField and stores the raw value for synthetic source.
- logsdb is automatic only for NEW logs-*-* data streams on 9.0+ and on Serverless. That covers the Elastic Agent logs-windows.* streams, but standalone Winlogbeat's default winlogbeat-* index stays in standard mode unless configured.
- match_only_text has no ignore_above, so .text stays searchable (not tested).
- process.args is keyword with ignore_above 1024.
- The Winlogbeat sysmon and security pipelines have no truncate processor.
Linux:
- MAX_ARG_STRLEN = PAGE_SIZE*32 (131,072 bytes including NUL on 4K pages).
- argv plus envp is limited to 1/4 of RLIMIT_STACK and also to 3/4 of _STK_LIM (6 MiB) (execve(2)).
- auditd EXECVE logs each argument separately. Arguments over 7,500 bytes (MAX_EXECVE_AUDIT_LEN) are split into aN_len / aN[i] chunks and forced to hex.
- Hex is also used when an argument contains '"', any byte < 0x21 (space included) or any byte > 0x7e (audit_string_contains_control).
- ECS process.command_line on Linux is a reconstruction.

**Unverified:**

- Security 4688 above 5,137 characters. That length is verified intact in OTRF. Hexacorn (2020, unreachable; search snippet only) reports the event was missed entirely for a very long command line, length unknown. Best bounded estimate: intact to at least 8,191 and probably to about 31,000 under the 64KB event-size reasoning. Treat 8,192-32,766 as risky.
- Whether the shipping Windows Sysmon binary matches SysmonCommon: the 62,000-byte budget, parent trimmed first, and no call to TrimStringIfNeeded (PATH_MAX_SIZE 31839). Even if TrimStringIfNeeded is called, 31,839 is above the roughly 30.4K budget ceiling, so the bound does not change. Older Sysmon had a 0x2000-character truncation, reportedly fixed on 2018-07-06 (search snippet only).
- Whether the current Splunk_TA_windows or Splunk_TA_microsoft_sysmon overrides TRUNCATE or LINE_BREAKER for XmlWinEventLog. Only an old 2016 fork without an override was readable. How Splunk line-breaks attack_data events that contain a raw LF is also unverified.
- Whether EvtRender emits a raw CR or &#xD;, and how NXLog im_msvistalog (the OTRF collector) handles C0, DEL, C1 and U+FFFD.
- How U+FFFD and C1 characters come out of Winlogbeat's SafeReader. This was derived from reading the Go code (one-byte advance after an escape), not from running it.
- Whether the match_only_text .text multi-field indexes values over 8191 characters in logsdb. Inferred yes, because ignore_above is not a text-field parameter, but not tested.
- EVTX chunk overhead (64KB chunk including binxml template) for a Sysmon EID 1 event near 62,000 bytes of payload. Not checked.

**Sources:**

- <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw>: lpCommandLine is at most 32,767 characters including the Unicode terminating NUL; the module name is limited to MAX_PATH when lpApplicationName is NULL; the OS may prepend a fully qualified path
- <https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation>: cmd.exe maximum string length 8191 characters for command lines, batch files and environment variable expansion (KB830473)
- <https://github.com/microsoft/SysmonCommon/blob/main/eventsCommon.cpp>: MAX_EVENT_PACKET_SIZE 62000; EID 1 trims ParentCommandLine then CommandLine via TrimStringByNChars (floor MAX_PATH+3 = 263, ending '...'); TrimStringToNChars for FieldSizes; comment that 8K truncation was removed; PATH_MAX_SIZE 31839 and TrimStringIfNeeded defined but not called in common code (commit 6678ccf, 2026-09-14)
- <https://github.com/microsoft/SysmonCommon/blob/main/manifest.xml>: EID 1 field list and inTypes for schema 4.90 (UnicodeString, 3 GUIDs, 2 UInt32 PIDs, HexInt64 LogonId, UInt32 TerminalSessionId)
- <https://github.com/microsoft/SysmonCommon/blob/main/parsecommandline.c>: FieldSizes is a comma-separated FieldName:Size list matched by field name; default NO_MAX_LENGTH (-1)
- <https://github.com/microsoft/SysmonCommon/blob/main/README.md>: Source files shared between the Windows and Linux versions of Sysmon
- <https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwrite>: ERROR_ARITHMETIC_OVERFLOW when the event size exceeds 64KB minus header
- <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw>: Each string is limited to 31,839 characters (Vista and later); prior to Vista, 32K characters
- <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688>: 4688 Data Name='CommandLine' (UnicodeString), added in version 1 (8.1/2012 R2), empty by default unless the GPO is enabled; ParentProcessName ('Creator Process Name') added in version 2; no parent command line; no documented length limit
- <https://github.com/elastic/ecs/blob/main/schemas/process.yml>: process.command_line type wildcard, multi_field match_only_text 'text', level extended (ECS 9.6.0-dev)
- <https://github.com/elastic/ecs/blob/main/generated/elasticsearch/composable/component/process.json>: command_line and parent.command_line are wildcard with no ignore_above; args and parent.args are keyword with ignore_above 1024
- <https://github.com/elastic/elasticsearch/blob/main/x-pack/plugin/core/template-resources/src/main/resources/ecs@mappings.json>: Dynamic template ecs_match_wildcard_and_match_only_text maps *command_line to wildcard plus match_only_text, no ignore_above
- <https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/keyword>: Wildcard ignore_above defaults to 2147483647 in standard indices 'so that all values would be accepted' and 8191 in logsdb; keyword documents rejected over 32766 UTF-8 bytes in standard indices
- <https://www.elastic.co/docs/manage-data/data-store/data-streams/logs-data-stream-configure>: logsdb index-level ignore_above 8191 characters applies to keyword, constant_keyword and wildcard; mapping-level setting takes precedence
- <https://www.elastic.co/docs/manage-data/data-store/data-streams/logs-data-stream>: logsdb automatic on new logs-*-* data streams in 9.0+ (not existing 8.x streams) and on Serverless
- <https://github.com/elastic/elasticsearch/blob/main/server/src/main/java/org/elasticsearch/index/mapper/Mapper.java>: IgnoreAbove defaults Integer.MAX_VALUE vs 8191 for LOGSDB indices; compares String.length()
- <https://github.com/elastic/elasticsearch/blob/main/x-pack/plugin/wildcard/src/main/java/org/elasticsearch/xpack/wildcard/mapper/WildcardFieldMapper.java>: Over-ignore_above values: addIgnoredField, not indexed, raw value stored for synthetic source
- <https://github.com/elastic/beats/blob/main/x-pack/winlogbeat/module/sysmon/ingest/sysmon.yml>: rename of winlog.event_data.CommandLine to process.command_line and ParentCommandLine to process.parent.command_line; no truncate processor
- <https://github.com/elastic/beats/blob/main/x-pack/winlogbeat/module/security/ingest/security_standard.yml>: Painless 'Process Event 4688' sets process.command_line and splits it into process.args; no truncate processor
- <https://github.com/elastic/beats/blob/main/libbeat/common/encoding/xml/safe_reader.go>: Current Winlogbeat XML sanitiser: runes where code == utf8.RuneError or (!unicode.IsSpace && unicode.IsControl) are emitted as the literal text \uNNNN, advancing only one byte
- <https://github.com/elastic/beats/pull/11006>: Winlogbeat escapes control characters so Go's XML parser no longer drops events (merged 2019-03-01)
- <https://github.com/elastic/beats/pull/11357>: CR, LF and TAB no longer escaped (IsSpace check); notes that the XML parser strips raw CR, hence &#xD; in the test
- <https://www.elastic.co/docs/reference/beats/winlogbeat/elasticsearch-output>: Winlogbeat default index winlogbeat-%{[agent.version]}-%{+yyyy.MM.dd}, which is not logs-*-*
- <https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/props.conf>: TRUNCATE is the maximum line length in bytes, default 10000, rounded down at multibyte boundaries; 0 disables it
- <https://github.com/splunk/attack_data/blob/master/bin/replay.py>: Replay posts files to HEC services/collector/raw, so parse-time props such as TRUNCATE apply
- <https://github.com/splunk/attack_data/blob/master/datasets/attack_techniques/T1003.001/atomic_red_team/atomic_red_team.yml>: windows-sysmon.log uses sourcetype XmlWinEventLog and source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
- <https://github.com/splunk/attack_data/blob/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log>: Measured 2026-11-02: 7,960 events on 7,975 lines (raw LF in 4 command lines); longest event 7,486 bytes; &amp; and &gt; entities; EID 1 non-command-line overhead 1,325-1,960 bytes
- <https://github.com/linearregression/TA-microsoft-sysmon/blob/master/default/props.conf>: Old (v3.2.1, 2016) Sysmon TA fork: the XmlWinEventLog:Microsoft-Windows-Sysmon/Operational stanza has no TRUNCATE override (secondary source)
- <https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip>: Measured 2026-11-02: NXLog-format JSON; CommandLine and ParentCommandLine top-level keys repeated in Message; max CommandLine 5,137 in both EID 1 and 4688; ASCII only; such records are about 13.3 KB
- <https://github.com/torvalds/linux/blob/master/include/uapi/linux/binfmts.h>: MAX_ARG_STRLEN = PAGE_SIZE*32; MAX_ARG_STRINGS 0x7FFFFFFF
- <https://man7.org/linux/man-pages/man2/execve.2.html>: argv plus envp limited to 1/4 of RLIMIT_STACK and to 3/4 of _STK_LIM; 32-page per-string limit
- <https://github.com/torvalds/linux/blob/master/kernel/auditsc.c>: MAX_EXECVE_AUDIT_LEN 7500; arguments spanning buffers are chunked with forced encoding
- <https://github.com/torvalds/linux/blob/master/kernel/audit.c>: audit_string_contains_control: '"', bytes < 0x21 or bytes > 0x7e trigger hex encoding
- <https://www.hexacorn.com/blog/?p=7053>: Reported (search snippet only; site unreachable): a very long command line was missed entirely by 4688, while Sysmon truncated it with an ellipsis

### `process.parent.command_line`

**Registry summary.** Same OS and index limits as process.command_line (it is the parent's own command line). Sysmon trims this field first, to no fewer than 263 characters, when an EID 1 event exceeds its 62,000-byte budget; at 8,191 for both command lines the event stays well under it.

**Character class:** `[^\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff\ufffd-\uffff]`

**Where it appears:**

- ecs: `process.parent.command_line` (ECS process events. The Winlogbeat sysmon module (also used by the Elastic Agent windows integration) renames Sysmon EID 1 winlog.event_data.ParentCommandLine to this field. Also set by Elastic Defend process events.)
- ecs: `winlog.event_data.ParentCommandLine` (Raw Winlogbeat event_data for Sysmon EID 1 before the rename)
- sysmon: `ParentCommandLine` (Sysmon EID 1 only. OTRF JSON top-level key "ParentCommandLine", also repeated verbatim in "Message". XML <Data Name='ParentCommandLine'>. Security 4688 has no equivalent: event version 2 has only ParentProcessName ('Creator Process Name').)

**Length evidence (verified):**

Units are UTF-16 code units of the unescaped value. The OS limits match process.command_line, because this is the parent's own command line: 32,766 usable, or 8,191 if the parent was started from cmd.exe. Elastic logsdb ignore_above 8191 limits indexing but not storage.
Sysmon sacrifices this field first. If the EID 1 descriptor exceeds 62,000 bytes, ParentCommandLine is cut by (excess bytes)/2 characters, down to a floor of 263 characters ending '...', before CommandLine is touched. The intact ceiling is floor((62000 - other_bytes - 2*(len(CommandLine)+1))/2) - 1. For the OTRF record with a 5,137-character child command line, that is about 25,333 (1,056 other bytes, no ParentUser), or about 25,316 with a 17-character ParentUser.
With both fields at 8,191 the descriptor is about 33.9 KB (4 x 8,192 + ~1,090), well under 62,000, so no trimming occurs.
The 8,191 cap is NOT end-to-end safe for Splunk. ParentCommandLine shares the 10,000-byte default TRUNCATE line budget with CommandLine and about 1.3-2.0 KB of other XML. tracebait must enforce the per-record serialized-line budget there, or set TRUNCATE = 0.

**Character evidence:**

The pipeline and evidence are the same as for process.command_line: a NUL-terminated UTF-16 command line logged as win:UnicodeString.
- libbeat SafeReader rewrites C0 controls (except TAB, LF and CR), DEL, C1 and U+FFFD as literal \uNNNN text.
- VT and FF reach Go encoding/xml, which rejects them.
- A raw CR is normalised to LF by the XML decoder.
- Lone surrogates and U+FFFE/U+FFFF are invalid in UTF-8 and XML.
The class compiles as a single Python re character class. Correction from the original: U+FFFD is now excluded, and U+FFFE/U+FFFF are escaped instead of written as literal characters.

**Attacker control:**

The attacker has full control when they launched the parent with a chosen command line, for example a stager whose children are then logged. Sysmon copies the value from the parent's process parameters when the child is created. For realism the same string must appear as CommandLine in the parent's own earlier EID 1 event, matched by ParentProcessGuid. OTRF shows this pattern: 5,137-character ParentCommandLine values on children of the 5,137-character process. Injecting only here creates a detectable inconsistency unless the parent's creation predates the dataset window.

**Truncation and ingest:**

Sysmon:
- A configured <FieldSizes> ParentCommandLine:N applies first: exactly N characters, the last 3 being '...'.
- Then the EID 1 62,000-byte budget trims ParentCommandLine first, via TrimStringByNChars with a MAX_PATH+3 = 263-character floor ending '...'. The source comment's rationale is that the parent command line was already logged when the parent was created.
- A long CommandLine injection can therefore silently truncate the original ParentCommandLine in a physically accurate record, and tracebait should model that.
Other sources:
- Security 4688 has no such field, so with a 4688-only source this field is absent from ECS unless an EDR supplies it.
- Elastic: wildcard plus .text match_only_text, no ignore_above in ECS or ecs@mappings. In logsdb, which is automatic only for new logs-*-* streams on 9.0+ and not for Winlogbeat's default winlogbeat-* index, values over 8191 are not indexed, are listed in _ignored, and are kept for synthetic _source.
- The Winlogbeat sysmon pipeline does a plain rename with no truncate.
- XML and Splunk: entity escaping applies, and so does the 10,000-byte per-line default TRUNCATE, which is shared with CommandLine. Events containing a raw LF span several physical lines.
- OTRF JSON: the value is repeated verbatim inside Message (verified). The maximum observed ParentCommandLine in empire_launcher_vbs is 5,137, not 75 (75 was one record's value).
- Linux: there is no separate kernel record. Agents rebuild the value from the parent's argv, which is subject to the 131,072-byte MAX_ARG_STRLEN per argument.

**Unverified:**

- Whether the production Windows Sysmon binary trims ParentCommandLine exactly as the open-source SysmonCommon code does. Assumed, because the README says the code is shared between Windows and Linux.
- Per-record overhead bytes. 1,056-1,098 bytes were measured from OTRF records without ParentUser. Long Image, CurrentDirectory or Hashes values reduce the ceiling, so tracebait should compute it per record.
- Splunk TA TRUNCATE and LINE_BREAKER overrides, NXLog control-character handling, and EvtRender's CR encoding, as for process.command_line.

**Sources:**

- <https://github.com/microsoft/SysmonCommon/blob/main/eventsCommon.cpp>: ParentCommandLine trimmed first when the EID 1 descriptor exceeds MAX_EVENT_PACKET_SIZE 62000; floor MAX_PATH+3 with '...'; rationale comment
- <https://github.com/microsoft/SysmonCommon/blob/main/manifest.xml>: ParentCommandLine is a win:UnicodeString field of EID 1 (schema 4.90)
- <https://github.com/microsoft/SysmonCommon/blob/main/parsecommandline.c>: FieldSizes by field name; default no limit
- <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw>: Parent's own command line is bounded by 32,767 characters including NUL
- <https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation>: 8191-character cmd.exe limit when the parent was launched from cmd
- <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688>: 4688 has ParentProcessName (version 2) only, no parent command line
- <https://github.com/elastic/ecs/blob/main/generated/elasticsearch/composable/component/process.json>: process.parent.command_line is wildcard plus match_only_text with no ignore_above
- <https://www.elastic.co/docs/manage-data/data-store/data-streams/logs-data-stream-configure>: logsdb index.mapping.ignore_above 8191 applies to wildcard
- <https://www.elastic.co/docs/manage-data/data-store/data-streams/logs-data-stream>: logsdb automatic only for new logs-*-* data streams on 9.0+ and on Serverless
- <https://github.com/elastic/beats/blob/main/x-pack/winlogbeat/module/sysmon/ingest/sysmon.yml>: Rename of winlog.event_data.ParentCommandLine to process.parent.command_line; no truncation
- <https://github.com/elastic/beats/blob/main/libbeat/common/encoding/xml/safe_reader.go>: Control, DEL, C1 and U+FFFD rewritten as \uNNNN text
- <https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/props.conf>: TRUNCATE default 10000 bytes per line
- <https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip>: Measured: ParentCommandLine key on Sysmon EID 1 (max 5,137), repeated verbatim in Message; no ParentUser key in the 2020 records
- <https://github.com/splunk/attack_data/blob/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log>: Measured: ParentCommandLine up to 2,815 characters; shares the per-event line with CommandLine

### `user_agent.original`

**Registry summary.** Web and proxy access logs: nginx and Apache reject header lines over about 8 KB, and AWS ALB truncates user_agent over '8 KB' (8,000 used as the floor). IIS replaces values over 4,096 bytes with '...', so IIS-sourced packs need 4,096. Printable ASCII only: access logs escape double quote and backslash, and write control or non-ASCII bytes as \xHH. Servers trim leading and trailing spaces, so the value must not end in one. Keep CloudTrail packs in the cloudtrail schema: CloudTrail's own 1 KB limit applies to them, not this one.

**Character class:** `[\x20\x21\x23-\x5b\x5d-\x7e]`

**Where it appears:**

- ecs: `user_agent.original` (ECS web/proxy access documents (Elastic nginx.access, apache.access, aws.elb, zeek.http integrations); also the target of the ES user_agent processor)
- web_access_log: `$http_user_agent (last quoted field of nginx 'combined')` (nginx access_log, log_format combined)
- web_access_log: `%{User-agent}i (last quoted field of Apache combined)` (Apache httpd mod_log_config CustomLog combined)
- web_access_log: `"user_agent" (field 14)` (AWS Application Load Balancer access log entries)
- zeek: `user_agent` (Zeek http.log (HTTP::Info))

**Length evidence (verified):**

All source limits are in bytes. Under the ASCII-only charset below, 1 byte = 1 stored character. The binding value for this mixed-source spec is the smallest per-source limit.
- nginx (verified in ngx_http_request.c, ngx_http_alloc_large_header_buffer): the whole header line, including CRLF, must fit in one large_client_header_buffers buffer (default 4 8k, so 8192 bytes). The test is (pos - header_name_start) >= size, which returns 400 (494 internally). 12 ('User-Agent: ') + value + 2 (CRLF) <= 8192, so the value is at most exactly 8178 (8179 with a bare LF or no SP).
- Apache 2.4 (protocol.c): ap_rgetline(limit_req_fieldsize + 2 = 8192) returns at most n-1 = 8191 bytes of line content. The normal path accepts a line of up to 8190 bytes (value 8178). A corner case where the CR fits and only the LF overruns accepts 8191 (value 8179). table_do_fn_check_lengths also caps the merged value at 8190. Both servers therefore always accept 8178.
- ALB: a single header of up to 16 K is accepted (quota), but the access log truncates user_agent 'longer than 8 KB'. AWS does not say whether 8 KB means 8000 or 8192 bytes. Under the 8000 reading, ALB truncation binds below 8178. 8000 is the floor that is safe under both readings, and it matches the 1 KB -> 1000 choice made for CloudTrail.
- Zeek: no per-field cap. HTTP::default_max_field_string_bytes = 0 (Zeek 8.1.0+), and releases before 8.1.0 do not truncate log strings at all. ContentLine buffers about 16 MiB. A Zeek record whose response succeeded implies the server accepted the UA, so the server's limit applies.
Enforce original+payload <= 8000. A per-source profile may use the source-verified 8178 for records that come only from nginx or Apache.

**Character evidence:**

RFC 9110 5.5 allows field-vchar (VCHAR 0x21-0x7E, or obs-text 0x80-0xFF), with SP/HTAB only between vchars. CR, LF and NUL are invalid: recipients MUST reject them or replace them with SP. 10.1.5: User-Agent = product *( RWS ( product / comment ) ). ctext (5.6.5) admits HTAB, SP, 0x21-27, 0x2A-5B, 0x5D-7E and obs-text.
Logger escaping is verified in source:
- nginx ngx_http_log_escape's default table escapes 0x00-0x1F, 0x22, 0x5C and 0x7F-0xFF as \xXX.
- Apache gen_test_char.c T_ESCAPE_LOGITEM covers !isprint, double quote, backslash and cntrl. They are written as \xhh, a backslash prefix for double quote and backslash, and C-style \t etc. for whitespace.
- Elastic's nginx and apache groks (DATA) do not unescape.
What survives byte-for-byte is printable ASCII 0x20-0x7E minus 0x22 and 0x5C. The class compiles in Python re as a single bracket class (93 characters).
The value must not start or end with SP. nginx trims only leading and trailing SP; Apache trims SP and HTAB. So the appended payload's last character must not be a space.

**Attacker control:**

Full and unauthenticated. Any client sets User-Agent to an arbitrary string on every request; no handshake or credentials are needed. Constraints:
- Header-size limits: nginx 8192-byte line, Apache 8190/8191-byte line, ALB 16 K.
- Parsers: Apache's default 'HttpProtocolOptions Strict LenientMethods Allow0.9' rejects values containing 0x00-0x08, 0x0A-0x1F or 0x7F with 400 (APLOGNO 02427 'Request header value is malformed', logged at DEBUG level). nginx rejects only NUL (NGX_HTTP_PARSE_INVALID_HEADER). It accepts other control bytes and \xXX-escapes them in the log.
Control-character payloads therefore give a 400 record (Apache) or an escaped record (nginx). The original UA is attacker-chosen too, so tracebait may treat the whole value as attacker text.

**Truncation and ingest:**

(1) nginx log_format escape=json (verified in ngx_escape_json) escapes only double quote and backslash as \" and \\, and bytes <=0x1F as \n/\r/\t/\b/\f/\u00XX. Bytes >=0x7F pass raw, so UTF-8 survives only with escape=json or escape=none. nginx itself never truncates access-log lines (file or syslog).
(2) ECS mapping depends on the template:
- The ECS repo composable component template maps user_agent.original as keyword, ignore_above 1024, plus .text (match_only_text).
- Fleet integrations on 8.13+ get it from Elasticsearch's ecs@mappings. Its dynamic template ecs_path_match_keyword_and_match_only_text maps *user_agent.original as keyword with NO ignore_above (plus .text match_only_text).
- logsdb index mode sets index.mapping.ignore_above to 8191.
None of these truncates: values over the threshold stay in _source and .text and are only missing from the keyword index. Offer an optional <=1024 profile only for agents that use keyword term queries on a 1024-capped template.
(3) The ES user_agent processor's default properties include 'original'. No input length limit is documented; only user_agent.cache_size.
(4) Splunk's official props.conf spec gives TRUNCATE default 10000 bytes per line (rounded down at a multi-byte boundary). The whole combined line must stay <=10000 bytes.
(5) rsyslog: maxMessageSize defaults to 8K and longer messages are truncated (from a search of rsyslog docs; one doc branch says 4K). If access logs are forwarded via syslog, the whole line, not just the UA, must fit.
(6) ALB: user_agent is truncated above 8 KB. A header with non-ASCII or control characters gets classification 'Acceptable' with reason 'NonCompliantHeader', which is a visible tell. NUL or CR gives 'BadHeader' (Severe).
(7) Zeek: the HTTP stream sets max_field_string_bytes = HTTP::default_max_field_string_bytes = 0 (unlimited), which overrides Log::default_max_field_string_bytes = 4096. The record total is Log::default_max_total_string_bytes = 256000. Both arrived in Zeek 8.1.0 (absent in v8.0.0). ContentLine DEFAULT_MAX_LINE_LENGTH = 16 MiB - 100. JSON output keeps valid UTF-8 (excluding C0/C1, PUA and U+FFF0-FFFF). Once one invalid sequence is seen, every non-ASCII byte in the value is written as \xHH.
(8) nginx HTTP/2 and HTTP/3: the buffer limits the HPACK/QPACK-compressed field, so Huffman-coded values can decompress larger. Do not rely on this.

**Unverified:**

- Whether ALB's '8 KB' means 8000 or 8192 bytes; 8000 is used as the safe floor.
- How ALB writes an embedded double quote, backslash or non-ASCII byte inside the quoted user_agent field is undocumented, so they are excluded.
- Whether Apache mod_http2 applies LimitRequestFieldSize to the decoded HTTP/2 field.
- rsyslog maxMessageSize default (8K per the stable docs, 4K on one dev-branch page) was not fetched directly. syslog-ng and other shippers were not researched.
- Zeek logging a request that the server rejected with 400 is expected behaviour but was not traced in Zeek source.
- That a given Fleet stack actually composes ecs@mappings (8.13+) rests on an Elastic blog post, not on Kibana source.
- Sourcetype-specific TRUNCATE overrides in Splunk TAs (for example access_combined) were not checked.
- CloudFront and other CDN/WAF access-log UA limits and encodings were not researched.

**Sources:**

- <https://www.rfc-editor.org/rfc/rfc9110.txt>: 5.5 field-value grammar and CR/LF/NUL rule; 5.4 field limits (4xx); 5.6.5 comment/ctext; 10.1.5 User-Agent ABNF
- <https://nginx.org/en/docs/http/ngx_http_core_module.html#large_client_header_buffers>: Default 4 8k; a header field cannot exceed one buffer or 400; HPACK/QPACK compressed-size note
- <https://raw.githubusercontent.com/nginx/nginx/master/src/http/ngx_http_request.c>: ngx_http_alloc_large_header_buffer: (pos - header_name_start) >= size gives 'client sent too long header line' (494/400). The line incl. CRLF must fit in 8192
- <https://raw.githubusercontent.com/nginx/nginx/master/src/http/ngx_http_parse.c>: ngx_http_parse_header_line: only NUL is invalid in a value; only SP is trimmed
- <https://raw.githubusercontent.com/nginx/nginx/master/src/http/modules/ngx_http_log_module.c>: Default escape table (0x00-0x1F, 0x22, 0x5C, 0x7F-0xFF to \xXX); combined format ends with "$http_user_agent"; no line truncation
- <https://raw.githubusercontent.com/nginx/nginx/master/src/core/ngx_string.c>: ngx_escape_json escapes only double quote, backslash and <=0x1F
- <https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format>: Documented default/json/none escaping and the combined format
- <https://httpd.apache.org/docs/2.4/mod/core.html#limitrequestfieldsize>: LimitRequestFieldSize default 8190 bytes; HttpProtocolOptions default 'Strict LenientMethods Allow0.9' (2.2.32/2.4.24+)
- <https://raw.githubusercontent.com/apache/httpd/2.4.x/server/protocol.c>: ap_rgetline(limit_req_fieldsize + 2); ap_rgetline_core returns at most n-1 chars (LF-overrun corner case); 400 'Size of a request header field exceeds server limit'; table_do_fn_check_lengths caps merged values at 8190; strict-mode ap_scan_http_field_content rejection
- <https://raw.githubusercontent.com/apache/httpd/2.4.x/include/httpd.h>: Internal buffers are 2 bytes larger than DEFAULT_LIMIT_REQUEST_FIELDSIZE 8190
- <https://raw.githubusercontent.com/apache/httpd/2.4.x/server/gen_test_char.c>: T_HTTP_CTRLS (NUL and cntrl except HTAB) and T_ESCAPE_LOGITEM (!isprint, double quote, backslash, cntrl)
- <https://httpd.apache.org/docs/2.4/mod/mod_log_config.html>: \xhh escaping since 2.0.46, backslash-escaping of double quote and backslash, C-style whitespace; combined format with %{User-agent}i
- <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html>: user_agent is field 14, truncated if longer than 8 KB; NonCompliantHeader = Acceptable; BadHeader = Severe
- <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html>: ALB single header 16 K and entire request header 64 K, so ALB accepts UAs larger than its 8 KB log truncation
- <https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/http/main.zeek>: HTTP::default_max_field_string_bytes = 0 passed to the HTTP log stream; user_agent set from the USER-AGENT header
- <https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/init-bare.zeek>: Log::default_max_field_string_bytes = 4096; Log::default_max_total_string_bytes = 256000
- <https://raw.githubusercontent.com/zeek/zeek/v8.1.0/scripts/base/protocols/http/main.zeek>: The HTTP override exists in v8.1.0; v8.0.0 has no log string limits (checked against the v8.0.0 tag)
- <https://raw.githubusercontent.com/zeek/zeek/master/src/analyzer/protocol/tcp/ContentLine.h>: DEFAULT_MAX_LINE_LENGTH = 16*1024*1024 - 100
- <https://raw.githubusercontent.com/zeek/zeek/master/src/util.cc>: escape_utf8 JSON escaping behaviour
- <https://www.elastic.co/docs/reference/ecs/ecs-user_agent>: user_agent.original: keyword, extended, multi-field .text match_only_text
- <https://raw.githubusercontent.com/elastic/ecs/main/generated/elasticsearch/composable/component/user_agent.json>: ECS repo template: ignore_above 1024
- <https://raw.githubusercontent.com/elastic/elasticsearch/main/x-pack/plugin/core/template-resources/src/main/resources/ecs%40mappings.json>: ecs@mappings maps *user_agent.original as keyword plus match_only_text with no ignore_above
- <https://www.elastic.co/observability-labs/blog/future-proof-your-logs-with-ecs-mappings-template>: ecs@mappings included in all Elastic Agent integration templates since 8.13 (Elastic blog)
- <https://www.elastic.co/docs/manage-data/data-store/data-streams/logs-data-stream-configure>: logsdb default index.mapping.ignore_above 8191
- <https://raw.githubusercontent.com/elastic/integrations/main/packages/nginx/data_stream/access/elasticsearch/ingest_pipeline/default.yml>: grok '"(-|%{DATA:user_agent.original})"' with no unescaping, then the user_agent processor
- <https://www.elastic.co/docs/reference/enrich-processor/user-agent-processor>: Default properties [name, os, device, original, version]; no input length limit documented
- <https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/props.conf>: Official: TRUNCATE is the default maximum line length in bytes, Default: 10000
- <https://www.rsyslog.com/doc/v5-stable/rainerscript/global.html>: maxMessageSize default 8K, larger messages truncated (search snippet only; the rsyslog site refused connection on fetch)

### `aws.cloudtrail.user_agent`

**Registry summary.** CloudTrail truncates userAgent over '1 KB' (1,000 used as the floor; AWS does not say 1,000 or 1,024) in trails, Event history and 256 KB event data stores. S3 data events wrap the agent in brackets; payloads must then go before the closing ']', which tracebait does not support yet. The value must not end in a space.

**Character class:** `[\x20-\x7e]`

**Where it appears:**

- cloudtrail: `userAgent` (All CloudTrail record types where present (AwsApiCall management and data events, AwsConsoleSignIn, network activity events). Optional: True)
- ecs: `user_agent.original` (Elastic aws.cloudtrail data stream. The user_agent processor reads json.userAgent with target_field user_agent, and its default 'original' property fills user_agent.original. Elastic has no aws.cloudtrail.user_agent field; that name is only the tracebait registry key)

**Length evidence (verified):**

The CloudTrail record-contents reference says userAgent 'has a maximum size of 1 KB; content exceeding that limit is truncated'. The exception is event data stores configured for a 1 MB maximum event size: there the field is truncated only if the event payload exceeds 1 MB, and userAgent is 5th in the documented truncation order.
AWS does not say whether 1 KB means 1000 or 1024, or whether it counts bytes or characters. Enforcing 1000 keeps the value intact under every reading, and with printable ASCII, bytes = characters.
Trails, Event history and default (256 KB) event data stores are under the 1 KB rule, and so are the S3-delivered records typical of splunk/attack_data.
Measure on the stored value. That includes the original SDK/CLI string and, for S3 events, the surrounding square brackets.

**Character evidence:**

CloudTrail stores the value as a JSON string. JSON escaping of double quote and backslash is lossless after parsing, so both are allowed here, unlike in the text access logs.
Real SDK and CLI UAs are printable ASCII; AWS's own example is aws-cli/1.3.23 Python/2.7.6 Linux/2.6.18-164.el5. botocore passes Config(user_agent=...) and user_agent_extra through as raw strings: RawStringUserAgentComponent says 'No sanitization is performed', and _build_legacy_ua_string joins override + extras. Only user_agent_appid is sanitized, to alphanumerics plus !$%&'*+-.^_`|~,#.
How AWS front-ends treat HTAB, control or non-ASCII bytes is undocumented, so the class is limited to 0x20-0x7E (95 characters; it compiles as a single class). Avoid a trailing SP for the RFC 9110 OWS reason.

**Attacker control:**

Full for direct API calls made with attacker-held credentials (stolen keys, assumed roles), which is the common incident case. The User-Agent header is not covered by SigV4: botocore's SIGNED_HEADERS_BLACKLIST includes 'user-agent', so it can be set or rewritten freely, including through an intercepting proxy. Hackingthe.cloud documents a Burp match-and-replace rule and says the configured UA appears in CloudTrail.
There is no attacker control when AWS makes the call. userAgent is then the calling service's event source (for example ec2.amazonaws.com) or 'AWS Internal/#'. For console sessions the value is the browser or console UA.

**Truncation and ingest:**

Content over 1 KB is silently truncated: the payload is cut, not dropped. The doc makes truncation depend on the destination: 1 MB-event Lake stores keep the full value, so CloudTrail holds it untruncated internally and trims it per destination. Trails, Event history and 256 KB event data stores are truncated; EventBridge behaviour is not documented.
S3 events wrap the UA in square brackets (AWS's own S3 example shows "userAgent": "[]"). When the original is bracket-wrapped, tracebait must insert the payload before the closing ']'; appending after it is implausible. The brackets count toward the 1000 budget.
In Elastic, the user_agent processor copies the full string to user_agent.original. At <=1 KB, neither the ECS-repo ignore_above 1024 nor ecs@mappings (no ignore_above) affects indexing.

**Unverified:**

- Whether CloudTrail's '1 KB' means 1000 or 1024, and whether it counts bytes or characters. 1000 is the safe floor.
- Where truncation cuts a multi-byte UTF-8 character, and whether a truncation marker is added. AWS does not document either.
- How AWS API front-ends handle HTAB, control or non-ASCII bytes in User-Agent (reject, replace or pass through) was not tested.
- Whether S3's bracket wrapping is applied before or after the 1 KB truncation; counting the brackets inside 1000 is conservative either way.
- Whether EventBridge copies are truncated at 1 KB.
- The UA limit for 1 MB-event CloudTrail Lake stores is bounded only by unknown AWS front-end header limits.

**Sources:**

- <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html>: userAgent definition, Optional: True, 1 KB maximum with truncation, 1 MB event data store exception and truncation order (userAgent 5th), example values, and 'AWS Internal/#' and service event-source values for AWS-originated calls
- <https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-understanding-s3-entries.html>: S3 CloudTrail example records show userAgent bracket-wrapped ("[]")
- <https://raw.githubusercontent.com/elastic/integrations/main/packages/aws/data_stream/cloudtrail/elasticsearch/ingest_pipeline/default.yml>: user_agent processor on json.userAgent with target_field user_agent and ignore_missing (fills user_agent.original)
- <https://www.elastic.co/docs/reference/enrich-processor/user-agent-processor>: Default properties include 'original'
- <https://raw.githubusercontent.com/boto/botocore/develop/botocore/auth.py>: SIGNED_HEADERS_BLACKLIST contains 'user-agent', so the UA is excluded from SigV4 signing
- <https://raw.githubusercontent.com/boto/botocore/develop/botocore/config.py>: user_agent replaces the header, user_agent_extra appends, and user_agent_appid is character-restricted
- <https://raw.githubusercontent.com/boto/botocore/develop/botocore/useragent.py>: RawStringUserAgentComponent ('No sanitization is performed') used for user_agent_extra; legacy override joins raw strings; sanitize_user_agent_string_component applies only to appid and similar components
- <https://hackingthe.cloud/aws/avoiding-detection/guardduty-pentest/>: The UA is caller-controlled and the rewritten value appears in CloudTrail (GuardDuty PenTest evasion)

### `dns.question.name`

**Registry summary.** RFC 1035: names are at most 255 octets on the wire, so 253 characters in presentation form, with labels of at most 63. An attacker who owns a domain controls only its leading labels, so payloads are prepended and should end with '.'. Lowercase letters, digits, '.', '_' and '-' survive every producer checked (Sysmon keeps case and a trailing dot; Packetbeat drops the dot).

**Character class:** `[a-z0-9._-]`

**Where it appears:**

- ecs: `dns.question.name` (All ECS DNS events: Packetbeat dns; Elastic Windows integration sysmon_operational and Winlogbeat sysmon module (EID 22, renamed verbatim from winlog.event_data.QueryName); Elastic Zeek integration dns data stream (dns.question.domain from the registered_domain processor on zeek.dns.query, renamed to dns.question.name))
- sysmon: `QueryName` (Sysmon EID 22 DNSEvent (DNS query): OTRF JSON top-level key 'QueryName'; Windows XML <Data Name='QueryName'>)
- zeek: `query` (Zeek dns.log (DNS::Info$query))

**Length evidence (verified):**

RFC 1035 §2.3.4 (labels 63 octets or less, names 255 octets or less) and §3.1 (the 255 includes the label length octets). 255 wire octets = 1 root octet + sum(label_len + 1), so the presentation form is at most 253 characters without a trailing dot. Each dot-free run must be 1-63 characters, with no empty labels. For ASCII names, characters = octets. This is the binding limit for every producer that only logs names it can parse: miekg/dns, which Packetbeat uses, returns ErrLongDomain once the wire budget of 255 is used up, so Packetbeat emits no event for longer names. Correction: Packetbeat STRIPS the trailing dot from question names (decodeDNSData: msg.Question[i].Name = trimRightDot(q.Name), present since at least v8.0.0), and so does Zeek. Only Sysmon-sourced values keep a trailing dot. If the original Sysmon value ends in '.', allow 254 stored characters including that dot. Zeek can log up to about 511 characters from crafted packets, with a weird, and Sysmon logs some names Windows rejects (status 123), but neither is a plausible resolvable name. ECS keyword ignore_above 1024 does not bind: miekg's worst-case \DDD-escaped compliant name is 1004 characters (61*4+1+63*4+1+63*4+1+63*4+1). original+payload <= 253.

**Character evidence:**

Intersection of what survives intact in every producer of dns.question.name. Uppercase is lost in Zeek-sourced documents, because Zeek lowercases the question name in ParseQuestion before dns_request. Packetbeat/miekg backslash-escapes . space ' @ ; ( ) " \ inside a label (isDomainNameLabelSpecial), and writes bytes below ' ' or above '~' as \DDD. ECS guidance also requires \DDD for characters below 32 or above 126, and escaping of backslash and quotes. Windows DnsValidateName treats space and { | } ~ [ \ ] ^ ' : ; < = > ? & @ ! " # $ % ` ( ) + / , as DNS_ERROR_INVALID_NAME_CHAR. Underscore is only a DNS_ERROR_NON_RFC_NAME warning, and real Sysmon EID 22 records show it intact (_kerberos._tcp..., _ldap._tcp...). Underscore is not special in miekg and is printable for Zeek. RFC 2181 §11 allows any binary label, but no producer renders arbitrary octets verbatim. Per-source siblings give wider classes: Sysmon also keeps A-Z; Zeek also keeps space and printable punctuation except backslash.

**Attacker control:**

Full value: when the attacker runs code on the host (DnsQuery/getaddrinfo for Sysmon, or raw UDP/TCP for network sensors), or can make any client or service resolve an attacker-chosen hostname (URLs, email links, SSRF, sandbox detonation). The name need not exist: NXDOMAIN is still logged (Sysmon QueryStatus 9003, seen in splunk attack_data; Zeek logs the query regardless of rcode). Realistic C2/exfil case: the attacker owns a registered domain and controls every label to its left, i.e. 253 - len('.' + attacker_domain) characters (245 for 'evil.io'), in labels of 63 characters or less. Appending text to the right-hand end of a DNS name changes its TLD, so tracebait should place the payload as leftmost labels, or treat the attacker's registered domain as a fixed suffix, rather than literally appending to a benign name.

**Truncation and ingest:**

Elastic sysmon_operational pipeline, and the Winlogbeat x-pack sysmon module pipeline: rename winlog.event_data.QueryName -> dns.question.name verbatim, with no lowercase, trim or gsub, so case and the trailing dot are kept. Then registered_domain (ignore_failure, ignore_missing) and removal of dns.question.domain. Elastic Zeek integration: registered_domain(field zeek.dns.query, target dns.question, ignore_missing) and rename dns.question.domain -> dns.question.name. dns.question.name is set only when the public-suffix parse succeeds: unknown TLDs such as .local give no field. The value is the Zeek query verbatim (lowercase, no trailing dot), and zeek.dns.query is kept, not removed. Packetbeat: dns.question.name = trimRightDot(miekg q.Name), a presentation form WITHOUT a trailing dot, with backslash/\DDD escapes. ECS guidance: characters below 32 or above 126 become \DDD, backslash and quotes are escaped, tab/CR/LF become \t \r \n. Keyword ignore_above is 1024, which does not bind, and affects only indexing, not _source. The harness must recompute dns.question.subdomain, registered_domain and top_level_domain after inserting the payload.

**Unverified:**

- Elastic Defend (endpoint) DNS events were not checked; they may populate dns.question.name differently.
- Non-ASCII/IDN handling (UTF-8 vs punycode) across producers was not tested; the class is ASCII-only on purpose.
- DNS 0x20 case randomization by recursive resolvers is a further reason uppercase is unreliable on egress sensors; no source was fetched for this.

**Sources:**

- <https://www.rfc-editor.org/rfc/rfc1035.txt>: §2.3.4 labels 63 octets or less, names 255 octets or less; §3.1 255 includes label length octets; §5.1 \X and \DDD escapes
- <https://www.rfc-editor.org/rfc/rfc2181.txt>: §11: any binary string can be a label; labels 1-63 octets; full name 255 octets including separators
- <https://github.com/elastic/ecs/blob/main/schemas/dns.yml>: dns.question.name definition and \DDD / backslash / quote / \t\r\n escaping guidance; subdomain/registered_domain definitions
- <https://github.com/elastic/ecs/blob/main/generated/elasticsearch/composable/component/dns.json>: dns.question.name / subdomain / registered_domain: keyword, ignore_above 1024
- <https://github.com/elastic/integrations/blob/main/packages/windows/_dev/shared/ingest_pipeline/sysmon_operational.yml>: rename winlog.event_data.QueryName -> dns.question.name; registered_domain with ignore_failure; no lowercase/trim
- <https://github.com/elastic/beats/blob/main/x-pack/winlogbeat/module/sysmon/ingest/sysmon.yml>: Winlogbeat sysmon module also renames QueryName -> dns.question.name verbatim
- <https://github.com/elastic/integrations/blob/main/packages/zeek/data_stream/dns/elasticsearch/ingest_pipeline/default.yml>: registered_domain on zeek.dns.query (ignore_missing) and rename dns.question.domain -> dns.question.name; zeek.dns.query not removed
- <https://github.com/elastic/elasticsearch/blob/main/libs/web-utils/src/main/java/org/elasticsearch/web/RegisteredDomain.java>: domain = raw fqdn; returns false (no fields) when there is no registrable domain
- <https://github.com/elastic/elasticsearch/blob/main/modules/ingest-common/src/main/java/org/elasticsearch/ingest/common/RegisteredDomainProcessor.java>: With ignore_missing, an unparseable domain leaves the document unchanged
- <https://github.com/elastic/beats/blob/main/packetbeat/protos/dns/dns.go>: decodeDNSData trims the trailing dot from question names (trimRightDot); dns.question.name = q.Name; subdomain = TrimRight(TrimSuffix(q.Name, eTLD+1), '.')
- <https://github.com/elastic/beats/blob/v8.0.0/packetbeat/protos/dns/dns.go>: Question-name trailing-dot trimming already present in v8.0.0
- <https://github.com/miekg/dns/blob/master/msg.go>: UnpackDomainName: 255-octet budget -> ErrLongDomain; special bytes backslash-escaped; bytes < ' ' or > '~' via escapeByte (\DDD); maxDomainNamePresentationLength = 1004
- <https://github.com/miekg/dns/blob/master/types.go>: isDomainNameLabelSpecial: . space ' @ ; ( ) " \
- <https://github.com/zeek/zeek/blob/e4a470da8ee7ed0db70fe46671fdb7ff9566d35d/src/analyzer/protocol/dns/DNS.cc>: Zeek lowercases the question name; label >63 = ParseError; DNS_NAME_too_long weird; 513-byte name buffer; trailing dot removed
- <https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsvalidatename_w>: Windows rules: >255 octets / label >63 / consecutive or leading dots = ERROR_INVALID_NAME; underscore/Unicode = DNS_ERROR_NON_RFC_NAME; space and listed punctuation = DNS_ERROR_INVALID_NAME_CHAR

### `file.name`

**Registry summary.** NTFS, exFAT and FAT32 allow 255 UTF-16 units per file name (Linux NAME_MAX is 255 bytes, so Linux-origin packs must count UTF-8 bytes). Windows forbids control characters and <>:"/\|?*; reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) are not checked here. Payloads are prepended so the extension, which is evidence, stays intact. Sysmon TargetFilename is a full path and is not supported yet.

**Character class:** `[^\x00-\x1f\x7f-\x9f"*/:<>?\\|\ud800-\udfff\ufffd-\uffff]`

**Where it appears:**

- ecs: `file.name` (ECS file events. The Winlogbeat Sysmon pipeline derives it from file.path (renamed from TargetFilename or ImageLoaded) as the substring after the last backslash, and runs that script only when the path contains a backslash. The same pipeline also renames Sysmon PipeName (EID 17/18) to file.name; pipe names have their own limits and are outside this spec.)
- sysmon: `TargetFilename` (Sysmon EID 2, 11, 15, 23 and 26 (confirmed in the SysmonCommon manifest). EID 27, 28 and 29 exist per the Sysinternals event table, and EID 29 carries TargetFilename per Splunk security_content. Only the final path component maps to file.name.)
- windows_security: `RelativeTargetName` (Security 5145 (the pipeline condition lists 5140 and 5145). Winlogbeat copies it to file.name, builds file.path as ShareLocalPath + backslash + RelativeTargetName, and builds file.target_path as ShareName + backslash + file.name. It is a share-relative path and can contain backslashes.)

**Length evidence (verified):**

255 UTF-16 code units for Windows-origin records. NTFS, exFAT and FAT32 limit a file name to 255 Unicode characters (UDF: 127 Unicode or 254 ASCII). Extended-length paths limit each component to lpMaximumComponentLength, which is commonly 255. Linux NAME_MAX is 255 bytes, and POSIX defines a filename as 1 to NAME_MAX bytes, so Linux-origin records must count UTF-8 bytes. Python len() counts code points, so a character above U+FFFF counts as 1 but uses 2 of the 255 UTF-16 units. Nothing downstream binds lower: Sysmon writes TargetFilename from a variable-length extension (FC_FileName), the Winlogbeat pipeline has no truncate processor, ECS ignore_above is 1024, and Splunk TRUNCATE is 10,000 bytes per event. Without the extended-length prefix, Win32 MAX_PATH (260 including the NUL) also requires len(directory) + 1 + len(name) <= 259. The attacker's own process can use the extended-length prefix or a long-path-aware runtime (.NET Core and .NET 5+ do no MAX_PATH check), so 255 is reachable in any writable directory.

**Character evidence:**

Microsoft Learn (Naming Files) forbids the characters < > : " / backslash | ? *, NUL, and characters 1-31 (which are allowed only in alternate data stream names). POSIX allows any byte except NUL and slash, so the Windows-legal set is used, and Linux accepts it too. Lone surrogates are excluded: NTFS treats names as opaque WCHARs, but Go's utf16.DecodeRune, used by the Winlogbeat UTF-16 conversion, returns U+FFFD for an invalid pair. U+FFFE and U+FFFF are excluded because XML 1.0's Char production omits them. The class writes them as escapes (backslash-ufffe, backslash-uffff), not as literal noncharacters that editors can silently corrupt. Tested: it compiles in Python re, is a single bracket class, rejects all reserved characters, controls, surrogates and FFFE/FFFF, and accepts DEL, non-ASCII and astral characters. Rules the class cannot express: the result must not be a reserved device name (CON, PRN, AUX, NUL, COM1-9, COM superscript 1-3, LPT1-9, LPT superscript 1-3), alone or followed by an extension. It must not be '.' or '..'. It must not end in '.' or ' ', because Win32 normalization strips trailing periods and spaces from the final segment (the extended-length prefix skips this, but the shell cannot handle such names).

**Attacker control:**

Full control of the final component of any file the attacker creates or renames in a directory they can write to (user temp and profile folders, Downloads, /tmp). This needs no privilege. OS-owned files cannot be renamed without elevation, so appending to the names of system files is not plausible.

**Truncation and ingest:**

ECS file.name is a plain keyword with ignore_above 1024 and no text multi-field. The Winlogbeat Sysmon script computes file.name with lastIndexOf on a backslash, and computes file.extension with lastIndexOf('.') on the full path, not the name. A '.' in the payload therefore changes file.extension, and a name with no dot can inherit a bogus extension from a dotted directory. Recompute name, directory and extension after patching. The security pipeline recomputes file.extension from file.name. OTRF JSON is a flat record with a rendered Message field that repeats 'TargetFilename: ...', so patch both copies. Rendered Message text can expand '%%<digits>' parameter references (Security events show values such as AccessList '%%4417' resolved), so avoid '%%' or '%' followed by digits in payloads. In XML records '&' is stored as &amp;. Sysmon's FieldSizes setting (no default, so off unless configured) truncates a field to the configured length and overwrites its last 3 characters with '.'.

**Unverified:**

- Whether NTFS accepts characters 0x01-0x1F in primary file names through the native API. The Microsoft doc covers Win32 naming only.
- How Windows Event Log XML rendering handles U+FFFE and U+FFFF. They are excluded as a precaution.
- Whether EvtFormatMessage-rendered Message copies of Sysmon events expand '%%n' or '%n' sequences inside insertion strings. Security events do resolve %%NNNN values; Sysmon was not tested.
- EID 27, 28 and 29 TargetFilename presence is confirmed only by the Sysinternals event table and Splunk security_content, not by the SysmonCommon manifest (the fetched portion ends at EID 26).
- The current Winlogbeat UTF-16 decoder (moved out of winlogbeat/sys into libbeat) was not inspected. The U+FFFD behavior is inferred from Beats 5.6 code, which used utf16.DecodeRune, and from the Go docs.
- The splunk/attack_data single-quoted <Data Name='TargetFilename'> format was not re-fetched; the sample file exceeded 10 MB.
- Linux filesystems other than ext4, XFS and btrfs, and network or FUSE mounts, may have a different NAME_MAX.

**Sources:**

- <https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file>: Reserved characters, NUL and 1-31 (ADS exception), reserved device names including COM and LPT with superscript digits 1-3, rule against a trailing space or period
- <https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison>: NTFS, exFAT and FAT32 file names up to 255 Unicode characters; UDF 127 Unicode or 254 ASCII; each path component no more than 255
- <https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation>: MAX_PATH of 260 including NUL; lpMaximumComponentLength commonly 255; names are opaque WCHAR sequences
- <https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats>: Normalization rules (separator canonicalization, trailing period and space trimming, extended-length prefix skips normalization); .NET Core has no MAX_PATH check
- <https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/limits.h>: NAME_MAX 255
- <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap03.html>: 3.146 Filename: 1 to NAME_MAX bytes, no NUL or slash
- <https://raw.githubusercontent.com/elastic/ecs/main/generated/elasticsearch/composable/component/file.json>: file.name is a keyword with ignore_above 1024
- <https://raw.githubusercontent.com/elastic/beats/main/x-pack/winlogbeat/module/sysmon/ingest/sysmon.yml>: TargetFilename, ImageLoaded and Device renamed to file.path; the split script derives name, directory and extension; PipeName renamed to file.name
- <https://raw.githubusercontent.com/elastic/beats/main/x-pack/winlogbeat/module/security/ingest/security_standard.yml>: 5140/5145 RelativeTargetName copied to file.name; file.path and file.target_path built from it; extension script
- <https://raw.githubusercontent.com/microsoft/SysmonCommon/main/eventsCommon.cpp>: TargetFilename comes from the FC_FileName extension (N_UnicodePath); TrimStringToNChars FieldSizes behavior
- <https://raw.githubusercontent.com/microsoft/SysmonCommon/main/usage.c>: FieldSizes configuration entry, listed without a default
- <https://raw.githubusercontent.com/microsoft/SysmonCommon/main/manifest.xml>: TargetFilename present in EID 2, 11, 15, 23, 26
- <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>: Event table including EID 27, 28, 29
- <https://pkg.go.dev/unicode/utf16>: DecodeRune returns U+FFFD for an invalid surrogate pair
- <https://www.w3.org/TR/xml/>: Char production excludes U+FFFE and U+FFFF and C0 controls other than tab, LF and CR

### `aws.cloudtrail.request_parameters.roleSessionName`

**Registry summary.** STS AssumeRole RoleSessionName: 2 to 64 characters from [A-Za-z0-9_+=,.@-]. The API rejects anything else before CloudTrail records it, so payloads here have no spaces.

**Character class:** `[A-Za-z0-9_+=,.@-]`

**Where it appears:**

- cloudtrail: `requestParameters.roleSessionName` (sts:AssumeRole and AssumeRoleWithWebIdentity (API parameter). AssumeRoleWithSAML: CloudTrail records it from the SAML attribute https://aws.amazon.com/SAML/Attributes/RoleSessionName. The session name is also echoed in responseElements.assumedRoleUser.arn/assumedRoleId, and in userIdentity.arn/principalId of every later call made by that session.)
- ecs: `aws.cloudtrail.flattened.request_parameters.roleSessionName` (Elastic flattened leaf (absent under retain=minimal/keyword/none). Appears as the substring 'roleSessionName=<v>' inside aws.cloudtrail.request_parameters. Not copied to its own ECS field. The pipeline lists json.requestParameters.roleSessionName only in the enrichSts related-entity list. The session name reaches related.user through the assumed-role ARN grok.)

**Length evidence (verified):**

STS AssumeRole and AssumeRoleWithWebIdentity RoleSessionName: 'Minimum length of 2. Maximum length of 64.' The SAML RoleSessionName attribute is also 2-64. The IAM quotas table says 'Role session name 64 characters'. Values are ASCII, so characters = bytes. Longer values are rejected at the API before CloudTrail, so 64 binds below every storage/ingest limit. original + payload <= 64.

**Character evidence:**

STS pattern [\w+=,.@-]*. The doc prose says 'upper- and lower-case alphanumeric characters with no spaces' plus _ + = , . @ -. The SAML attribute doc gives the same set and 'cannot contain spaces'. ASCII rendering is conservative. Verified: compiles as a single Python bracket class. No spaces, quotes, colons, slashes or brackets.

**Attacker control:**

Full, within the charset: any principal calling AssumeRole or AssumeRoleWithWebIdentity picks it, unless the trust policy constrains it with sts:RoleSessionName. For SAML the IdP sets it, so the attacker needs IdP control. Cross-account: logged in the role-owner account, and the name persists in the assumed-role ARN of every later event.

**Truncation and ingest:**

Never truncated (64 is far below 100 KB and ignore_above 8191). The keyword form is unescaped ('roleSessionName=<v>'). ',' is legal in the charset, so ', ' cannot occur (no space), but '=' and ',' can and make the keyword form ambiguous. Exact in flattened and _source.

**Sources:**

- <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html>: RoleSessionName min 2 max 64, pattern [\w+=,.@-]*, cross-account visibility
- <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html>: RoleSessionName min 2 max 64, same pattern
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html>: SAML RoleSessionName attribute 2-64 chars, alphanumeric, _ . , + = @ -, no spaces
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>: Role session name 64 characters
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html>: AssumeRole/SAML/OIDC events showing requestParameters.roleSessionName and the session name inside the assumed-role ARN
- <https://raw.githubusercontent.com/elastic/integrations/main/packages/aws/data_stream/cloudtrail/elasticsearch/ingest_pipeline/default.yml>: roleSessionName only in the enrichSts list; related.user gets the session name from the ARN grok

### `aws.cloudtrail.request_parameters.sourceIdentity`

**Registry summary.** STS SourceIdentity: the API reference says 2 to 64 characters (the IAM User Guide says 256; 64 is the safe bound), from [A-Za-z0-9_+=,.@-], and it may not start with 'aws:'.

**Character class:** `[A-Za-z0-9_+=,.@-]`

**Where it appears:**

- cloudtrail: `requestParameters.sourceIdentity` (sts:AssumeRole (API parameter). AssumeRoleWithSAML (SAML attribute SourceIdentity) and AssumeRoleWithWebIdentity (JWT claim https://aws.amazon.com/source_identity); both are confirmed in IAM CloudTrail examples. Also echoed in responseElements.sourceIdentity, and persisted in userIdentity.sessionContext.sourceIdentity of later and chained calls.)
- ecs: `aws.cloudtrail.flattened.request_parameters.sourceIdentity` (Elastic flattened leaf. The persisted copy json.userIdentity.sessionContext.sourceIdentity is renamed to aws.cloudtrail.user_identity.session_context.source_identity (keyword with NO ignore_above in fields.yml).)

**Length evidence (verified):**

STS API reference: SourceIdentity 'Minimum length of 2. Maximum length of 64.' This holds for the AssumeRole request and for the AssumeRoleWithSAML/AssumeRoleWithWebIdentity response elements. The IAM User Guide (source-identity page and SAML attribute page) instead says '2 and 256 characters'. Because the API model and the response elements say 64, 64 is the conservative intact bound. ASCII only. original + payload <= 64.

**Character evidence:**

STS pattern [\w+=,.@-]*; the IAM guide gives the same set. The value cannot begin with 'aws:'. That rule cannot be hit anyway, because ':' is not in the charset. Verified: compiles as a single class.

**Attacker control:**

Set at assume time only if the role trust policy grants sts:SetSourceIdentity (required for all IdP-connected roles). The value is immutable for the session and persists through role chaining. SAML/OIDC values come from the IdP. If sts:SourceIdentity conditions pin it, the attacker cannot choose it.

**Truncation and ingest:**

Never truncated. Correction: the ECS twin aws.cloudtrail.user_identity.session_context.source_identity has no ignore_above in the integration's fields.yml (the earlier claim of 1024 was wrong). Irrelevant at 64 characters. Keyword form 'sourceIdentity=<v>' is unescaped.

**Unverified:**

- AWS docs conflict on the maximum: the STS API reference says 64, the IAM User Guide says 256. Whether STS actually accepts 65-256 characters (especially via the SAML/OIDC paths) was not tested. 64 is used as the safe bound.

**Sources:**

- <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html>: SourceIdentity min 2 max 64, pattern [\w+=,.@-]*, aws: prefix reserved
- <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html>: SourceIdentity response element 2-64 with the same pattern
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html>: Conflicting statement: source identity 2-256 characters; sts:SetSourceIdentity requirement; OIDC claim name
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html>: SAML SourceIdentity attribute stated as 2-256 characters, same charset
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html>: requestParameters.sourceIdentity in AssumeRole/SAML/OIDC events; sessionContext.sourceIdentity persistence
- <https://raw.githubusercontent.com/elastic/integrations/main/packages/aws/data_stream/cloudtrail/fields/fields.yml>: user_identity.session_context.source_identity keyword without ignore_above

### `aws.cloudtrail.request_parameters.userName`

**Registry summary.** IAM CreateUser UserName: 1 to 64 characters from [A-Za-z0-9_+=,.@-]. For events other than CreateUser the name must already exist, so the payload has to be part of the user's name from creation.

**Character class:** `[A-Za-z0-9_+=,.@-]`

**Where it appears:**

- cloudtrail: `requestParameters.userName` (iam:CreateUser. Afterwards, every IAM call that references the user (GetUserPolicy, AddUserToGroup, AttachUserPolicy, PutUserPolicy, CreateAccessKey, DeleteUser, ...). requestParameters.newUserName on UpdateUser.)
- ecs: `user.target.name` (Elastic: set user.target.name copy_from json.requestParameters.userName. related.user is appended from '{{{json.requestParameters.userName}}}' (triple-mustache, so not HTML-escaped). newUserName goes to user.changes.name. ECS mapping: keyword ignore_above 1024 + match_only_text.)

**Length evidence (verified):**

IAM CreateUser UserName: 'Minimum length of 1. Maximum length of 64.' The IAM quotas table says 'User name 64 characters'. ASCII only. The API rejects longer values. original + payload <= 64. For any event other than CreateUser, the name must be an existing user's name, so the payload must be baked in at CreateUser/UpdateUser time.

**Character evidence:**

IAM CreateUser pattern [\w+=,.@-]+. The IAM quotas page: names 'must be alphanumeric, including ... + = , . @ _ -'. Case-insensitive for uniqueness, but case is preserved in logs. Verified: compiles as a single class.

**Attacker control:**

Full control with iam:CreateUser (or newUserName via iam:UpdateUser). The value is echoed in user.target.name and related.user, which analysts and rules read directly.

**Truncation and ingest:**

64 is far below ignore_above 1024 on user.target.name/related.user, the 8191 keyword limit and 100 KB. Never truncated. Keyword form 'userName=<v>'. Do not confuse with userIdentity.userName, where failed ConsoleLogin with a wrong user name is masked as HIDDEN_DUE_TO_SECURITY_REASONS.

**Sources:**

- <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html>: UserName min 1 max 64, pattern [\w+=,.@-]+
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>: User name 64 characters; allowed name characters
- <https://raw.githubusercontent.com/elastic/integrations/main/packages/aws/data_stream/cloudtrail/elasticsearch/ingest_pipeline/default.yml>: user.target.name copy_from userName; user.changes.name from newUserName; related.user appends
- <https://raw.githubusercontent.com/elastic/ecs/main/generated/elasticsearch/composable/component/user.json>: user.target.name and user.changes.name keyword ignore_above 1024
- <https://github.com/elastic/integrations/tree/main/packages/aws/data_stream/cloudtrail/_dev/test/pipeline>: test-create-user-json.log: requestParameters {userName: Bob} rendered as '{userName=Bob}'

### `aws.cloudtrail.request_parameters.groupDescription`

**Registry summary.** EC2 CreateSecurityGroup GroupDescription: up to 255 characters from a documented ASCII set (letters, digits, space and ._-:/()#,@[]+=&;{}!$*). The API rejects anything else.

**Character class:** `[A-Za-z0-9 ._:/()#,@+=&;{}!$*\[\]-]`

**Where it appears:**

- cloudtrail: `requestParameters.groupDescription` (ec2:CreateSecurityGroup. requestParameters is {groupName, groupDescription, vpcId} in a captured third-party sample event. groupName has the same 255 limit and charset and is also attacker-controlled.)
- ecs: `aws.cloudtrail.flattened.request_parameters.groupDescription` (Elastic flattened leaf (absent under retain=minimal/keyword/none); substring 'groupDescription=<v>' in the keyword.)

**Length evidence (verified):**

EC2 CreateSecurityGroup GroupDescription: 'Constraints: Up to 255 characters in length'. The valid set is ASCII, so characters = bytes. Rejected at the API, far below every storage limit. original + payload <= 255.

**Character evidence:**

EC2 doc: 'Valid characters: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*'. The class contains exactly these, and compiles as a single Python class. It includes spaces, braces and brackets, so it is a strong natural-language surface. The documented set is used even though EC2's real enforcement may be looser (unverified).

**Attacker control:**

Full control with ec2:CreateSecurityGroup: free text chosen at creation time, logged in the CreateSecurityGroup event that analysts review for perimeter changes.

**Truncation and ingest:**

No per-field truncation. '=', ', ', '{', '}', '[' and ']' make the toString keyword form ambiguous. Exact in flattened and _source.

**Unverified:**

- No AWS-primary CloudTrail sample for CreateSecurityGroup was found; the field name rests on a third-party captured event plus EC2's lowerCamelCase convention
- Whether EC2 enforces exactly the documented set or accepts any printable ASCII

**Sources:**

- <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSecurityGroup.html>: GroupDescription and GroupName up to 255 chars; valid character list; GroupName cannot start with sg-
- <https://docs.blinkops.com/docs/integrations/aws/triggers/new-security-group>: Third-party captured CreateSecurityGroup event: requestParameters {groupName, groupDescription, vpcId} (secondary source)
- <https://github.com/elastic/integrations/tree/main/packages/aws/data_stream/cloudtrail/_dev/test/pipeline>: EC2 CloudTrail lowerCamelCase keys (RunInstances fixture: instanceType, tagSpecificationSet)

### `aws.cloudtrail.request_parameters.description`

**Registry summary.** The requestParameters.description key carries IAM role and policy descriptions (1,000) and KMS key descriptions (8,192); Lambda (probably 256) uses it too, but its key casing is unverified, and services such as Directory Service (128) are not covered. 256 is conservative for IAM and KMS only. Characters are narrowed to printable ASCII until the KMS character set is verified.

**Character class:** `[\x20-\x7e]`

**Where it appears:**

- cloudtrail: `requestParameters.description` (Scoped to eventSource iam.amazonaws.com: CreateRole, UpdateRole, CreatePolicy (IAM uses lowerCamelCase keys, e.g. policyName/policyDocument in the fixture). The same raw key is used by KMS CreateKey (lowercase 'description', confirmed in the KMS ct-createkey example; max 8192) and probably Lambda CreateFunction20150331 (max 256). Those need separate per-service entries with their own max_length.)
- cloudtrail: `requestParameters.CreateTrafficMirrorFilterRuleRequest.Description` (EC2 traffic-mirror calls: nested, capitalized key (confirmed in Elastic fixture test-create-traffic-mirror-filter-rule-json.log). This is a different raw field and needs its own limit.)

**Length evidence (verified):**

IAM CreateRole, UpdateRole and CreatePolicy Description: 'Maximum length of 1000'. Valid only when eventSource=iam.amazonaws.com. For the same raw key elsewhere: KMS CreateKey 8192, Lambda CreateFunction 256. A registry keyed only by raw field name, without eventSource, must use the smallest applicable limit (256 if Lambda is in scope). original + payload <= 1000 for IAM.

**Character evidence:**

IAM CreateRole and UpdateRole Description pattern [\u0009\u000A\u000D -~¡-ÿ]* (U+00A0 excluded). In a Python str pattern \xa1-\xff means U+00A1-U+00FF, which is correct. Compiles as a single class. Correction: CreatePolicy Description publishes NO pattern, so this class is a conservative assumption for CreatePolicy. KMS and Lambda descriptions also publish no pattern.

**Attacker control:**

Full control with iam:CreateRole/UpdateRole/CreatePolicy: attacker-written free text with spaces, full ASCII punctuation, Latin-1 and TAB/LF/CR. KMS says its Description 'may be displayed in plaintext in CloudTrail logs', so it is not redacted.

**Truncation and ingest:**

No per-field truncation at 1000. A KMS description near 8192 alone exceeds Elastic's ignore_above 8191 for the whole aws.cloudtrail.request_parameters keyword: the value is kept in _source and the flattened leaf, but the keyword is not indexed. TAB/LF/CR are JSON-escaped by CloudTrail and appear raw in the Painless toString keyword. Lambda environment variables are omitted from CloudTrail (the fixture shows environment {}). Policy descriptions are immutable after creation.

**Unverified:**

- IAM CreateRole/CreatePolicy CloudTrail key spelled 'description' (consistent with IAM lowerCamelCase fixtures, but no sample containing a description was captured)
- Lambda CreateFunction CloudTrail key casing for description
- CreatePolicy, KMS and Lambda description charsets (no AWS pattern published)
- EC2 traffic-mirror Description length limit (the earlier '~255' was not checked)

**Sources:**

- <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html>: Description max 1000; pattern [\u0009\u000A\u000D -~¡-ÿ]*
- <https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateRole.html>: Description max 1000, same pattern
- <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html>: Description max 1000; no pattern published; immutable
- <https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html>: Description 0-8192; plaintext-in-CloudTrail warning
- <https://docs.aws.amazon.com/kms/latest/developerguide/ct-createkey.html>: KMS CreateKey CloudTrail requestParameters uses lowercase 'description'
- <https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html>: Description 0-256; Environment 'Omitted from AWS CloudTrail logs'
- <https://github.com/elastic/integrations/tree/main/packages/aws/data_stream/cloudtrail/_dev/test/pipeline>: Traffic-mirror nested capitalized Description; IAM lowerCamelCase keys; Lambda environment {}

## Researched but not in the registry yet

These need a placement or schema tracebait does not support yet, or no v0.1 pack uses them.

- `aws.cloudtrail.request_parameters`: 100000 (confidence medium). CloudTrail record-contents doc: requestParameters 'has a maximum size of 100 KB. When the field size exceeds 100 KB, the requestParameters content is omitted' (on 1 MB-max event data stores it is omitted only if the whole event payload exceeds 1 MB). AWS does not say whether KB means 1000 or 1024 by
- `aws.cloudtrail.request_parameters.key`: 1024 (confidence medium). S3: 'maximum length of 1,024 bytes' UTF-8, prefixes included. This limit is in UTF-8 BYTES, not characters. tracebait must enforce len((original+payload).encode('utf-8')) <= 1024: for pure ASCII that is 1024 characters, fewer with multibyte characters. Rejected at the S3 API, far below 100 KB and th
- `aws.cloudtrail.request_parameters.tags.key`: 128 (confidence medium). IAM Tag.Key and STS Tag.Key: 'Minimum length of 1. Maximum length of 128.' EC2: 'Maximum key length – 128 Unicode characters in UTF-8'. Resource Groups Tagging API key max 128. The API enforces it, far below storage limits. original + payload <= 128 characters. For the portable charset (ASCII plus B
- `aws.cloudtrail.request_parameters.tags.value`: 256 (confidence medium). IAM Tag.Value and STS Tag.Value: 'Minimum length of 0. Maximum length of 256.' EC2: 256 Unicode characters in UTF-8. Resource Groups Tagging API value max 256. The API enforces it. original + payload <= 256.
- `dns.question.subdomain`: 248 (confidence medium). subdomain = dns.question.name minus '.' + registered_domain, with no trailing period (ECS). Its limit is 253 - len(registered_domain) - 1. The shortest real registered domain is 4 characters (1-char label + 2-letter TLD, e.g. 't.co'; no single-letter TLD exists), giving a cap of 248. Tracebait shoul
- `file.path`: 1024 (confidence medium). 1024 characters is a conservative cap, not a truncation point. It is the ECS ignore_above on the file.path keyword. Longer values stay intact in _source and in the file.path.text match_only_text sub-field, but are not indexed as keywords, so term and aggregation queries on file.path stop seeing them
- `iis.access.user_agent`: 4096 (confidence medium). Microsoft KB 2809913 (original product version IIS 8.0; its example log is IIS 7.5) says the length of each IIS log field value is limited to 4096 bytes, and a value 'greater than 4096 bytes' is replaced by '...'. The value is replaced outright, not truncated.
- `process.executable`: 255 (confidence medium). 255 UTF-16 code units, set by Sysmon rather than by the OS. In SysmonCommon, Image fields resolved from a process ID go through FetchImageName into TCHAR tmpStringBuffer[256], copied with _tcsncpy_s(..., _TRUNCATE). These are ProcessTerminate EID 5 Image, CreateRemoteThread EID 8 SourceImage and Tar
- `winlog.event_data.QueryName`: 253 (confidence medium). Plausibility/resolvability limit, not a logger limit. DnsValidateName says Windows treats names over 255 octets, labels over 63 octets, consecutive dots and a leading dot as ERROR_INVALID_NAME, so a resolvable name is at most 253 characters, or 254 with the trailing dot that Sysmon keeps verbatim (e
- `zeek.dns.query`: 253 (confidence high). RFC 1035 wire limit (255 octets) gives 253 characters, and Zeek strips the trailing dot. Zeek enforces the 63-octet label limit: a longer label is a ParseError with a 'DNS_label_too_long' weird (except when the responder port is 137, NetBIOS), dns_request is not raised, and the query field stays uns

## Verifier corrections

### command_line (32 claims checked, 12 corrected or unverifiable)

- **unverifiable**, `process.command_line`: No other Sysmon string cap applies (not stated in the original) → eventsCommon.cpp also defines PATH_MAX_SIZE 31839 and TrimStringIfNeeded ('Command line can be up to 0x7FFE but event log strings have a limit of 31839'), but nothing in the common code calls it. Whether the Windows-only code calls it is unknown. It would not change the bound, since 31,839 is above the ~30.4K budget ceiling.
- **corrected**, `process.command_line`: The legacy pre-Vista ReportEvent path limits each string to 31,839 characters → ReportEventW doc: 'Each string is limited to 31,839 characters. Prior to Windows Vista: Each string is limited to 32K characters.' So 31,839 applies to Vista and later, not pre-Vista. Sysmon uses EventWrite on Vista and later (eventsCommon.cpp bPreVista branch), so ReportEvent is not the active path.
- **unverifiable**, `process.command_line`: 4688 behaviour near 32K is unverified; best estimate intact up to at least 8,191 → New lower evidence: a 5,137-character CommandLine is intact in an OTRF 4688 record (measured). The Hexacorn post ?p=7053 is unreachable (ECONNREFUSED; web.archive blocked). A search snippet says 4688 'completely missed' the process created with a very long command line, length unknown. 8,191 for 4688 remains an estimate.
- **corrected**, `process.command_line`: 8,191 'works for every launch path and every target store in this family' → Measured splunk/attack_data T1003.001 windows-sysmon.log: EID 1 overhead without CommandLine and ParentCommandLine is 1,325-1,960 bytes. Under the default TRUNCATE=10000 that leaves 5,299-8,066 bytes (median 8,066) for CommandLine given each record's own parent. attack_data replay.py posts to HEC services/collector/raw, so parse-time TRUNCATE applies. OTRF JSON records with a 5,137-character command line are already ~13.3 KB. max_length 8191 is kept as the field cap, but the basis now requires a per-record Splunk line budget, or TRUNCATE=0.
- **unverifiable**, `process.command_line`: Splunk Windows/Sysmon TAs may override TRUNCATE (unverified) → No public current Splunk_TA_windows or Splunk_TA_microsoft_sysmon repo was found (GitHub API 404). An old fork (linearregression/TA-microsoft-sysmon 3.2.1, 2016) has a stanza [XmlWinEventLog:Microsoft-Windows-Sysmon/Operational] with no TRUNCATE.
- **corrected**, `process.command_line`: Winlogbeat replaces C0 controls with literal \uNNNN (PR 11006); CRLF and TAB escaping was reverted (PR 11357); DEL and C1 are excluded only as a precaution → Both PRs confirmed (merged 2019-03-01 and 2019-03-21; 11357 changed the condition to !unicode.IsSpace && unicode.IsControl). The current code is libbeat/common/encoding/xml/safe_reader.go, with condition code == utf8.RuneError || (!IsSpace && IsControl). IsControl covers U+0000-001F and U+007F-009F, so DEL and C1 are rewritten too: their exclusion is evidence-based, not a precaution. Literal U+FFFD equals utf8.RuneError and is also rewritten. Because the reader advances one byte, multi-byte runes leave extra \ufffd text. VT, FF and NEL pass the reader because they count as spaces, and Go xml rejects VT and FF.
- **corrected**, `process.command_line`: charset_regex_class [^\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff<U+FFFE><U+FFFF>] compiles and is a single bracket class → It compiles as a single IN class (re/sre_parse check), but it accepts U+FFFD, which Winlogbeat does not log faithfully. It also embeds literal noncharacters that can be mangled in transport. Replaced by [^\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff\ufffd-\uffff], which was verified to compile as a single class. It accepts TAB, LF, space, NBSP, é and emoji, and rejects CR, VT, NUL, DEL, NEL, U+FFFD-FFFF and lone surrogates.
- **unverifiable**, `process.command_line`: Event Viewer cannot render events that contain ESC → Not found in any source checked. The beats PRs show only that Go's XML parser rejected U+001B. The claim was dropped from the basis.
- **corrected**, `process.command_line`: splunk/attack_data stores one <Event> per line; the longest line in T1003.001 windows-sysmon.log is 7,487 bytes; &amp; and &gt; are escaped → The file is 7,960 events on 7,975 physical lines because 4 command lines contain a raw LF, so the format is not strictly one event per line. The longest event is 7,486 bytes without the newline (7,487 counts it). Entities seen are &amp; and &gt;. Raw double quotes are unescaped, and there are no CR characters.
- **corrected**, `process.parent.command_line`: At 8,191 for both fields the total is about 34-35 KB → 4 x 8,192 + ~1,056-1,090 other bytes = ~33.8-33.9 KB, still well under 62,000, so the conclusion (no trimming) stands.
- **corrected**, `process.parent.command_line`: OTRF ParentCommandLine observed length 75 → 75 is only the parent of the 5,137-character record. The longest ParentCommandLine in empire_launcher_vbs is 5,137 (children of that process), and it is repeated verbatim in Message (verified).
- **corrected**, `process.parent.command_line`: charset_regex_class same as process.command_line → The same correction applies: U+FFFD is now excluded and U+FFFE/U+FFFF are written as escapes. The new class was verified to compile as a single Python re class.

### user_agent (34 claims checked, 10 corrected or unverifiable)

- **corrected**, `user_agent.original`: max_length 8178 is the binding end-to-end limit; 'ALB truncates user_agent only above 8 KB, so it does not bind' → ALB docs: user_agent is truncated 'if the string is longer than 8 KB', while the ALB quota allows a single header of 16 K. AWS does not define 8 KB as 8000 or 8192. Under the 8000 reading, ALB truncation binds below 8178. max_length lowered to 8000, the floor that is safe under both readings and consistent with the 1 KB -> 1000 choice for CloudTrail. 8178 stays valid for records that come only from nginx or Apache.
- **corrected**, `user_agent.original`: nginx exact boundary unverified (8177-8180); 8192 buffer vs CRLF and > vs >= → Resolved in ngx_http_request.c ngx_http_alloc_large_header_buffer: the line is declined when (header_in->pos - header_name_start) >= large_client_header_buffers.size, which only happens when the buffer is full with no LF. The line including CRLF must therefore fit in 8192 bytes: 12 + value + 2 <= 8192, so the value is at most exactly 8178 (8179 with a bare LF or no SP). The claim moves from unverified to confirmed.
- **corrected**, `user_agent.original`: Apache: LimitRequestFieldSize 8190 bytes; ap_rgetline(limit+2); 8190-12 = 8178 'matches Apache exactly' → Docs confirm the default 8190 bytes, and 2.4.x protocol.c confirms ap_rgetline(r->server->limit_req_fieldsize + 2) with a 400 'Size of a request header field exceeds server limit.' However, ap_rgetline_core can return up to n-1 = 8191 bytes: when the CR fits and only the LF overruns, the line is accepted (saw_eol = 2). Apache therefore accepts a value of up to 8179 with one SP. table_do_fn_check_lengths also caps the merged value at 8190. 8178 is the always-accepted bound, not an exact match.
- **corrected**, `user_agent.original`: nginx treatment of NUL/control bytes in header values unverified → Resolved in ngx_http_parse.c ngx_http_parse_header_line: only '\0' returns NGX_HTTP_PARSE_INVALID_HEADER. Other control bytes are accepted and later escaped as \xXX in the log. Only SP (not HTAB) is trimmed before and after the value.
- **corrected**, `user_agent.original`: Zeek JSON keeps valid UTF-8 and writes invalid bytes and unprintable controls as \xHH → In util.cc escape_utf8, once any invalid or disallowed sequence is found (C0/C1 controls, PUA, U+FFF0-FFFF), the escaped variant is returned and every non-ASCII byte of the value, including valid UTF-8, becomes \xHH. The original claim was only partly right.
- **corrected**, `user_agent.original`: In the ECS composable template user_agent.original is keyword ignore_above 1024 with .text match_only_text (implying Elastic deployments do not keyword-index >1024) → The ECS repo generated/composable/component/user_agent.json does have ignore_above 1024, but the Elastic integrations (nginx, iis, aws) define no user_agent field. On 8.13+ Fleet relies on Elasticsearch's ecs@mappings, whose 'ecs_path_match_keyword_and_match_only_text' dynamic template maps *user_agent.original as keyword plus match_only_text with no ignore_above. logsdb mode adds an index-level ignore_above of 8191. The 1024 caveat applies only to ECS-repo or Beats-style templates. No template truncates.
- **unverifiable**, `user_agent.original`: rsyslog/syslog shipping limits not researched → A search of rsyslog docs shows maxMessageSize defaults to 8K with larger messages truncated, though one dev-branch page says 4K. The rsyslog site refused the connection, so the page could not be fetched; this stays in unverified as a deployment-specific limit on the whole line. nginx itself does not truncate syslog or file access-log lines (ngx_http_log_module.c sizes the line exactly).
- **corrected**, `iis.access.user_agent`: IIS customFields / maxCustomFieldLength could not be fetched; custom-field UA logging may allow more → Resolved from Microsoft Learn customFields: introduced in IIS 8.5 and unchanged in IIS 10. maxCustomFieldLength defaults to 4096 bytes (range 2-65536), and custom data totals at most 65536 bytes, beyond which it is truncated. A custom field defaults to the same 4096; more is possible only if an admin raises it.
- **corrected**, `aws.cloudtrail.user_agent`: Truncation applies at the source, so it affects every downstream copy (S3 trail files, Event history, EventBridge) → Per the doc, 1 MB-event Lake stores keep the full userAgent unless the event exceeds 1 MB. CloudTrail therefore holds the untruncated value, and truncation depends on the destination rather than happening at the source. Trails, Event history and 256 KB stores are truncated; the doc says nothing about EventBridge.
- **corrected**, `aws.cloudtrail.user_agent`: S3 data events commonly show the UA wrapped in square brackets (not confirmed) → AWS's own S3 CloudTrail example page shows "userAgent": "[]" in all three records, so bracket wrapping is confirmed for S3. Added the rule: insert the payload before the closing ']' and count the brackets inside the 1000 budget.

### dns_query (37 claims checked, 7 corrected or unverifiable)

- **corrected**, `dns.question.name`: Packetbeat always adds/keeps the trailing dot on dns.question.name; trimRightDot is applied only to answers → packetbeat/protos/dns/dns.go decodeDNSData has 'msg.Question[i].Name = trimRightDot(q.Name)' under '// Normalize question names', also present in v8.0.0. Packetbeat question names have NO trailing dot; only Sysmon-sourced values keep one.
- **unverifiable**, `dns.question.name`: DNS 0x20 case randomization makes uppercase unreliable on egress sensors → No primary source fetched; left in unverified.
- **corrected**, `winlog.event_data.QueryName`: 9003 NXDOMAIN records as companion state (implicitly with no results) → In splunk long_dns_queries, some 9003 records carry SOA-style QueryResults 'type:  6 ;10.0.1.14;', so the harness should not assume '-' for 9003.
- **unverifiable**, `winlog.event_data.QueryName`: Over-long labels are logged with status 123 and never reach the wire → The logging with status 123 is confirmed; 'never reach the wire' is an inference from client-side ERROR_INVALID_NAME and was moved to unverified.
- **unverifiable**, `winlog.event_data.QueryName`: QueryName is a UTF-16 string (win:UnicodeString) → Only third-party copies of the Sysmon manifest were found; no Microsoft page states the inType. Plausible and harmless for ASCII.
- **corrected**, `winlog.event_data.QueryName`: splunk nslookup_exfil has 565 nslookup references and 0 EID 22 events → Streamed file (5.66 MB): 678 occurrences of 'nslookup' (occurrence count; the 565 may have been a line count), 0 <EventID>22</EventID> records in total; base64 'VXNlck5hbWU6IEd1ZXN0' present 6 times. Since there are no EID 22 records at all, this is not evidence about nslookup.
- **corrected**, `zeek.dns.query`: Names of 255 octets or more are logged with a DNS_NAME_too_long weird → ExtractName: n = dotted length including Zeek's trailing dot; 'if (n >= 255) Weird'. This fires only for wire length > 255; a compliant 253-char name (n = 254) gets no weird. Parsing continues, so over-limit names are still logged.

### file_name (36 claims checked, 12 corrected or unverifiable)

- **corrected**, `file.name`: Reserved device names are CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without an extension → Naming Files also reserves COM and LPT with superscript digits 1-3 (ISO 8859-1 superscripts are treated as digits).
- **corrected**, `file.name`: TargetFilename appears in Sysmon EID 2, 11, 15, 23, 26 → Confirmed in the SysmonCommon manifest for 2, 11, 15, 23 and 26. EID 27, 28 and 29 (Sysinternals event table) were added; EID 29 TargetFilename is per Splunk security_content and not confirmed in the manifest.
- **corrected**, `file.name`: charset_regex_class is a single, valid Python re character class → It compiles in Python 3 and passes a single-class check, and accept/reject tests behave as intended. It was rewritten to use backslash-ufffe and backslash-uffff escapes instead of literal noncharacters, which do not survive copy and paste reliably. The behavior is the same.
- **corrected**, `file.name`: No other Winlogbeat source writes file.name → sysmon.yml also renames winlog.event_data.PipeName (EID 17/18) to file.name. Pipe names have different limits (whole name up to 256 characters per Microsoft Learn Pipe Names), so they are flagged as out of scope.
- **corrected**, `file.path`: ECS ignore_above 1024 is the binding limit → The Elasticsearch ignore_above doc says longer values are not indexed but 'will still be present in the _source field', and that ignore_above has no effect in columnar index modes. It is a soft index cap, not truncation. 1024 is kept as a conservative cap because every hard limit is higher: Splunk TRUNCATE 10,000 bytes per line, ETW 64KB minus header, Sysmon PATH_MAX_SIZE 31839, extended-length paths of about 32,767.
- **corrected**, `file.path`: NTFS path limit is 32,760 characters (with no per-component rule stated) → The comparison table says '32,760 Unicode characters with each path component no more than 255 characters'. The spec omitted the per-component limit, which binds when the payload contains no backslash. It was added to max_length_basis.
- **corrected**, `file.path`: The real ceilings come from the 62,000-byte event packet cap → eventsCommon.cpp defines MAX_EVENT_PACKET_SIZE 62000, but checks it only for SYSMONEVENT_CREATE_PROCESS_Type and trims only ParentCommandLine and CommandLine. It does not bound TargetFilename. The relevant ceilings are the ETW 64KB-minus-header event limit and PATH_MAX_SIZE 31839, which matches the ReportEvent 31,839-character per-string limit.
- **corrected**, `file.path`: Security ObjectName for 4656/4663/4660 → The 4660 doc's EventData has no ObjectName (only HandleId), and the doc says the event does not contain the object name. 4663 ObjectName is confirmed. No processor in security_standard.yml references ObjectName (both halves of the file checked).
- **corrected**, `file.path`: The charset class allows backslash and compiles → It compiles as a single class, and backslash is accepted. Rewritten with backslash-ufffe and backslash-uffff escapes. Structural normalization rules from the .NET path formats doc were added (separator runs collapse; '.' and '..' are removed; trailing periods are trimmed).
- **corrected**, `process.executable`: max_length 259 because CreateProcess limits the module name to MAX_PATH → The CreateProcessW doc limits the module name to MAX_PATH only 'If lpApplicationName is NULL'. A Bazel commit (third party) reports that an extended-length lpApplicationName runs longer paths. Sysmon resolves PID-based Image fields (EID 5, 8 Source/TargetImage, 9, 25) through FetchImageName into tmpStringBuffer[256] with _TRUNCATE, which keeps at most 255 characters per the CRT docs. Lowered to 255 so every copy survives intact.
- **unverifiable**, `file.name`: OTRF Sysmon JSON uses top-level TargetFilename and Image keys and repeats them in Message → The msticpy Mordor docs show OTRF records as flat DataFrames with a Message column holding rendered Sysmon text, which is consistent with the claim. No raw OTRF file was opened, because the datasets are zip archives.
- **unverifiable**, `file.path`: splunk/attack_data XML uses <Data Name='TargetFilename'> and escapes & as &amp; → The windows-sysmon.log sample exceeded the 10 MB fetch limit. &amp; escaping is required by XML; the single-quote style was not re-checked.

### cloudtrail_params (40 claims checked, 14 corrected or unverifiable)

- **corrected**, `aws.cloudtrail.request_parameters`: requestParameters cap is 100 KB = 102,400 bytes; whole object omitted, not truncated → CloudTrail record-contents: 'maximum size of 100 KB. When the field size exceeds 100 KB, the requestParameters content is omitted.' The omit rule is confirmed, but AWS never says KB = 1024. max_length lowered to the conservative 100000.
- **corrected**, `aws.cloudtrail.request_parameters`: Flattened twin is populated when Retain includes flattened/all/minimal → True for gating, but under retain=minimal script_retain_minimal_flattened keeps only cidrIp, serialNumber and withDecryption in flattened.request_parameters. remove_9365dd2c deletes the keyword unless retain is all/keyword/minimal. Default retain is 'all' (cloudtrail manifest.yml).
- **corrected**, `aws.cloudtrail.request_parameters`: Elastic AWS integration package 8.15.0 → packages/aws/manifest.yml on main shows version 8.17.0 (kibana ^9.6.0) at check time. Behaviour was re-verified on main.
- **corrected**, `aws.cloudtrail.request_parameters`: Container charset [^\x00-\x1f\x7f] (no control chars survive) → IAM CreateRole/UpdateRole Description pattern admits \u0009, \u000A and \u000D. They round-trip through CloudTrail JSON and appear raw in the toString keyword. Class changed to [^\x00-\x08\x0b\x0c\x0e-\x1f\x7f].
- **unverifiable**, `aws.cloudtrail.request_parameters.sourceIdentity`: SourceIdentity max 64, cannot begin with aws: → STS API ref (AssumeRole request; AssumeRoleWithSAML/WebIdentity response) says 2-64, but IAM User Guide source-identity and SAML attribute pages say '2 and 256 characters'. Kept 64 as the conservative bound and lowered confidence to medium. The aws: prefix rule is confirmed, though ':' is outside the charset anyway.
- **corrected**, `aws.cloudtrail.request_parameters.sourceIdentity`: ECS aws.cloudtrail.user_identity.session_context.source_identity is keyword ignore_above 1024 → fields.yml defines source_identity as keyword with no ignore_above; only request_parameters and response_elements carry ignore_above (8191).
- **corrected**, `aws.cloudtrail.request_parameters.tags.key`: STS principalTags and incomingTransitiveTags render as 'tags=[{value=.., key=..}]' → IAM CloudTrail examples: principalTags {"CostCenter": "987654", ...} and incomingTransitiveTags {"Department": "Engineering"} are maps keyed by tag key. Only the AssumeRole 'tags' parameter is a list of {value,key}. Added aliases for both maps.
- **unverifiable**, `aws.cloudtrail.request_parameters.tags.key`: EC2 CreateTags uses requestParameters.tagSet items → No primary CreateTags CloudTrail sample found; left in unverified.
- **corrected**, `aws.cloudtrail.request_parameters.key`: Charset [^\x00-\x1f\x7f] → Also excludes C1 controls U+0080-U+009F (S3 avoid list) and lone surrogates U+D800-U+DFFF (not UTF-8 encodable, so they can never reach S3): [^\x00-\x1f\x7f-\x9f\ud800-\udfff]. Compiles as a single class.
- **corrected**, `aws.cloudtrail.request_parameters.key`: confidence high → Lowered to medium: CloudTrail raw-vs-percent-encoded key storage remains unverified, and the Elastic PutObject fixture lacks requestParameters.key entirely.
- **corrected**, `aws.cloudtrail.request_parameters.description`: IAM description pattern [\u0009\u000A\u000D -~¡-ÿ] applies to IAM-style descriptions generally → The pattern is published for CreateRole and UpdateRole only. CreatePolicy Description lists a length constraint but no pattern, so the class is a conservative assumption there.
- **corrected**, `aws.cloudtrail.request_parameters.description`: KMS CreateKey description key is capitalized 'Description' in CloudTrail → KMS developer guide ct-createkey examples show requestParameters {"description": "", "origin": ..., "keySpec": ...}: lowercase.
- **unverifiable**, `aws.cloudtrail.request_parameters.description`: EC2 traffic-mirror Description ~255 → Not checked against the EC2 API reference; flagged in unverified.
- **corrected**, `aws.cloudtrail.request_parameters.description`: max_length 1000 as the binding limit for requestParameters.description → KMS (8192) and probably Lambda (256) share the same raw key. 1000 binds only for eventSource=iam.amazonaws.com, so event_types are now scoped to IAM, with per-service limits stated.

