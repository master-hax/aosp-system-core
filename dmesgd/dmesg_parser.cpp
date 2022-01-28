#include <cassert>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#include "dmesg_parser.h"

namespace dmesg_parser {

DmesgParser::DmesgParser() {
    std::string bug_types;
    for (auto t : kBugTypes) {
        if (bug_types.empty())
            bug_types = t;
        else
            bug_types += "|" + t;
    }
    std::string bug_re = kTimestampRe + "\\[([0-9T\\s]+)\\]\\s(BUG: (" + bug_types + "):.*)";
    this->bug_pattern = std::regex(bug_re);
    this->register_pattern = std::regex(kRegisterRe);
    this->addr64_pattern = std::regex(kAddr64Re);
}

/*
 * Read a single line terminated by a newline, and process it as follows:
 * 1. If we haven't seen a bug header, skip the current line unless it contains
 *    "BUG:".
 *    If it does, parse the line to extract the task ID (T1234), tool name
 *    (KASAN or KFENCE) and the whole report title (needed for report
 *    deduplication).
 * 2. If the current line does not contain the known task ID, skip it.
 * 3. If the current line contains a delimiter ("====="), stop accepting new
 *    lines.
 * 4. Otherwise strip potential sensitive data from the current line and append
 *    it to the report.
 */
void DmesgParser::processLine(const std::string& line) {
    std::smatch m;

    if (report_ready) return;

    // We haven't encountered a BUG: line yet.
    if (current_report.empty()) {
        if (std::regex_search(line, m, bug_pattern)) {
            assert(m.size() == 4);
            std::string task_re = kTimestampRe + "\\[" + std::string(m[1]) + "\\]\\s";
            task_line_pattern = std::regex(task_re);
            task_delimiter_pattern = std::regex(task_re + "={10,}");
            current_title = m[2];
            current_tool = m[3];
            current_report = this->stripSensitiveData(line);
        }
        return;
    }

    // If there is a delimiter, mark the current report as ready.
    if (std::regex_search(line, task_delimiter_pattern)) {
        report_ready = true;
        return;
    }

    if (std::regex_search(line, task_line_pattern)) current_report += stripSensitiveData(line);
}

/*
 * Return true iff the current report is ready (it was terminated by the "====="
 * delimiter.
 */
bool DmesgParser::reportReady() const {
    return report_ready;
}

/*
 * Return the tool that generated the currently collected report.
 */
std::string DmesgParser::reportType() const {
    return current_tool;
}

/*
 * Return the title of the currently collected report.
 */
std::string DmesgParser::reportTitle() const {
    return current_title;
}

/*
 * Return the report collected so far and reset the parser.
 */
std::string DmesgParser::flushReport() {
    report_ready = false;
    return std::move(current_report);
}

/*
 * Strip potentially sensitive data from the reports by performing the
 * following actions:
 *  1. Drop the entire line, if it contains substrings from kSkipSubstrings,
 *     e.g. process name:
 *       [   69.547684] [ T6006]c7   6006  CPU: 7 PID: 6006 Comm: sh Tainted:
 *     or hardware information:
 *       [   69.558923] [ T6006]c7   6006  Hardware name: Phone1
 *
 *  2. Drop the entire line, if it contains a memory dump, e.g.:
 *
 *        ... raw: 4000000000010200 0000000000000000 0000000000000000
 *
 *      or register dump:
 *
 *        ... RIP: 0033:0x7f96443109da
 *        ... RSP: 002b:00007ffcf0b51b08 EFLAGS: 00000202 ORIG_RAX: 00000000000000af
 *        ... RAX: ffffffffffffffda RBX: 000055dc3ee521a0 RCX: 00007f96443109da
 *
 *      (on x86_64)
 *
 *        ... pc : lpm_cpuidle_enter+0x258/0x384
 *        ... lr : lpm_cpuidle_enter+0x1d4/0x384
 *        ... sp : ffffff800820bea0
 *        ... x29: ffffff800820bea0 x28: ffffffc2305f3ce0
 *        ... ...
 *        ... x9 : 0000000000000001 x8 : 0000000000000000
 *
 *  3. For substrings that are known to be followed by sensitive information,
 *     cut the line after those substrings and append "DELETED\n",
 *     e.g. " by task ":
 *        ... Read at addr f0ffff87c23fdf7f by task sh/9971
 *     and "Corrupted memory at":
 *        ... Corrupted memory at 0xf0ffff87c23fdf00 [ ! . . . . . . . . . . . . . . . ]
 *
 *  4. Replace all strings that look like 64-bit hexadecimal values, with
 *     XXXXXXXXXXXXXXXX.
 */
std::string DmesgParser::stripSensitiveData(const std::string& line) const {
    for (auto skip : kSkipSubstrings)
        if (line.find(skip) != std::string::npos) return "";

    if (std::regex_search(line, register_pattern)) return "";

    std::string ret = line;
    for (auto infix : kCutInfix) {
        auto pos = ret.find(infix);
        if (pos != std::string::npos) {
            ret = ret.substr(0, pos + infix.size()) + "DELETED\n";
        }
    }
    ret = std::regex_replace(ret, addr64_pattern, "XXXXXXXXXXXXXXXX");
    return ret;
}

}  // namespace dmesg_parser
