/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2014, CodeTickler, Inc
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#ifndef S2E_LINUX_MONITOR

#define S2E_LINUX_MONITOR

#include "s2e.h"

#define S2E_LINUXMON_COMMAND_VERSION 0x201611031025ULL // date +%Y%m%d%H%M

enum S2E_LINUXMON_COMMANDS {
    SEGMENT_FAULT,
    ELFBINARY_LOAD,
    LIBRARY_LOAD,
    DIVIDE_BY_ZERO,
    TASK_EXIT,
    TASK_SWITCH
};

struct S2E_LINUXMON_COMMAND_ELFBINARY_LOAD {
    uint64_t process_id;

    uint64_t entry_point;

    uint64_t header;
    uint64_t start_code;
    uint64_t end_code;
    uint64_t start_data;
    uint64_t end_data;
    uint64_t start_stack;

    char process_path[128]; // not NULL terminated
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_SEGMENT_FAULT {
    uint64_t pc;
    uint64_t address;
    uint64_t fault;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_LIBRARY_LOAD {
    char library_path[128]; // not NULL terminated
} __attribute__((packed));


struct S2E_LINUXMON_COMMAND_DIVIDE_BY_ZERO {
    uint64_t fault_pc;
    uint64_t sig_code;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_TASK_EXIT {
    uint64_t code;
} __attribute__((packed));

#define TP(x) task_pre_ ## x
#define TN(x) task_nxt_ ## x
struct S2E_LINUXMON_COMMAND_TASK_SWITCH {
    uint64_t TP(pid);
    uint64_t TP(entry_point);
    uint64_t TP(header);
    uint64_t TP(start_code);
    uint64_t TP(end_code);
    uint64_t TP(start_data);
    uint64_t TP(end_data);
    uint64_t TP(start_stack);
    uint64_t TP(page_dir);
    char     TP(process_path[128]);

    uint64_t TN(pid);
    uint64_t TN(entry_point);
    uint64_t TN(header);
    uint64_t TN(start_code);
    uint64_t TN(end_code);
    uint64_t TN(start_data);
    uint64_t TN(end_data);
    uint64_t TN(start_stack);
    uint64_t TN(page_dir);
    char     TN(process_path[128]);
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND {
    uint64_t version;
    enum S2E_LINUXMON_COMMANDS Command;
    uint64_t currentPid;
    union {
        struct S2E_LINUXMON_COMMAND_ELFBINARY_LOAD ElfBinaryLoad;
        struct S2E_LINUXMON_COMMAND_LIBRARY_LOAD LibraryLoad;
        struct S2E_LINUXMON_COMMAND_SEGMENT_FAULT SegmentFault;
        struct S2E_LINUXMON_COMMAND_DIVIDE_BY_ZERO DividebyZero;
        struct S2E_LINUXMON_COMMAND_TASK_EXIT TaskExit;
        struct S2E_LINUXMON_COMMAND_TASK_SWITCH TaskSwitch;
    };
    char currentName[32]; // not NULL terminated
} __attribute__((packed));

static inline void s2e_linux_elfbinary_load(pid_t pid, const char *name, const struct task_struct *t, const void *hdr, size_t hdr_size, const char *path, uintptr_t entry)
{
	struct S2E_LINUXMON_COMMAND cmd = { 0 };
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = ELFBINARY_LOAD;
	cmd.currentPid = pid;
	strncpy(cmd.currentName, name, sizeof(cmd.currentName));
	cmd.ElfBinaryLoad.header = (uintptr_t) hdr;
	cmd.ElfBinaryLoad.start_code = t->mm->start_code;
	cmd.ElfBinaryLoad.end_code = t->mm->end_code;
	cmd.ElfBinaryLoad.start_data = t->mm->start_data;
	cmd.ElfBinaryLoad.end_data = t->mm->end_data;
	cmd.ElfBinaryLoad.start_stack = t->mm->start_stack;
	cmd.ElfBinaryLoad.process_id = t->pid;
	cmd.ElfBinaryLoad.entry_point = entry;
	strncpy(cmd.ElfBinaryLoad.process_path, path, sizeof(cmd.ElfBinaryLoad.process_path));

	__s2e_touch_buffer(hdr, hdr_size);
	s2e_invoke_plugin("LinuxMonitor2", &cmd, sizeof(cmd));
}

static inline void s2e_linux_segment_fault(pid_t pid, const char *name, uint64_t pc, uint64_t address, uint64_t fault)
{
	struct S2E_LINUXMON_COMMAND cmd = { 0 };
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = SEGMENT_FAULT;
	cmd.currentPid = pid;
	strncpy(cmd.currentName, name, sizeof(cmd.currentName));
	cmd.SegmentFault.pc = pc;
	cmd.SegmentFault.address = address;
	cmd.SegmentFault.fault = fault;

	s2e_invoke_plugin("LinuxMonitor2", &cmd, sizeof(cmd));
}

static inline void s2e_linux_dividebyzero(pid_t pid, const char *name, uint64_t sicode, uint64_t siaddr)
{
    struct S2E_LINUXMON_COMMAND cmd = { 0 };
    cmd.version = S2E_LINUXMON_COMMAND_VERSION;
    cmd.Command = DIVIDE_BY_ZERO;
    cmd.currentPid = pid;
    strncpy(cmd.currentName, name, sizeof(cmd.currentName));
    cmd.DividebyZero.fault_pc = siaddr;
    cmd.DividebyZero.sig_code = sicode;

    s2e_invoke_plugin("LinuxMonitor2", &cmd, sizeof(cmd));
}

static inline void s2e_linux_task_exit(pid_t pid, const char *name, uint64_t code)
{
    struct S2E_LINUXMON_COMMAND cmd = { 0 };
    cmd.version = S2E_LINUXMON_COMMAND_VERSION;
    cmd.Command = TASK_EXIT;
    cmd.currentPid = pid;
    strncpy(cmd.currentName, name, sizeof(cmd.currentName));
    cmd.TaskExit.code = code;

    s2e_invoke_plugin("LinuxMonitor2", &cmd, sizeof(cmd));
}

static inline void s2e_linux_task_switch(const struct task_struct *prev, const struct task_struct *next)
{
    struct S2E_LINUXMON_COMMAND cmd = { 0 };
    cmd.version = S2E_LINUXMON_COMMAND_VERSION;
    cmd.Command = TASK_SWITCH;
    cmd.currentPid = prev->pid;
    if (prev->comm)
        strncpy(cmd.currentName, prev->comm, sizeof(cmd.currentName));
    // fill previous arguments
    cmd.TaskSwitch.task_pre_end_code = (!prev->mm)? 0 : prev->mm->end_code;
    cmd.TaskSwitch.task_pre_end_data = (!prev->mm)? 0 : prev->mm->end_data;
    cmd.TaskSwitch.task_pre_entry_point = 0; // never mind
    cmd.TaskSwitch.task_pre_header = 0; // never mind
    cmd.TaskSwitch.task_pre_page_dir = (!prev->mm)? 0 : prev->mm->pgd;
    cmd.TaskSwitch.task_pre_pid = prev->pid;
    if (prev->comm)
        strncpy(cmd.TaskSwitch.task_pre_process_path, prev->comm, sizeof(cmd.TaskSwitch.task_pre_process_path)); //HACK with no path
    cmd.TaskSwitch.task_pre_start_code = (!prev->mm)? 0 : prev->mm->start_code;
    cmd.TaskSwitch.task_pre_start_data = (!prev->mm)? 0 : prev->mm->start_data;
    cmd.TaskSwitch.task_pre_start_stack = (!prev->mm)? 0 : prev->mm->start_stack;
    // fill next arguments
    cmd.TaskSwitch.task_nxt_end_code = (!next->mm)? 0 : next->mm->end_code;
    cmd.TaskSwitch.task_nxt_end_data = (!next->mm)? 0 : next->mm->end_data;
    cmd.TaskSwitch.task_nxt_entry_point = 0; // never mind
    cmd.TaskSwitch.task_nxt_header = 0; // never mind
    cmd.TaskSwitch.task_nxt_page_dir = (!next->mm)? 0 : next->mm->pgd;
    cmd.TaskSwitch.task_nxt_pid = next->pid;
    if (next->comm)
        strncpy(cmd.TaskSwitch.task_nxt_process_path, next->comm, sizeof(cmd.TaskSwitch.task_nxt_process_path)); //HACK with no path
    cmd.TaskSwitch.task_nxt_start_code = (!next->mm)? 0 : next->mm->start_code;
    cmd.TaskSwitch.task_nxt_start_data = (!next->mm)? 0 : next->mm->start_data;
    cmd.TaskSwitch.task_nxt_start_stack = (!next->mm)? 0 : next->mm->start_stack;
    s2e_invoke_plugin("LinuxMonitor2", &cmd, sizeof(cmd));
}

#endif
