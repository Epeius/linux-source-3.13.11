/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
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
 * Currently maintained by:
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#ifndef S2E_CUSTOM_INSTRUCTIONS

#define S2E_CUSTOM_INSTRUCTIONS


#define S2E_INSTRUCTION_COMPLEX(val1, val2)             \
	".byte 0x0F, 0x3F\n"                                \
	".byte 0x00, 0x" #val1 ", 0x" #val2 ", 0x00\n"      \
	".byte 0x00, 0x00, 0x00, 0x00\n"

#define S2E_INSTRUCTION_SIMPLE(val)                     \
	S2E_INSTRUCTION_COMPLEX(val, 00)

#ifdef __x86_64__
#define S2E_INSTRUCTION_REGISTERS_COMPLEX(val1, val2)   \
	"push %%rbx\n"                                  \
	"mov %%rdx, %%rbx\n"                            \
	S2E_INSTRUCTION_COMPLEX(val1, val2)             \
	"pop %%rbx\n"
#else
#define S2E_INSTRUCTION_REGISTERS_COMPLEX(val1, val2)   \
	"pushl %%ebx\n"                                 \
	"movl %%edx, %%ebx\n"                           \
	S2E_INSTRUCTION_COMPLEX(val1, val2)             \
	"popl %%ebx\n"
#endif

#define S2E_INSTRUCTION_REGISTERS_SIMPLE(val)           \
	S2E_INSTRUCTION_REGISTERS_COMPLEX(val, 00)

/** Forces the read of every byte of the specified string.
  * This makes sure the memory pages occupied by the string are paged in
  * before passing them to S2E, which can't page in memory by itself. */
static inline void __s2e_touch_string(volatile const char *string)
{
	while (*string) {
		++string;
	}
}

static inline void __s2e_touch_buffer(volatile const void *buffer, unsigned size)
{
	unsigned i;
	volatile const char *b = (volatile const char *) buffer;
	for (i = 0; i < size; ++i) {
		*b; ++b;
	}
}

/** Fill buffer with unconstrained symbolic values. */
static inline void s2e_make_symbolic(void *buf, int size, const char *name)
{
	__asm__ __volatile__(
		S2E_INSTRUCTION_REGISTERS_SIMPLE(03)
		: : "a" (buf), "d" (size), "c" (name) : "memory"
	);
}

/** Fill buffer with unconstrained symbolic values without discarding concrete data. */
static inline void s2e_make_concolic(void *buf, int size, const char *name)
{
	__asm__ __volatile__(
		S2E_INSTRUCTION_REGISTERS_SIMPLE(11)
		: : "a" (buf), "d" (size), "c" (name) : "memory"
	);
}

/** Print message to the S2E log. */
static inline void s2e_message(const char *message)
{
	__asm__ __volatile__(
		S2E_INSTRUCTION_SIMPLE(10)
		: : "a" (message)
	);
}

static int s2e_printf(const char *format, ...)
{
	char buffer[512];
	int ret;
	va_list args;
	va_start(args, format);
	ret = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	s2e_message(buffer);
	return ret;
}

static inline int s2e_version(void)
{

	int version;
	__asm__ __volatile__(
				S2E_INSTRUCTION_SIMPLE(00)
				: "=a" (version) : "a" (0)
				);
	return version;
}

/**
 *  Transmits a buffer of dataSize length to the plugin named in pluginName.
 *  eax contains the failure code upon return, 0 for success.
 */
static inline int s2e_invoke_plugin(const char *pluginName, void *data, uint32_t dataSize)
{
	int result;
	__s2e_touch_string(pluginName);
	__s2e_touch_buffer(data, dataSize);
	__asm__ __volatile__(
		S2E_INSTRUCTION_SIMPLE(0B)
		: "=a" (result) : "a" (pluginName), "c" (data), "d" (dataSize) : "memory"
	);

	return result;
}

/** Prevent the searcher from switching states, unless the current state dies */
static inline void s2e_begin_atomic(void)
{
	__asm__ __volatile__(
		S2E_INSTRUCTION_SIMPLE(12)
	);
}

static inline void s2e_end_atomic(void)
{
	__asm__ __volatile__(
		S2E_INSTRUCTION_SIMPLE(13)
	);
}

/** Disable all APIC interrupts in the guest. */
static inline void s2e_disable_all_apic_interrupts(void)
{
	__asm__ __volatile__(
		S2E_INSTRUCTION_COMPLEX(51, 01)
	);
}

/** Enable all APIC interrupts in the guest. */
static inline void s2e_enable_all_apic_interrupts(void)
{
	__asm__ __volatile__(
		S2E_INSTRUCTION_SIMPLE(51)
	);
}

/** Terminate current state. */
static inline void s2e_kill_state(int status, const char *message)
{
	__s2e_touch_string(message);
	__asm__ __volatile__(
		S2E_INSTRUCTION_REGISTERS_SIMPLE(06)
		: : "a" (status), "d" (message)
	);
}

#endif
