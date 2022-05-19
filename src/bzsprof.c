#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <strings.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <sched.h>

#include <signal.h>
#include <poll.h>
#include <asm/perf_regs.h>

#include "blazesym.h"


#define mb()    asm volatile("mfence":::"memory")
#define rmb()   asm volatile("lfence":::"memory")
#define wmb()   asm volatile("sfence" ::: "memory")

typedef uint64_t u64;

struct read_format {
	u64 value;         /* The value of the event */
	u64 id;            /* if PERF_FORMAT_ID */
};

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		      group_fd, flags);
	return ret;
}

static struct blazesym *symbolizer;

static void
init_symbolizer()
{
	symbolizer = blazesym_new();
}

static char
ringbuf_read_byte(const char **ptr, const char *start, uint64_t size)
{
	const char *stop = start + size;
	char r = **ptr;

	(*ptr)++;

	return r;
}

static void
ringbuf_read(void *output, uint64_t nbytes, const char **ptr,
	     const char *start, uint64_t size)
{
	const char *stop = start + size;
	const char *_ptr = *ptr;
	char *_output = output;
	int i;

	for (i = 0; i < nbytes; i++) {
		_output[i] = *_ptr++;
		if (_ptr == stop)
			_ptr = start;
	}

	*ptr = _ptr;
}

static uint32_t
ringbuf_read_uint32(const char **ptr, const char *start, uint64_t size)
{
	char *tmp[sizeof(uint32_t)];

	ringbuf_read(tmp, sizeof(uint32_t), ptr, start, size);

	return *(uint32_t *)tmp;
}

static uint64_t
ringbuf_read_uint64(const char **ptr, const char *start, uint64_t size)
{
	char *tmp[sizeof(uint64_t)];

	ringbuf_read(tmp, sizeof(uint64_t), ptr, start, size);

	return *(uint64_t *)tmp;
}

static void
show_samples(struct perf_event_mmap_page *meta)
{
	uint64_t head = meta->data_head;
	uint64_t tail = meta->data_tail;
	uint64_t offset = meta->data_offset;
	uint64_t size = meta->data_size;
	char *buf = (char *)meta;
	char *data_start = buf + offset;
	const char *ptr, *next_ptr;
	struct perf_event_header peheader;
	struct sym_file_cfg cfgs[2] = {
		{
			.cfg_type = CFG_T_KERNEL,
			.params = {
				.kernel = { NULL, NULL },
			},
		},
		{
			.cfg_type = CFG_T_PROCESS,
			.params = {
				.process = {
					.pid = 0
				}
			}
		},
	};
	uint64_t addrs[32];
	const struct blazesym_result *bzresult;
	int i;

	rmb();
	while (tail < head) {
		ptr = data_start + (tail % size);
		ringbuf_read(&peheader, sizeof(peheader), &ptr, data_start, size);
		next_ptr = data_start + ((tail + peheader.size) % size);

		printf("\n");

		if (peheader.type == PERF_RECORD_SAMPLE) {
			printf("sample size = %d\n", peheader.size);
		} else {
			printf("unknown\n");
		}

		tail += peheader.size;

		uint32_t pid = ringbuf_read_uint32(&ptr, data_start, size);
		uint32_t tid = ringbuf_read_uint32(&ptr, data_start, size);
		printf("PID %d, TID %d\n", pid, tid);

		uint64_t nr = ringbuf_read_uint64(&ptr, data_start, size);
		for (i = 0; i < nr; i++) {
			addrs[i] = ringbuf_read_uint64(&ptr, data_start, size);
		}
		printf("Kernel (%d):\n", nr);
		if (pid == 0) {
			bzresult = blazesym_symbolize(symbolizer, cfgs, 1, addrs, nr);
		} else {
			cfgs[1].params.process.pid = pid;
			bzresult = blazesym_symbolize(symbolizer, cfgs, 2, addrs, nr);
		}
		if (bzresult == NULL)
			printf("Fail to symbolize addresses\n");

		for (i = 0; i < nr; i++) {
			if (bzresult && bzresult[i].valid)
				printf("  %d [<%016llx>] %s+0x%x %s:%d\n", i, addrs[i], bzresult[i].symbol, addrs[i] - bzresult[i].start_address, bzresult[i].path, bzresult[i].line_no);
			else
				printf("  %d [<%016llx>] UNKNOWN\n", i, addrs[i]);
		}
		if (bzresult)
			blazesym_result_free(bzresult);

		if (ptr == next_ptr) {
			printf("\n");
			continue;
		}

		uint64_t abi = *(uint64_t *)ptr;
		if (abi != 0) {
			printf("ABI: %llx\n", abi);
			ptr += sizeof(uint64_t);
			if (ptr == next_ptr) {
				printf("\n");
				continue;
			}
			printf("User BP: %p\n", (void *)*(uint64_t *)ptr);
			ptr += sizeof(uint64_t);
			if (ptr == next_ptr) {
				printf("\n");
				continue;
			}
			printf("User SP: %p\n", (void *)*(uint64_t *)ptr);
			ptr += sizeof(uint64_t);
			if (ptr == next_ptr) {
				printf("\n");
				continue;
			}
			printf("User IP: %p\n", (void *)*(uint64_t *)ptr);
			ptr += sizeof(uint64_t);
		} else {
			printf("No user regs\n");
		}

		if (ptr == next_ptr) {
			printf("\n");
			continue;
		}

		uint64_t us_size = *(uint64_t *)ptr;
		ptr += sizeof(uint64_t);
		printf("Userspace (%lld):\n", us_size);
		for (i = 0; i < us_size; i++) {
			if (i % 16 == 0)
				printf("  %03x -", i);
			printf(" %02x", *ptr++ & 0xff);
			if (i % 16 == 15)
				printf("\n");
		}
		printf("\n");
	}
	wmb();
	meta->data_tail = tail;
}


int
main(int argc, const char *argv[])
{
	struct perf_event_attr attr;
	const int pid = -1, cpu = 0;
	long pagesize;
	char *mapped;
	struct read_format pedata;
	struct perf_event_mmap_page *meta;
	struct pollfd fds;
	int pages, exit_code = 0, pefd = -1, cp;

	init_symbolizer();

	bzero(&attr, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_freq = 1;
	attr.sample_type = PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_STACK_USER | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_TID;
	attr.freq = 1;
	attr.read_format = PERF_FORMAT_ID;
	attr.wakeup_events = 1;
	attr.sample_stack_user = 512;
	attr.sample_max_stack = 30;
	attr.sample_regs_user = (1 << PERF_REG_X86_SP) | (1 << PERF_REG_X86_IP) | (1 << PERF_REG_X86_BP);

	pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
	if (pefd < 0) {
		perror("perf_event_open");
		return 1;
	}

	pagesize = sysconf(_SC_PAGESIZE);
	printf("pagesize %d\n", pagesize);
	pages = 1 + 8;

	mapped = mmap(NULL, pagesize * pages, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_FILE, pefd, 0);
	if (mapped == MAP_FAILED) {
		perror("mmap");
		exit_code = 1;
		goto _exit;
	}

	meta = (struct perf_event_mmap_page *)mapped;
	fds.fd = pefd;
	fds.events = POLLIN;
	while (poll(&fds, 1, -1) >= 0) {
		cp = read(pefd, &pedata, sizeof(pedata));
		if (cp != sizeof(pedata)) {
			printf("invalid size %d\n", cp);
			continue;
		}
		printf("value %lld, id %lld\n", pedata.value, pedata.id);
		while (meta->data_head != meta->data_tail)
			show_samples(meta);
		fds.revents = 0;
	}

_exit:
	if (pefd >= 0) {
		close(pefd);
	}

	return exit_code;
}
