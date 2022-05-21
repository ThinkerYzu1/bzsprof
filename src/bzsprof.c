#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#include <sched.h>

#include <signal.h>
#include <poll.h>
#include <asm/perf_regs.h>

#include "blazesym.h"


#define CALLCHAIN_DEPTH_MAX 512

#define mb()    asm volatile("mfence":::"memory")
#define rmb()   asm volatile("lfence":::"memory")
#define wmb()   asm volatile("sfence" ::: "memory")

typedef uint64_t u64;

/* The fields of this type depends on the configuration of
 * perf_event_attr.
 */
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
process_perf_events(struct perf_event_mmap_page *meta_data, struct blazesym *symbolizer)
{
	uint64_t head = meta_data->data_head;
	uint64_t tail = meta_data->data_tail;
	uint64_t size = meta_data->data_size;
	char *ring_buf = (char *)meta_data + meta_data->data_offset;
	const char *ptr, *next_event;
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
	uint64_t *addrs, nr, abi, ustack_sz;
	uint64_t _addrs[32];
	int addrs_capa = 32;
	const struct blazesym_result *bzresult;
	uint32_t pid, tid;
	int i;

	addrs = _addrs;

	/* Process perf events in the ring buffer */
	rmb();
	while (tail < head) {
		ptr = ring_buf + (tail % size);
		/* perf_event_header */
		ringbuf_read(&peheader, sizeof(peheader), &ptr, ring_buf, size);
		next_event = ring_buf + ((tail + peheader.size) % size);
		tail += peheader.size;

		printf("\n");

		if (peheader.type == PERF_RECORD_SAMPLE) {
			printf("sample size = %d\n", peheader.size);
		} else {
			printf("unknown\n");
		}

		/* PERF_SAMPLE_ID */
		pid = ringbuf_read_uint32(&ptr, ring_buf, size);
		tid = ringbuf_read_uint32(&ptr, ring_buf, size);
		printf("PID %d, TID %d\n", pid, tid);

		/* PERF_SAMPLE_CALLCHAIN - get backtrace */
		nr = ringbuf_read_uint64(&ptr, ring_buf, size);
		if (nr > CALLCHAIN_DEPTH_MAX) {
			printf("\nBacktrace is too long (>%d).  Skip the event!\n", CALLCHAIN_DEPTH_MAX);
			continue;
		}
		if (nr > addrs_capa) {
			while (nr > addrs_capa)
				addrs_capa *= 2;
			if (addrs == _addrs) {
				addrs = (uint64_t *)malloc(sizeof(uint64_t) * addrs_capa);
			} else {
				addrs = (uint64_t *)realloc(addrs, sizeof(uint64_t) * addrs_capa);
			}
		}
		for (i = 0; i < nr; i++) {
			addrs[i] = ringbuf_read_uint64(&ptr, ring_buf, size);
		}
		printf("Stack (%d):\n", nr);
		/* Symbolize */
		if (pid == 0) {
			bzresult = blazesym_symbolize(symbolizer, cfgs, 1, addrs, nr);
		} else {
			cfgs[1].params.process.pid = pid;
			bzresult = blazesym_symbolize(symbolizer, cfgs, 2, addrs, nr);
		}
		if (bzresult == NULL)
			printf("Fail to symbolize addresses\n");

		/* Show backtrace */
		for (i = 0; i < nr; i++) {
			if (bzresult && bzresult[i].valid)
				printf("  %d [<%016llx>] %s+0x%x %s:%d\n", i, addrs[i],
				       bzresult[i].symbol, addrs[i] - bzresult[i].start_address,
				       bzresult[i].path, bzresult[i].line_no);
			else
				printf("  %d [<%016llx>] UNKNOWN\n", i, addrs[i]);
		}
		if (bzresult)
			blazesym_result_free(bzresult);

		if (ptr == next_event) {
			printf("\n");
			continue;
		}

		/* PERF_SAMPLE_REGS_USER */
		abi = *(uint64_t *)ptr;
		if (abi != 0) {
			printf("ABI: %llx\n", abi);
			ptr += sizeof(uint64_t);
			if (ptr == next_event) {
				printf("\n");
				continue;
			}
			printf("User BP: %p\n", (void *)*(uint64_t *)ptr);
			ptr += sizeof(uint64_t);
			if (ptr == next_event) {
				printf("\n");
				continue;
			}
			printf("User SP: %p\n", (void *)*(uint64_t *)ptr);
			ptr += sizeof(uint64_t);
			if (ptr == next_event) {
				printf("\n");
				continue;
			}
			printf("User IP: %p\n", (void *)*(uint64_t *)ptr);
			ptr += sizeof(uint64_t);
		} else {
			printf("No user regs\n");
		}

		if (ptr == next_event) {
			printf("\n");
			continue;
		}

		/* PERF_SAMPLE_STACK_USER */
		ustack_sz = *(uint64_t *)ptr;
		ptr += sizeof(uint64_t);
		printf("Userspace (%lld):\n", ustack_sz);
		for (i = 0; i < ustack_sz; i++) {
			if (i % 16 == 0)
				printf("  %03x -", i);
			printf(" %02x", *ptr++ & 0xff);
			if (i % 16 == 15)
				printf("\n");
		}
		printf("\n");
	}
	meta_data->data_tail = tail;
	wmb();

	if (addrs != _addrs)
		free(addrs);
}

void
show_help(const char *progname)
{
	printf("Usage: %s [-f <frequency>] [-p <pid>] [-d <stack-depth> [-h]\n", progname);
}

int
main(int argc, char * const argv[])
{
	struct blazesym *symbolizer;
	struct perf_event_attr attr;
	long page_size;
	char *mapped;
	struct read_format pedata;
	struct perf_event_mmap_page **all_meta_data, *meta_data;
	struct pollfd *fds;
	int nprocs;		/* number of processors/cores */
	int *pefds;		/* perf event FDs */
	int pages, exit_code = 0, pefd, cpu, cp, opt;
	int freq = 1, pid = -1, max_stack_depth = 127;

	while ((opt = getopt(argc, argv, "hf:p:d:")) != -1) {
		switch (opt) {
		case 'f':
			freq = atoi(optarg);
			if (freq < 1) freq = 1;
			break;

		case 'p':
			pid = atoi(optarg);
			if (pid < 1) pid = -1;
			break;

		case 'd':
			max_stack_depth = atoi(optarg);
			if (max_stack_depth < 32)
				max_stack_depth = 32;
			break;

		case 'h':
		default:
			show_help(argv[0]);
			return 1;
		}
	}

	symbolizer = blazesym_new();
	if (symbolizer == NULL)
		return 1;

	page_size = sysconf(_SC_PAGESIZE);
	nprocs = get_nprocs();

	printf("%d processors\n", nprocs);
	all_meta_data = (struct perf_event_mmap_page **)malloc(sizeof(struct perf_event_mmap_page *) * nprocs);
	bzero(all_meta_data, sizeof(struct perf_event_mmap_page *) * nprocs);
	pefds = (int *)malloc(sizeof(int) * nprocs);
	memset(pefds, -1, sizeof(int) * nprocs);
	fds = (struct pollfd *)malloc(sizeof(struct pollfd) * nprocs);
	bzero(fds, sizeof(struct pollfd) * nprocs);

	// Set attributes for perf_event_open()
	bzero(&attr, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_freq = freq;
	attr.sample_type = PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_STACK_USER | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_TID;
	attr.freq = 1;
	attr.read_format = PERF_FORMAT_ID;
	attr.wakeup_events = 1;
	attr.sample_stack_user = 128;
	attr.sample_max_stack = max_stack_depth;
	attr.sample_regs_user = (1 << PERF_REG_X86_SP) | (1 << PERF_REG_X86_IP) | (1 << PERF_REG_X86_BP);

	printf("page_size %d\n", page_size);
	/* perf event fd required being mapped with a size of 1+2^n pages */
	pages = 1 + 8;

	/* Set perf events for each processor */
	for (cpu = 0; cpu < nprocs; cpu++) {
		pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			perror("perf_event_open");
			return 1;
		}

		mapped = mmap(NULL, page_size * pages, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_FILE, pefd, 0);
		if (mapped == MAP_FAILED) {
			perror("mmap");
			exit_code = 1;
			goto _exit;
		}

		meta_data = (struct perf_event_mmap_page *)mapped;
		pefds[cpu] = pefd;
		all_meta_data[cpu] = meta_data;
		fds[cpu].fd = pefd;
		fds[cpu].events = POLLIN;
	}

	printf("\n");
	while (poll(fds, nprocs, -1) >= 0) {
		for (cpu = 0; cpu < nprocs; cpu++) {
			if (fds[cpu].revents == 0)
				continue;
			pefd = pefds[cpu];
			meta_data = all_meta_data[cpu];
			cp = read(pefd, &pedata, sizeof(pedata));
			if (cp != sizeof(pedata)) {
				printf("invalid size %d\n", cp);
				continue;
			}
			printf("CPU %d: value %lld, id %lld\n", cpu, pedata.value, pedata.id);
			while (meta_data->data_head != meta_data->data_tail)
				process_perf_events(meta_data, symbolizer);
			fds[cpu].revents = 0;
		}
	}

_exit:
	for (cpu = 0; cpu < nprocs; cpu++) {
		pefd = pefds[cpu];
		if (pefd >= 0)
			close(pefd);
		meta_data = all_meta_data[cpu];
		if (meta_data)
			munmap(meta_data, pages * page_size);
	}
	free(pefds);
	free(all_meta_data);
	free(fds);
	blazesym_free(symbolizer);

	return exit_code;
}
