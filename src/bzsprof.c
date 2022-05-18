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

static void
show_samples(struct perf_event_mmap_page *meta) {
	uint64_t head = meta->data_head;
	uint64_t tail = meta->data_tail;
	uint64_t offset = meta->data_offset;
	uint64_t size = meta->data_size;
	char *buf = (char *)meta;
	char *ptr;
	struct perf_event_header *peheader;
	int i;

	while (tail < head) {
		peheader = (struct perf_event_header *)(buf + offset + (tail % size));

		printf("\n");

		if (peheader->type == PERF_RECORD_SAMPLE) {
			printf("sample size = %d\n", peheader->size);
		} else {
			printf("unknown\n");
		}

		tail += peheader->size;

		ptr = (char *)peheader + sizeof(peheader);
		uint64_t nr = *(uint64_t *)ptr;
		ptr += sizeof(uint64_t);
		printf("Kernel (%d):\n", nr);
		for (i = 0; i < nr; i++) {
			printf("  %d %p\n", i, (void *)*(uint64_t *)ptr);
			ptr += sizeof(uint64_t);
		}

		if ((ptr - (char *)peheader) >= peheader->size) {
			printf("\n");
			continue;
		}

		uint64_t abi = *(uint64_t *)ptr;
		ptr += sizeof(uint64_t);
		printf("User SP: %p\n", (void *)*(uint64_t *)ptr);
		ptr += sizeof(uint64_t);

		if ((ptr - (char *)peheader) >= peheader->size) {
			printf("\n");
			continue;
		}

		uint64_t size = *(uint64_t *)ptr;
		ptr += sizeof(uint64_t);
		printf("Userspace (%lld):\n", size);
		for (i = 0; i < size; i++) {
			if (i % 16 == 0)
				printf("  %03x -", i);
			printf(" %02x", *ptr++ & 0xff);
			if (i % 16 == 15)
				printf("\n");
		}
		printf("\n");
	}
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

	bzero(&attr, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_freq = 1;
	attr.sample_type = PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_STACK_USER | PERF_SAMPLE_REGS_USER;
	attr.freq = 1;
	attr.read_format = PERF_FORMAT_ID;
	attr.wakeup_events = 3;
	attr.sample_stack_user = 512;
	attr.sample_max_stack = 10;
	attr.sample_regs_user = 1 << PERF_REG_X86_SP;

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
		show_samples(meta);
		fds.revents = 0;
	}

_exit:
	if (pefd >= 0) {
		close(pefd);
	}

	return exit_code;
}
