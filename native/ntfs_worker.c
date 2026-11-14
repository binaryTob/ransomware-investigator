/* Typed, read-only libtsk worker. Never accepts a source pathname or a command. */
#define _GNU_SOURCE
#include <tsk/libtsk.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    TSK_IMG_INFO image;
    int fd, failed;
    uint64_t base, length, budget, used, calls, call_limit, deadline;
} Source;
typedef struct { unsigned long count, limit, depth; int partial, deleted; } Walk;

static uint64_t millis(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
/* Installed after dynamic loading, before any filesystem parsing. There is no
 * open/exec/network/mount syscall in this allowlist. Only pipes 1 and 2 may be
 * written. A parser exploit still is not a formal proof of isolation. */
#define ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_##n, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
static int sandbox(void) {
#if defined(__x86_64__)
    const uint32_t arch=AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    const uint32_t arch=AUDIT_ARCH_AARCH64;
#else
    return -1;
#endif
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,arch,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        ALLOW(read), ALLOW(pread64), ALLOW(close), ALLOW(fstat), ALLOW(newfstatat),
        ALLOW(lseek), ALLOW(fcntl), ALLOW(brk), ALLOW(mmap), ALLOW(mprotect),
        ALLOW(munmap), ALLOW(mremap), ALLOW(madvise), ALLOW(futex),
        ALLOW(clock_gettime), ALLOW(getpid), ALLOW(gettid), ALLOW(getuid), ALLOW(geteuid),
        ALLOW(getgid), ALLOW(getegid), ALLOW(getrandom), ALLOW(rt_sigaction),
        ALLOW(rt_sigprocmask), ALLOW(rt_sigreturn), ALLOW(sigaltstack), ALLOW(sched_yield),
        ALLOW(exit), ALLOW(exit_group),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_write,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,1,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,2,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    };
    struct sock_fprog program={(unsigned short)(sizeof(filter)/sizeof(filter[0])),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
static uint64_t number(const char *s, uint64_t max) {
    if (!s || !*s || strspn(s, "0123456789") != strlen(s)) exit(2);
    errno = 0; char *end; unsigned long long value = strtoull(s, &end, 10);
    if (errno || *end || value > max) exit(2);
    return value;
}
static uint64_t source_call_limit(const char *op, uint64_t budget) {
    return !strcmp(op,"directory") && budget>256*1024*1024 ? 8192 : 4096;
}
static ssize_t source_read(TSK_IMG_INFO *image, TSK_OFF_T off, char *buf, size_t len) {
    Source *s = (Source *) image;
    if (s->failed || off < 0 || (uint64_t)off > s->length || len > s->length - (uint64_t)off ||
        len > s->budget - s->used || s->calls >= s->call_limit || millis() >= s->deadline) {
        s->failed = 1; fprintf(stderr, "RI_DENIED read_budget_extent_or_deadline\n"); return -1;
    }
    s->calls++; s->used += len;
    /* Every actual read is scope/deadline/budget checked and has a receipt. */
    fprintf(stderr,"RI_READ_INTENT %" PRIu64 " %zu\n",s->base+(uint64_t)off,len);
    ssize_t got = pread(s->fd, buf, len, (off_t)(s->base + (uint64_t)off));
    fprintf(stderr, "RI_READ %" PRIu64 " %zu %zd\n", s->base + (uint64_t)off, len, got);
    if (got < 0 || (size_t)got != len) s->failed = 1;
    return got;
}
static void source_close(TSK_IMG_INFO *img) { (void) img; }
static void source_stat(TSK_IMG_INFO *img, FILE *out) { (void)img; (void)out; }
#include "ntfs_diagnostic.h"
static void hex(const char *s) {
    if (s && strnlen(s,4097)>4096) { fprintf(stderr,"RI_DENIED oversized_name\n"); exit(3); }
    putchar('"');
    if (s) for (size_t i = 0; s[i] && i < 4096; i++) printf("%02x", (unsigned char)s[i]);
    putchar('"');
}
static TSK_WALK_RET_ENUM entry(TSK_FS_FILE *file, const char *path, void *ctx) {
    Walk *w = ctx;
    if (!file->name || !file->name->name || !strcmp(file->name->name, ".") || !strcmp(file->name->name, "..")) return TSK_WALK_CONT;
    unsigned depth = 0;
    if (path) for (const char *p = path; *p; p++) if (*p == '/') depth++;
    if (w->count >= w->limit || depth > w->depth) { w->partial = 1; return TSK_WALK_STOP; }
    w->count++;
    int name_deleted = !!(file->name->flags & TSK_FS_NAME_FLAG_UNALLOC);
    TSK_FS_FILE *loaded = NULL;
    TSK_FS_META *m = file->meta;
    if (!m && file->name->meta_addr <= file->fs_info->last_inum) {
        loaded=tsk_fs_file_open_meta(file->fs_info,NULL,file->name->meta_addr);
        if (loaded) m=loaded->meta;
        else tsk_error_reset();
    }
    int meta_deleted = m && !!(m->flags & TSK_FS_META_FLAG_UNALLOC);
    if (w->deleted && !name_deleted && !meta_deleted) { if (loaded) tsk_fs_file_close(loaded); return TSK_WALK_CONT; }
    printf("{\"kind\":\"entry\",\"inode\":%" PRIuINUM ",\"name_hex\":", file->name->meta_addr);
    hex(file->name->name); printf(",\"path_hex\":"); hex(path);
    printf(",\"name_unallocated\":%s,\"metadata_available\":%s,\"metadata_unallocated\":%s,\"name_sequence\":%u",
           name_deleted ? "true":"false", m ? "true":"false", meta_deleted ? "true":"false", file->name->meta_seq);
    if (m) printf(",\"sequence\":%u,\"size_bytes\":%" PRIdOFF ",\"directory\":%s",
                  m->seq, m->size, TSK_FS_IS_DIR_META(m->type) ? "true":"false");
    printf("}\n");
    if (loaded) tsk_fs_file_close(loaded);
    return TSK_WALK_CONT;
}
static void metadata(TSK_FS_FILE *file) {
    TSK_FS_META *m = file->meta;
    printf("{\"kind\":\"mft\",\"inode\":%" PRIuINUM ",\"sequence\":%u,\"allocated\":%s,\"directory\":%s,\"size_bytes\":%" PRIdOFF,
           m->addr, m->seq, (m->flags & TSK_FS_META_FLAG_ALLOC) ? "true":"false", TSK_FS_IS_DIR_META(m->type) ? "true":"false", m->size);
    printf(",\"times_unix\":{\"modified\":%lld,\"accessed\":%lld,\"changed\":%lld,\"created\":%lld}",
           (long long)m->mtime, (long long)m->atime, (long long)m->ctime, (long long)m->crtime);
    printf(",\"times_nanoseconds\":{\"modified\":%u,\"accessed\":%u,\"changed\":%u,\"created\":%u}",
           m->mtime_nano,m->atime_nano,m->ctime_nano,m->crtime_nano);
    printf(",\"file_name_times_unix\":{\"modified\":%lld,\"accessed\":%lld,\"changed\":%lld,\"created\":%lld},\"file_name_attribute_id\":%u,\"streams\":[",
           (long long)m->time2.ntfs.fn_mtime,(long long)m->time2.ntfs.fn_atime,(long long)m->time2.ntfs.fn_ctime,
           (long long)m->time2.ntfs.fn_crtime,m->time2.ntfs.fn_id);
    int count = tsk_fs_file_attr_getsize(file), first = 1;
    if (count < 0 || count > 1024) { fprintf(stderr, "RI_DENIED attribute_count\n"); exit(3); }
    for (int i=0; i<count; i++) {
        const TSK_FS_ATTR *a = tsk_fs_file_attr_get_idx(file, i);
        if (!a || a->type != TSK_FS_ATTR_TYPE_NTFS_DATA) continue;
        if (!first) putchar(',');
        first = 0;
        printf("{\"type\":128,\"id\":%u,\"size_bytes\":%" PRIdOFF ",\"flags\":%d,\"name_hex\":", a->id, a->size, a->flags);
        hex(a->name); putchar('}');
    }
    printf("]}\n");
}
static TSK_WALK_RET_ENUM deleted_record(TSK_FS_FILE *file, void *ctx) {
    Walk *w=ctx;
    if (!file->meta || !(file->meta->flags & TSK_FS_META_FLAG_UNALLOC)) return TSK_WALK_CONT;
    if (w->count >= w->limit) { w->partial=1; return TSK_WALK_STOP; }
    w->count++;
    TSK_FS_META *m=file->meta;
    printf("{\"kind\":\"entry\",\"inode\":%" PRIuINUM ",\"sequence\":%u,\"name_hex\":",m->addr,m->seq);
    hex(m->name2 ? m->name2->name : "");
    printf(",\"path_hex\":\"\",\"name_sequence\":null,\"name_unallocated\":false,\"metadata_available\":true,\"metadata_unallocated\":true,\"size_bytes\":%" PRIdOFF ",\"directory\":%s,\"path_reconstructed\":false",
           m->size,TSK_FS_IS_DIR_META(m->type)?"true":"false");
    if (m->name2) printf(",\"parent_inode\":%" PRIuINUM ",\"parent_sequence\":%u",m->name2->par_inode,m->name2->par_seq);
    printf("}\n");
    return TSK_WALK_CONT;
}
static void volume_identity(TSK_FS_INFO *fs) {
    printf("{\"filesystem\":\"NTFS\",\"first_inode\":%" PRIuINUM ",\"last_inode\":%" PRIuINUM ",\"root_inode\":%" PRIuINUM ",\"block_size\":%u,\"block_count\":%" PRIuDADDR ",\"fs_id_hex\":\"",
           fs->first_inum,fs->last_inum,fs->root_inum,fs->block_size,fs->block_count);
    if (fs->fs_id_used > sizeof(fs->fs_id)) exit(3);
    for (size_t i=0;i<fs->fs_id_used;i++) printf("%02x",fs->fs_id[i]);
    printf("\"}");
}
static int scan_record(TSK_FS_FILE *file) {
    TSK_FS_META *m=file->meta;
    if (!m) return 3;
    int count=tsk_fs_file_attr_getsize(file);
    if (count<0 || count>1024) return 3;
    printf("{\"kind\":\"record\",\"inode\":%" PRIuINUM ",\"sequence\":%u,\"allocated\":%s,\"unallocated\":%s,\"used\":%s,\"directory\":%s,\"meta_type\":%d,\"size_bytes\":%" PRIdOFF,
           m->addr,m->seq,(m->flags&TSK_FS_META_FLAG_ALLOC)?"true":"false",(m->flags&TSK_FS_META_FLAG_UNALLOC)?"true":"false",
           (m->flags&TSK_FS_META_FLAG_USED)?"true":"false",TSK_FS_IS_DIR_META(m->type)?"true":"false",m->type,m->size);
    printf(",\"times_unix\":{\"modified\":%lld,\"accessed\":%lld,\"changed\":%lld,\"created\":%lld},\"times_nanoseconds\":{\"modified\":%u,\"accessed\":%u,\"changed\":%u,\"created\":%u}",
           (long long)m->mtime,(long long)m->atime,(long long)m->ctime,(long long)m->crtime,m->mtime_nano,m->atime_nano,m->ctime_nano,m->crtime_nano);
    printf(",\"file_name_times_unix\":{\"modified\":%lld,\"accessed\":%lld,\"changed\":%lld,\"created\":%lld},\"names\":[",
           (long long)m->time2.ntfs.fn_mtime,(long long)m->time2.ntfs.fn_atime,(long long)m->time2.ntfs.fn_ctime,(long long)m->time2.ntfs.fn_crtime);
    unsigned names=0;
    for (TSK_FS_META_NAME_LIST *n=m->name2;n;n=n->next) {
        if (++names>1024) return 3;
        if (names>1) putchar(',');
        printf("{\"name_hex\":"); hex(n->name);
        printf(",\"parent_inode\":%" PRIuINUM ",\"parent_sequence\":%u}",n->par_inode,n->par_seq);
    }
    printf("],\"attributes\":[");
    for (int i=0;i<count;i++) {
        const TSK_FS_ATTR *a=tsk_fs_file_attr_get_idx(file,i);
        if (!a) return 3;
        if (i) putchar(',');
        printf("{\"type\":%d,\"id\":%u,\"size_bytes\":%" PRIdOFF ",\"flags\":%d,\"name_hex\":",a->type,a->id,a->size,a->flags); hex(a->name);
        printf(",\"runs\":[");
        const TSK_FS_ATTR_RUN *run=(a->flags&TSK_FS_ATTR_NONRES)?a->nrd.run:NULL;
        unsigned runs=0;
        for (;run && runs<64;run=run->next,runs++) {
            if (runs) putchar(',');
            printf("{\"offset_blocks\":%" PRIuDADDR ",\"address_blocks\":%" PRIuDADDR ",\"length_blocks\":%" PRIuDADDR ",\"flags\":%d}",run->offset,run->addr,run->len,run->flags);
        }
        printf("],\"runs_truncated\":%s}",run?"true":"false");
    }
    printf("]}\n");
    return 0;
}
static int scan_page(TSK_FS_INFO *fs,const char *op,TSK_INUM_T inode,uint64_t limit,uint64_t cursor) {
    uint64_t visited=0,next=cursor,total=0;
    uint32_t directory_sequence=0;
    int status=0,eof=1;
    if (!strcmp(op,"records")) {
        if (inode<fs->first_inum || inode>fs->last_inum) return 3;
        TSK_INUM_T end=inode+limit-1;
        if (end<inode || end>fs->last_inum) end=fs->last_inum;
        for (TSK_INUM_T i=inode;i<=end;i++) {
            TSK_FS_FILE *file=tsk_fs_file_open_meta(fs,NULL,i);
            if (!file || scan_record(file)) { if (file) tsk_fs_file_close(file); status=3; break; }
            tsk_fs_file_close(file); visited++;
        }
        next=inode+visited; total=fs->last_inum-fs->first_inum+1;
        eof=next>fs->last_inum;
    } else if (!strcmp(op,"directory")) {
        TSK_FS_DIR *dir=tsk_fs_dir_open_meta(fs,inode);
        if (!dir) return 3;
        if (!dir->fs_file || !dir->fs_file->meta || !(dir->fs_file->meta->flags&TSK_FS_META_FLAG_ALLOC)) { tsk_fs_dir_close(dir); return 3; }
        directory_sequence=dir->fs_file->meta->seq;
        total=tsk_fs_dir_getsize(dir);
        if (cursor>total) { tsk_fs_dir_close(dir); return 3; }
        uint64_t end=total-cursor<limit?total:cursor+limit;
        for (uint64_t i=cursor;i<end;i++) {
            const TSK_FS_NAME *name=tsk_fs_dir_get_name(dir,(size_t)i);
            if (!name || !name->name) { status=3; break; }
            printf("{\"kind\":\"directory_entry\",\"index\":%" PRIu64 ",\"parent_inode\":%" PRIuINUM ",\"inode\":%" PRIuINUM ",\"name_sequence\":%u,\"name_unallocated\":%s,\"name_type\":%d,\"name_hex\":",
                   i,inode,name->meta_addr,name->meta_seq,(name->flags&TSK_FS_NAME_FLAG_UNALLOC)?"true":"false",name->type);
            hex(name->name); printf("}\n"); visited++;
        }
        next=cursor+visited; eof=next==total;
        tsk_fs_dir_close(dir);
    }
    printf("{\"kind\":\"summary\",\"visited\":%" PRIu64 ",\"next_cursor\":%" PRIu64 ",\"reported_total\":%" PRIu64 ",\"eof\":%s,\"partial\":%s,\"volume_identity\":",visited,next,total,eof?"true":"false",status?"true":"false");
    volume_identity(fs); printf(",\"directory_sequence\":%u,\"tsk_version\":\"%s\"}\n",directory_sequence,tsk_version_get_str());
    return status;
}
int main(int argc, char **argv) {
    if (getuid() == 0 || geteuid() == 0 || (argc != 15 && argc != 16)) return 2;
    int fd = (int)number(argv[1], 65535);
    const char *op = argv[2];
    if (strcmp(op,"list") && strcmp(op,"search") && strcmp(op,"deleted") && strcmp(op,"mft") && strcmp(op,"extract") && strcmp(op,"volume") && strcmp(op,"records") && strcmp(op,"directory") && strcmp(op,"prefix") && strcmp(op,"diagnose")) return 2;
    if ((argc==16)!=(!strcmp(op,"directory"))) return 2;
    uint64_t cursor=argc==16?number(argv[15],INT64_MAX):0;
    uint64_t base = number(argv[3], INT64_MAX), length = number(argv[4], INT64_MAX);
    TSK_INUM_T inode = number(argv[5], INT64_MAX);
    uint16_t attr_id = (uint16_t)number(argv[6], UINT16_MAX);
    uint64_t limit = number(argv[7], 10000), depth = number(argv[8], 8), max_bytes = number(argv[9], 16*1024*1024);
    uint64_t sequence = number(argv[10], UINT32_MAX), expected_size = number(argv[11], !strcmp(op,"prefix")?INT64_MAX:16*1024*1024);
    if (!strcmp(op,"prefix") && (!expected_size || max_bytes>65536)) return 2;
    int allow_deleted = (int)number(argv[12],1);
    uint64_t budget = number(argv[13], !strcmp(op,"directory")?512*1024*1024:256*1024*1024), duration = number(argv[14],15000);
    if (!length || base > INT64_MAX-length || !limit || !max_bytes || !budget || !duration) return 2;
    if (!strcmp(op,"diagnose") && (inode<16 || limit!=1 || depth || max_bytes!=65536 ||
        attr_id || sequence || expected_size || allow_deleted || budget>64*1024*1024 || duration>10000)) return 2;
    struct stat st;
    if (fstat(fd,&st) || (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode)) || (fcntl(fd,F_GETFL) & O_ACCMODE) != O_RDONLY) return 2;
    struct rlimit memory = {512*1024*1024,512*1024*1024}, cpu = {20,20}, core = {0,0};
    if (setrlimit(RLIMIT_AS,&memory) || setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_CORE,&core) ||
        prctl(PR_SET_DUMPABLE,0,0,0,0) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) return 2;
    if (sandbox()) return 2;
    fprintf(stderr,"RI_ID %u %u %u\n",(unsigned)getuid(),(unsigned)geteuid(),(unsigned)getgid());
    fprintf(stderr,"RI_SANDBOX seccomp_no_open_exec_network_writefiles\n");
    Source *source = calloc(1,sizeof(Source)); if (!source) return 3;
    source->fd=fd; source->base=base; source->length=length; source->budget=budget; source->deadline=millis()+duration;
    source->call_limit=source_call_limit(op,budget);
    if (!strcmp(op,"diagnose") && !diag_boot(source)) {
        fprintf(stderr,"RI_DENIED diagnostic_boot_geometry\n");
        fprintf(stderr,"RI_SUMMARY %" PRIu64 " %" PRIu64 " %s\n",source->calls,source->used,tsk_version_get_str());
        free(source); return 3;
    }
    TSK_IMG_INFO *img = tsk_img_open_external(source, (TSK_OFF_T)length, 512, source_read, source_close, source_stat);
    if (!img) { free(source); return 3; }
    TSK_FS_INFO *fs = tsk_fs_open_img(img,0,TSK_FS_TYPE_NTFS);
    if (!fs) {
        if (!strcmp(op,"diagnose")) {
            fprintf(stderr,"RI_DENIED diagnostic_locator_failed\n");
            fprintf(stderr,"RI_SUMMARY %" PRIu64 " %" PRIu64 " %s\n",source->calls,source->used,tsk_version_get_str());
        } else tsk_error_print(stderr);
        tsk_img_close(img); free(source); return 3;
    }
    int status = 0;
    if (!strcmp(op,"diagnose")) {
        status=diagnose_record(source,fs,inode);
    } else if (!strcmp(op,"volume")) {
        printf("{\"kind\":\"volume\",\"volume_identity\":"); volume_identity(fs);
        printf(",\"tsk_version\":\"%s\"}\n",tsk_version_get_str());
    } else if (!strcmp(op,"records") || !strcmp(op,"directory")) {
        status=scan_page(fs,op,inode,limit,cursor);
    } else if (!strcmp(op,"deleted")) {
        Walk walk={0,(unsigned long)limit,0,0,1};
        TSK_INUM_T end=inode+limit-1;
        if (end>fs->last_inum) end=fs->last_inum;
        if (inode<fs->first_inum || inode>end) status=3;
        else if (tsk_fs_meta_walk(fs,inode,end,TSK_FS_META_FLAG_UNALLOC|TSK_FS_META_FLAG_USED,deleted_record,&walk)) status=3;
        if (end<fs->last_inum) walk.partial=1;
        printf("{\"kind\":\"summary\",\"visited\":%lu,\"partial\":%s,\"scanned_start_inode\":%" PRIuINUM ",\"scanned_end_inode\":%" PRIuINUM ",\"tsk_version\":\"%s\"}\n",
               walk.count,walk.partial?"true":"false",inode,end,tsk_version_get_str());
    } else if (!strcmp(op,"list") || !strcmp(op,"search")) {
        TSK_FS_FILE *dir = tsk_fs_file_open_meta(fs,NULL,inode);
        if (!dir || !dir->meta || !TSK_FS_IS_DIR_META(dir->meta->type)) status=3;
        if (dir) tsk_fs_file_close(dir);
        Walk walk = {0,(unsigned long)limit,(unsigned long)depth,0,!strcmp(op,"deleted")};
        TSK_FS_DIR_WALK_FLAG_ENUM flags = TSK_FS_DIR_WALK_FLAG_ALLOC|TSK_FS_DIR_WALK_FLAG_UNALLOC|TSK_FS_DIR_WALK_FLAG_NOORPHAN;
        if (depth) flags |= TSK_FS_DIR_WALK_FLAG_RECURSE;
        if (!status && tsk_fs_dir_walk(fs,inode,flags,entry,&walk)) status=3;
        printf("{\"kind\":\"summary\",\"visited\":%lu,\"partial\":%s,\"tsk_version\":\"%s\"}\n",walk.count,walk.partial?"true":"false",tsk_version_get_str());
    } else {
        TSK_FS_FILE *file = tsk_fs_file_open_meta(fs,NULL,inode);
        if (!file || !file->meta) status=3;
        else if (!strcmp(op,"mft")) metadata(file);
        else {
            const TSK_FS_ATTR *a = tsk_fs_file_attr_get_type(file,TSK_FS_ATTR_TYPE_NTFS_DATA,attr_id,1);
            if (inode < 16 || file->meta->type != TSK_FS_META_TYPE_REG || !a || file->meta->seq != sequence ||
                a->id != attr_id || a->type != TSK_FS_ATTR_TYPE_NTFS_DATA || a->size < 0 || (uint64_t)a->size != expected_size || (strcmp(op,"prefix") && expected_size > max_bytes) ||
                (!(file->meta->flags & TSK_FS_META_FLAG_ALLOC) && !allow_deleted) ||
                (a->flags & (TSK_FS_ATTR_ENC|TSK_FS_ATTR_COMP|TSK_FS_ATTR_SPARSE))) {
                fprintf(stderr,"RI_DENIED extraction_preconditions\n"); status=3;
            } else {
                char buffer[65536]; uint64_t pos=0,target=(!strcmp(op,"prefix") && expected_size>max_bytes)?max_bytes:expected_size;
                while (pos < target) {
                    size_t want = target-pos < sizeof(buffer) ? (size_t)(target-pos) : sizeof(buffer);
                    ssize_t got = tsk_fs_attr_read(a,(TSK_OFF_T)pos,buffer,want,TSK_FS_FILE_READ_FLAG_NONE);
                    if (got <= 0 || (size_t)got > want || fwrite(buffer,1,(size_t)got,stdout) != (size_t)got) { status=3; break; }
                    pos += (size_t)got;
                }
            }
        }
        if (file) tsk_fs_file_close(file);
    }
    if (source->failed) status=3;
    fprintf(stderr,"RI_SUMMARY %" PRIu64 " %" PRIu64 " %s\n",source->calls,source->used,tsk_version_get_str());
    if (status && strcmp(op,"diagnose")) tsk_error_print(stderr);
    tsk_fs_close(fs); tsk_img_close(img); free(source);
    return status;
}
