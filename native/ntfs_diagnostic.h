/* Metadata-only diagnostic. Included after Source/source_read; no new IO path.
 * libtsk locates $MFT; this checker does NOT independently validate its map.
 * Never parses names/attributes of the target, applies fixes, or exports bytes.
 */
#include <tsk/fs/tsk_ntfs.h>

static uint16_t diag_u16(const unsigned char *p) { return (uint16_t)(p[0]|p[1]<<8); }
static uint32_t diag_u32(const unsigned char *p) {
    return (uint32_t)diag_u16(p)|((uint32_t)diag_u16(p+2)<<16);
}
static uint64_t diag_u64(const unsigned char *p) { return diag_u32(p)|((uint64_t)diag_u32(p+4)<<32); }

/* Reject holes, overlapping runs, recovery maps and uninitialized bytes rather
 * than obtaining synthetic zeros from a logical attribute reader. Bound all
 * arithmetic BEFORE multiplication. Physical offsets never come from argv. */
static int diag_read(Source *s, uint32_t cluster, uint64_t blocks, const TSK_FS_ATTR *a,
                     uint64_t pos, unsigned char *out, size_t len, int resident) {
    if (!cluster || blocks>s->length/cluster || !a || a->size<0 || pos>(uint64_t)a->size || len>(uint64_t)a->size-pos ||
        (a->name && *a->name)) return 0;
    if (resident && a->flags==(TSK_FS_ATTR_INUSE|TSK_FS_ATTR_RES)) {
        if (!a->rd.buf || (uint64_t)a->size>a->rd.buf_size) return 0;
        memcpy(out,a->rd.buf+pos,len); return 1;
    }
    if (a->flags!=(TSK_FS_ATTR_INUSE|TSK_FS_ATTR_NONRES) || a->nrd.skiplen ||
        a->nrd.initsize<0 || a->nrd.initsize>a->size ||
        pos>(uint64_t)a->nrd.initsize || len>(uint64_t)a->nrd.initsize-pos ||
        a->nrd.allocsize<a->size) return 0;
    uint64_t end=0;
    unsigned count=0;
    for (const TSK_FS_ATTR_RUN *r=a->nrd.run;r;r=r->next) {
        if (++count>256 || r->flags || !r->len || !r->addr || r->offset!=end ||
            r->addr>blocks || r->len>blocks-r->addr ||
            end>blocks || r->len>blocks-end) return 0;
        for (const TSK_FS_ATTR_RUN *p=a->nrd.run;p!=r;p=p->next)
            if (r->addr<p->addr+p->len && p->addr<r->addr+r->len) return 0;
        end+=r->len;
    }
    if ((uint64_t)a->size>end*cluster || (uint64_t)a->nrd.allocsize>end*cluster) return 0;
    size_t done=0;
    for (const TSK_FS_ATTR_RUN *r=a->nrd.run;r && done<len;r=r->next) {
        uint64_t start=r->offset*cluster, bytes=r->len*cluster;
        if (pos<start || pos-start>=bytes) continue;
        size_t n=bytes-(pos-start)<len-done?(size_t)(bytes-(pos-start)):len-done;
        uint64_t offset=r->addr*cluster+(pos-start);
        if (source_read(&s->image,(TSK_OFF_T)offset,(char *)out+done,n)!=(ssize_t)n) return -1;
        pos+=n; done+=n;
    }
    return done==len;
}

static int diag_boot(Source *s) {
    unsigned char boot[512];
    if (source_read(&s->image,0,(char *)boot,sizeof(boot))!=sizeof(boot)) return 0;
    unsigned cluster=boot[13]*512U;
    int code=(int8_t)boot[64];
    uint64_t size=code>0?(uint64_t)code*cluster:code>=-16 && code<0?1ULL<<-code:0;
    return !memcmp(boot+3,"NTFS    ",8) && boot[510]==0x55 && boot[511]==0xaa &&
        diag_u16(boot+11)==512 && cluster && cluster<=65536 && !(cluster&(cluster-1)) &&
        size>=512 && size<=65536 && !(size&(size-1)) && diag_u64(boot+40)>0 &&
        diag_u64(boot+40)<=s->length/512 && diag_u64(boot+48)>0 &&
        diag_u64(boot+48)<diag_u64(boot+40)/boot[13];
}

static int diagnose_record(Source *s, TSK_FS_INFO *fs, TSK_INUM_T inode) {
    NTFS_INFO *ntfs=(NTFS_INFO *)fs;
    uint32_t size=ntfs->mft_rsize_b, cluster=ntfs->csize_b;
    const char *assessment="inconclusive", *reason="unsupported_geometry", *bitmap="unknown";
    const char *signature="unread", *structure="unread";
    unsigned char record[65536], bit=0;
    unsigned usa_offset=0,usa_count=0,attr_offset=0,flags=0,used=0,allocated=0,mismatches=0;
    int present=0, bitmap_value=-1;
    /* Fixup stride is 512 in this deliberately narrow implementation. Other
     * sector geometries need independent validation, not a guessed verdict. */
    if (ntfs->ssize_b!=512 || size<512 || size>sizeof(record) || (size&(size-1)) ||
        (ntfs->ver!=NTFS_VINFO_2K && ntfs->ver!=NTFS_VINFO_XP) ||
        !cluster || cluster>65536 || cluster%512 || (cluster&(cluster-1)) ||
        !ntfs->mft_data || !ntfs->mft_data->nrd.run ||
        ntfs->mft_data->nrd.run->addr>s->length/cluster ||
        ntfs->mft_data->nrd.run->addr*cluster!=ntfs->root_mft_addr ||
        fs->block_count>s->length/cluster || ntfs->root_mft_addr>=s->length) goto output;
    if (inode>INT64_MAX/size || inode>fs->last_inum) { reason="inode_out_of_range"; goto output; }
    int read_status=diag_read(s,cluster,fs->block_count,ntfs->mft_data,inode*size,record,size,0);
    if (read_status!=1) { reason="mft_mapping_unavailable"; goto output; }
    present=1;
    signature=!memcmp(record,"FILE",4)?"file":"other";
    int all_zero=1;
    for (uint32_t i=0;i<size;i++) if (record[i]) { all_zero=0; break; }
    if (all_zero) signature="zero";
    structure="signature_rejected";
    if (!strcmp(signature,"file")) {
        usa_offset=diag_u16(record+4); usa_count=diag_u16(record+6);
        attr_offset=diag_u16(record+20); flags=diag_u16(record+22);
        used=diag_u32(record+24); allocated=diag_u32(record+28);
        structure="usa_count_rejected";
        if (usa_count==size/512+1) {
            structure="usa_bounds_rejected";
            if (usa_offset>=48 && !(usa_offset%2) && usa_offset+2*usa_count<=510 &&
                usa_offset+2*usa_count<=attr_offset) {
                for (uint32_t i=1;i<usa_count;i++)
                    if (diag_u16(record+i*512-2)!=diag_u16(record+usa_offset)) mismatches++;
                structure="fixup_mismatch";
                if (!mismatches) {
                    structure="header_bounds_rejected";
                    if (!(attr_offset%8) && attr_offset>=48 && attr_offset<=size-4 &&
                        used>=attr_offset+4 && used<=size && allocated==size && !(flags&~3U))
                        structure="valid_header_fixups";
                }
            }
        }
    }
    /* Locate the SINGLE unnamed $MFT::$BITMAP, never volume::$Bitmap. */
    const TSK_FS_ATTR *bmap=NULL;
    int count=ntfs->mft_file?tsk_fs_file_attr_getsize(ntfs->mft_file):-1, matches=0;
    if (count>=0 && count<=1024) for (int i=0;i<count;i++) {
        const TSK_FS_ATTR *a=tsk_fs_file_attr_get_idx(ntfs->mft_file,i);
        if (a && a->type==TSK_FS_ATTR_TYPE_NTFS_BITMAP && (!a->name || !*a->name)) {
            bmap=a; matches++;
        }
    }
    if (matches==1 && diag_read(s,cluster,fs->block_count,bmap,inode/8,&bit,1,1)==1) {
        bitmap_value=!!(bit&(1U<<(inode%8))); bitmap=bitmap_value?"allocated":"free";
    }
    reason="bitmap_unavailable";
    if (bitmap_value>=0) {
        assessment="structural_rejection"; reason=structure;
        if (!strcmp(signature,"zero") && !bitmap_value) {
            assessment="unallocated_corroborated"; reason="zero_and_bitmap_free";
        } else if (!strcmp(structure,"valid_header_fixups")) {
            assessment="inconclusive"; reason="allocation_conflict";
            if (bitmap_value==!!(flags&1)) {
                assessment=bitmap_value?"valid_header_fixups":"unallocated_corroborated";
                reason="header_and_bitmap_agree";
            }
        }
    }
output:
    if (s->failed) { assessment="read_failed"; reason="provider_failed"; }
    printf("{\"kind\":\"diagnostic\",\"inode\":%" PRIuINUM ",\"assessment\":\"%s\",\"reason\":\"%s\","
           "\"inventory_eligible\":false,\"locator\":\"libtsk_mft_map\",\"checker\":\"bounded_header_fixups_v1\","
           "\"sector_size\":%u,\"cluster_size\":%u,\"record_size\":%u,\"mft_start_bytes\":%" PRIuDADDR ","
           "\"bitmap\":\"%s\",\"record\":",inode,assessment,reason,ntfs->ssize_b,cluster,size,ntfs->root_mft_addr,bitmap);
    if (!present) printf("null");
    else printf("{\"signature\":\"%s\",\"structure\":\"%s\",\"usa_offset\":%u,\"usa_count\":%u,"
                "\"attribute_offset\":%u,\"flags\":%u,\"bytes_used\":%u,\"bytes_allocated\":%u,\"fixup_mismatches\":%u}",
                signature,structure,usa_offset,usa_count,attr_offset,flags,used,allocated,mismatches);
    printf("}\n");
    return s->failed?3:0;
}
