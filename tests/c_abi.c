/* Compile this unchanged against upstream's original header and the Rust library. */
#include "libunshield.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <dirent.h>

_Static_assert(offsetof(UnshieldFileGroup, first_file) == sizeof(void *), "group layout");
_Static_assert(offsetof(UnshieldFileGroup, last_file) == sizeof(void *) + sizeof(int), "group layout");
_Static_assert(sizeof(UnshieldIoCallbacks) == 9 * sizeof(void *), "callback layout");
typedef struct { unsigned opens, closes, reads, writes, dirs, dir_closes; } State;
static void *cb_open(const char *p,const char *m,void *u) { FILE *f=fopen(p,m); if(f)((State *)u)->opens++; return f; }
static int cb_seek(void *f,long o,int w,void *u) { (void)u; return fseek((FILE *)f,o,w); }
static long cb_tell(void *f,void *u) { (void)u; return ftell((FILE *)f); }
static size_t cb_read(void *p,size_t s,size_t n,void *f,void *u) { ((State *)u)->reads++; return fread(p,s,n,(FILE *)f); }
static size_t cb_write(const void *p,size_t s,size_t n,void *f,void *u) { ((State *)u)->writes++; return fwrite(p,s,n,(FILE *)f); }
static int cb_close(void *f,void *u) { ((State *)u)->closes++; return fclose((FILE *)f); }
static void *cb_opendir(const char *p,void *u) { DIR *d=opendir(p);if(d)((State *)u)->dirs++;return d; }
static int cb_closedir(void *d,void *u) { ((State *)u)->dir_closes++;return closedir((DIR *)d); }
static struct dirent *cb_readdir(void *d,void *u) { (void)u;return readdir((DIR *)d); }
static void *cb_no_dir(const char *p,void *u) { (void)p;(void)u;return NULL; }
static void compare(const char *a,const char *b) {
    FILE *x=fopen(a,"rb"),*y=fopen(b,"rb");int c,d;assert(x&&y);
    do {c=fgetc(x);d=fgetc(y);assert(c==d);} while(c!=EOF);assert(!ferror(x)&&!ferror(y));fclose(x);fclose(y);
}
static void copy_file(const char *a,const char *b) {
    FILE *x=fopen(a,"rb"),*y=fopen(b,"wb");int c;assert(x&&y);
    while((c=fgetc(x))!=EOF)assert(fputc(c,y)!=EOF);
    assert(!ferror(x));assert(!fclose(x));assert(!fclose(y));
}
static void exercise(Unshield *h,const char *out,const char *expected,int version) {
    const char *name;UnshieldFileGroup *g;
    assert(h);assert(unshield_file_count(h)==1);assert(unshield_directory_count(h)==1);
    assert(unshield_component_count(h)==1);assert(unshield_file_group_count(h)==1);
    assert(!strcmp(unshield_component_name(h,0),"Application"));assert(!strcmp(unshield_directory_name(h,0),"files"));
    assert(!strcmp(unshield_file_group_name(h,0),"Main"));
    name=unshield_file_name(h,0);assert(name);assert(unshield_file_is_valid(h,0));assert(unshield_file_directory(h,0)==0);
    assert(unshield_file_size(h,0)>65536);assert(unshield_is_unicode(h)==(version>=17));
    g=unshield_file_group_get(h,0);assert(g&&g->first_file==0&&g->last_file==0&&!strcmp(g->name,"Main"));
    assert(g==unshield_file_group_find(h,"Main"));assert(!unshield_file_group_find(h,"missing"));
    assert(unshield_file_save(h,0,NULL));assert(unshield_file_save(h,0,out));compare(out,expected);
    if(version<=5) {assert(unshield_file_save_old(h,0,out));compare(out,expected);}
    assert(unshield_file_save_raw(h,0,NULL));
    assert(name==unshield_file_name(h,0));assert(!unshield_file_name(h,-1));assert(!unshield_file_is_valid(h,1));
    assert(unshield_file_directory(h,1)==-1);assert(unshield_file_size(h,-1)==0);assert(!unshield_file_group_get(h,-1));
    assert(!unshield_file_save(h,-1,NULL));assert(!unshield_file_save_old(h,-1,NULL));assert(!unshield_file_save_raw(h,-1,NULL));
}
int main(int argc,char **argv) {
    char cabinet[4096],out[4096],expected[4096],source[4096];int versions[]={0,5,6,17};unsigned i;
    State state={0};UnshieldIoCallbacks cb={cb_open,cb_seek,cb_tell,cb_read,cb_write,cb_close,cb_opendir,cb_closedir,cb_readdir};
    unsigned seed=0;unsigned char encoded[]={0xd5,0xdd,0xc5};
#ifdef _WIN32
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0,_WRITE_ABORT_MSG|_CALL_REPORTFAULT);
#endif
    assert(argc==2);unshield_set_log_level(0);
    unshield_deobfuscate(encoded,sizeof(encoded),&seed);assert(seed==3&&encoded[0]==0&&encoded[1]==1&&encoded[2]==2);
    unshield_close(NULL);assert(!unshield_open(NULL));
    for(i=0;i<sizeof(versions)/sizeof(versions[0]);i++) {
        Unshield *h;int v=versions[i];
        snprintf(cabinet,sizeof(cabinet),"%s/v%d/data1.cab",argv[1],v);
        snprintf(out,sizeof(out),"%s/v%d/result.bin",argv[1],v);snprintf(expected,sizeof(expected),"%s/v%d/expected.bin",argv[1],v);
        h=unshield_open(cabinet);exercise(h,out,expected,v);unshield_close(h);
        h=unshield_open_force_version(cabinet,v);exercise(h,out,expected,v);unshield_close(h);
        h=unshield_open2(cabinet,&cb,&state);exercise(h,out,expected,v);unshield_close(h);
        h=unshield_open2_force_version(cabinet,v,&cb,&state);exercise(h,out,expected,v);unshield_close(h);
    }
    /* If opendir is unavailable, upstream falls back to direct fopen. Also test
       embedded metadata with no .hdr sibling, where fopen must fall back to CAB. */
    snprintf(cabinet,sizeof(cabinet),"%s/v6_embedded/data1.cab",argv[1]);
    snprintf(out,sizeof(out),"%s/v6_embedded/result.bin",argv[1]);snprintf(expected,sizeof(expected),"%s/v6_embedded/expected.bin",argv[1]);
    cb.opendir=cb_no_dir;
    { Unshield *h=unshield_open2(cabinet,&cb,&state);exercise(h,out,expected,6);unshield_close(h); }
    /* Narrow C filename bytes must survive both native and callback I/O. */
    snprintf(source,sizeof(source),"%s/v6/data1.hdr",argv[1]);snprintf(cabinet,sizeof(cabinet),"%s/v6/\xc3\xa9" "data1.hdr",argv[1]);copy_file(source,cabinet);
    snprintf(source,sizeof(source),"%s/v6/data1.cab",argv[1]);snprintf(cabinet,sizeof(cabinet),"%s/v6/\xc3\xa9" "data1.cab",argv[1]);copy_file(source,cabinet);
    snprintf(out,sizeof(out),"%s/v6/\xc3\xa9" "result.bin",argv[1]);snprintf(expected,sizeof(expected),"%s/v6/expected.bin",argv[1]);
    { Unshield *h=unshield_open(cabinet);exercise(h,out,expected,6);unshield_close(h); }
    cb.opendir=cb_opendir;
    { Unshield *h=unshield_open2(cabinet,&cb,&state);exercise(h,out,expected,6);unshield_close(h); }
    assert(state.reads&&state.writes&&state.dirs);assert(state.opens==state.closes);assert(state.dirs==state.dir_closes);
    puts("C ABI: all public functions, extraction bytes, callback I/O and lifetimes passed");return 0;
}
