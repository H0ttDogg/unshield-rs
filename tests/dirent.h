/* Self-contained C test adapter using upstream's Windows dirent ABI layout. */
#ifdef _WIN32
#include <io.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
struct dirent {
    long d_ino;
    unsigned short d_reclen;
    size_t d_namlen;
    int d_type;
    char d_name[260];
};
typedef struct {
    intptr_t handle;
    struct _finddata_t data;
    struct dirent entry;
    int first;
} DIR;
static DIR *opendir(const char *name) {
    size_t len=strlen(name);
    char *pattern=(char *)malloc(len+3);
    DIR *directory=(DIR *)calloc(1,sizeof(DIR));
    if(!pattern||!directory) {free(pattern);free(directory);return NULL;}
    memcpy(pattern,name,len);pattern[len]='\\';pattern[len+1]='*';pattern[len+2]=0;
    directory->handle=_findfirst(pattern,&directory->data);free(pattern);
    if(directory->handle==-1) {free(directory);return NULL;}
    directory->first=1;return directory;
}
static struct dirent *readdir(DIR *directory) {
    if(directory->first) directory->first=0;
    else if(_findnext(directory->handle,&directory->data)!=0) return NULL;
    directory->entry.d_reclen=(unsigned short)sizeof(struct dirent);
    directory->entry.d_namlen=strlen(directory->data.name);
    directory->entry.d_type=(directory->data.attrib&_A_SUBDIR)?4:8;
    memcpy(directory->entry.d_name,directory->data.name,directory->entry.d_namlen+1);
    return &directory->entry;
}
static int closedir(DIR *directory) {
    int result=_findclose(directory->handle);free(directory);return result;
}
#else
#include_next <dirent.h>
#endif
