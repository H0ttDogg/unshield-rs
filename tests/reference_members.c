/* Build against the pinned upstream C library to produce independent evidence.
 * Output names use member indices so duplicate/unsafe archive paths cannot collide.
 */
#include <libunshield.h>
#include <stdio.h>
#include <string.h>

static void hex(const char *s) {
    putchar('"');
    if (s) for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
        printf("%02x", *p);
    putchar('"');
}

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[3], "new") && strcmp(argv[3], "old"))) {
        fprintf(stderr, "usage: reference-members CAB EXISTING_OUTPUT_DIR new|old\n");
        return 2;
    }
    unshield_set_log_level(0);
    Unshield *u = unshield_open(argv[1]);
    if (!u) return 3;
    printf("{\"unicode\":%s,\"directories_hex\":[", unshield_is_unicode(u) ? "true" : "false");
    for (int i = 0; i < unshield_directory_count(u); ++i) {
        if (i) putchar(',');
        hex(unshield_directory_name(u, i));
    }
    printf("],\"components_hex\":[");
    for (int i = 0; i < unshield_component_count(u); ++i) {
        if (i) putchar(',');
        hex(unshield_component_name(u, i));
    }
    printf("],\"groups\":[");
    for (int i = 0; i < unshield_file_group_count(u); ++i) {
        UnshieldFileGroup *g = unshield_file_group_get(u, i);
        if (!g) { unshield_close(u); return 4; }
        if (i) putchar(',');
        printf("{\"name_hex\":"); hex(g->name);
        printf(",\"first_file\":%d,\"last_file\":%d}", g->first_file, g->last_file);
    }
    printf("],\"files\":[");
    int failed = 0;
    for (int i = 0; i < unshield_file_count(u); ++i) {
        bool valid = unshield_file_is_valid(u, i);
        if (i) putchar(',');
        printf("{\"index\":%d,\"valid\":%s,\"name_hex\":", i, valid ? "true" : "false");
        hex(unshield_file_name(u, i));
        printf(",\"directory_index\":%d,\"expanded_size\":%zu}",
            unshield_file_directory(u, i), unshield_file_size(u, i));
        if (valid) {
            char path[4096];
            int n = snprintf(path, sizeof(path), "%s/%d.bin", argv[2], i);
            if (n < 0 || (size_t)n >= sizeof(path) ||
                !(strcmp(argv[3], "old") ? unshield_file_save(u, i, path) : unshield_file_save_old(u, i, path))) {
                fprintf(stderr, "reference extraction failed for member %d\n", i);
                failed = 1;
            }
        }
    }
    printf("]}\n");
    unshield_close(u);
    return failed;
}
