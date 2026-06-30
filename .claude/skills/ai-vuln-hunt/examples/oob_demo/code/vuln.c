#include <stddef.h>
/* writes v at buf[idx] with no bounds check — classic OOB sink */
void write_at(unsigned char *buf, int idx, unsigned char v) { buf[idx] = v; }
int parse_and_store(int idx) {
  unsigned char buf[16];
  write_at(buf, idx, 0x41);   /* idx>=16 => stack-buffer-overflow */
  return buf[0];
}
