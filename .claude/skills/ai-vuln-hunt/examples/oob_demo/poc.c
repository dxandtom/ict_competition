extern int parse_and_store(int);
int main(void) { return parse_and_store(20); }   /* idx 20 lands in ASAN's redzone => clean report */
