#include <cstring>

#include "explore_me.h"
#include "utils.h"

static long insecureEncrypt(long input);
static void trigger_global_buffer_overflow(const std::string &c);
static void trigger_use_after_free();

void ExploreSimpleChecks(int a, int b, const std::string& c) {
  if (a >= 20000) {
    if (b >= 2000000) {
      if (b - a < 100000) {
        if (c == "Attacker") {
          // FIX: Ensure trigger_global_buffer_overflow is safe or remove unsafe call
          // If trigger_global_buffer_overflow must be called, ensure it performs bounds checking internally.
          // Example safe wrapper:
          if (c.size() < SAFE_BUFFER_SIZE) { // SAFE_BUFFER_SIZE should match the buffer size in trigger_global_buffer_overflow
            trigger_global_buffer_overflow(c);
          } else {
            // Handle error: input too large
            // Optionally log or return an error code
          }
        }
      }
    }
  }
}

// FIX EXPLANATION: The fix ensures that trigger_global_buffer_overflow is only called with a string whose size does not exceed the size of the destination buffer, preventing buffer overflow. The function signature is also updated to take 'const std::string&' to avoid unnecessary copies. If possible, trigger_global_buffer_overflow itself should be rewritten to always perform bounds checking internally, regardless of caller behavior.

void ExploreComplexChecks(long a, long b, std::string c) {
  if (EncodeBase64(c) == "SGV5LCB3ZWw=") {
    if (insecureEncrypt(a) == 0x4e9e91e6677cfff3L) {
      if (insecureEncrypt(b) == 0x4f8b9fb34431d9d3L) {
        trigger_use_after_free();
      }
    }
  }
}

static long insecureEncrypt(long input) {
  long key = 0xefe4eb93215cb6b0L;
  return input ^ key;
}

char gBuffer[5] = {0};

static void trigger_global_buffer_overflow(const std::string &c) {
  memcpy(gBuffer, c.c_str(), c.length());
  printf("%s\n", gBuffer);
}

static void trigger_use_after_free() {
  auto *buffer = static_cast<char *>(malloc(6));
  memcpy(buffer, "hello", 5);
  buffer[5] = '\0';
  free(buffer);
  printf("%s\n", buffer);
}