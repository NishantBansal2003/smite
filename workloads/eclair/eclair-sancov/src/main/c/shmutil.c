#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/shm.h>

// JNI implementation of EclairSanCov.mapShm(int shmId).
//
// Attaches to the AFL shared memory segment identified by shmId via shmat()
// and wraps the region as a Java direct ByteBuffer. The buffer capacity is
// read from AFL_MAP_SIZE (set in the environment by the nyx-agent to match
// the allocated segment size).
//
// Called once from EclairSanCov.premain() before any class transformation.
JNIEXPORT jobject JNICALL Java_EclairSanCov_mapShm(JNIEnv *env, jclass cls,
                                                   jint shmId) {
  const char *map_size_str = getenv("AFL_MAP_SIZE");
  if (map_size_str == NULL) {
    fprintf(stderr, "eclair-sancov: AFL_MAP_SIZE not set\n");
    return NULL;
  }
  long map_size = atol(map_size_str);
  if (map_size <= 0) {
    fprintf(stderr, "eclair-sancov: invalid AFL_MAP_SIZE: %s\n", map_size_str);
    return NULL;
  }

  void *ptr = shmat((int)shmId, NULL, 0);
  if (ptr == (void *)-1) {
    perror("eclair-sancov: shmat");
    return NULL;
  }

  return (*env)->NewDirectByteBuffer(env, ptr, (jlong)map_size);
}
