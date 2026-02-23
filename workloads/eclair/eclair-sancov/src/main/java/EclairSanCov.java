import java.io.File;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.ByteBuffer;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

// Java agent that provides AFL coverage feedback for Eclair.
//
// When loaded via -javaagent:eclair-sancov.jar, this agent maps the AFL shared
// memory region and instruments Eclair's classes to record method-level
// coverage.
//
// Edge IDs are pre-assigned by scanning all Eclair JARs on the classpath before
// any class is loaded, sorted by class name then declaration order within each
// class. This gives stable IDs across restarts, which is required for afl-cmin
// and cross-session coverage comparisons to work correctly.
public class EclairSanCov {

  // Map from "InternalClassName#methodName#descriptor" to pre-assigned edge ID.
  // Populated by prescan() before any class transformation occurs.
  static Map<String, Integer> edgeIds = null;

  // Direct ByteBuffer pointing at the AFL shared memory region.
  static volatile ByteBuffer shmBuffer = null;

  // Java agent entry point, called by the JVM before main().
  public static void premain(String args, Instrumentation inst) {
    String shmIdStr = System.getenv("__AFL_SHM_ID");
    if (shmIdStr == null) {
      throw new RuntimeException("eclair-sancov: __AFL_SHM_ID not set");
    }

    edgeIds = prescan();

    System.loadLibrary("eclair-sancov");
    shmBuffer = mapShm(Integer.parseInt(shmIdStr));

    inst.addTransformer(new EclairTransformer());
  }

  // Maps the AFL shared memory segment via shmat and wraps it as a direct
  // ByteBuffer. The buffer capacity equals AFL_MAP_SIZE (set in the environment
  // by the nyx-agent before spawning Eclair). Implemented in shmutil.c via JNI.
  private static native ByteBuffer mapShm(int shmId);

  // Records coverage for an instrumented edge. Called from every instrumented
  // method entry. edgeId is a pre-assigned sequential integer always in
  // [0, AFL_MAP_SIZE).
  public static void edge(int edgeId) {
    shmBuffer.put(edgeId, (byte)(shmBuffer.get(edgeId) + 1));
  }

  // Scans all Eclair JARs on the classpath and assigns sequential edge IDs to
  // every non-abstract, non-native method in fr/acinq/eclair/ classes. Classes
  // are processed in sorted order by internal name; methods within each class
  // are processed in declaration order (as visited by ASM). This gives
  // deterministic IDs independent of class loading order at runtime.
  static Map<String, Integer> prescan() {
    // Collect the set of JAR files to scan. java.class.path contains the
    // explicit -cp arguments, which may include JAR files and directories.
    List<String> jarPaths = new ArrayList<>();
    String classpath = System.getProperty("java.class.path", "");
    for (String entry : classpath.split(":")) {
      if (entry.endsWith(".jar")) {
        jarPaths.add(entry);
      } else {
        File dir = new File(entry);
        if (dir.isDirectory()) {
          File[] jars = dir.listFiles(f -> f.getName().endsWith(".jar"));
          if (jars != null) {
            for (File jar : jars) {
              jarPaths.add(jar.getAbsolutePath());
            }
          }
        }
      }
    }

    // Collect all fr/acinq/eclair/ class files from classpath JARs, sorted by
    // class name for deterministic ordering.
    TreeMap<String, byte[]> sortedClasses = new TreeMap<>();

    for (String entry : jarPaths) {
      try (JarFile jar = new JarFile(entry)) {
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
          JarEntry je = entries.nextElement();
          String name = je.getName();
          if (!name.startsWith("fr/acinq/eclair/") ||
              !name.endsWith(".class")) {
            continue;
          }
          String className =
              name.substring(0, name.length() - 6); // strip .class
          try (InputStream is = jar.getInputStream(je)) {
            sortedClasses.put(className, is.readAllBytes());
          }
        }
      } catch (Exception e) {
        throw new RuntimeException(
            "eclair-sancov: failed to scan JAR: " + entry, e);
      }
    }

    // Assign sequential IDs by visiting each class in sorted order. counter[0]
    // is used instead of a plain int because the anonymous ClassVisitor
    // requires any captured variable to be effectively final.
    Map<String, Integer> ids = new HashMap<>();
    int[] counter = {0};

    for (Map.Entry<String, byte[]> entry : sortedClasses.entrySet()) {
      String className = entry.getKey();
      byte[] bytecode = entry.getValue();

      ClassReader reader = new ClassReader(bytecode);
      reader.accept(
          new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(
                int access, String name, String descriptor, String signature,
                String[] exceptions) {
              // We include the descriptor in the key because overloaded methods
              // share the same name. The descriptor encodes the parameter and
              // return types (e.g. "(I)V" = takes int, returns void), making it
              // unique per overload.
              if ((access & Opcodes.ACC_ABSTRACT) == 0 &&
                  (access & Opcodes.ACC_NATIVE) == 0) {
                String key = className + "#" + name + "#" + descriptor;
                ids.put(key, counter[0]++);
              }
              return null;
            }
            // SKIP_CODE, SKIP_DEBUG, SKIP_FRAMES tell ASM not to parse the
            // method bodies, debug info, or stack frames -- we only need names
            // and access flags for the prescan, so this is significantly
            // faster.
          },
          ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG |
              ClassReader.SKIP_FRAMES);
    }

    return ids;
  }

  // ASM ClassFileTransformer that inserts a call to edge() at the entry point
  // of every non-abstract, non-native method in Eclair classes.
  static class EclairTransformer implements ClassFileTransformer {

    private static final String ECLAIR_PREFIX = "fr/acinq/eclair/";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {

      if (className == null || !className.startsWith(ECLAIR_PREFIX)) {
        return null; // null = no transformation
      }

      ClassReader reader = new ClassReader(classfileBuffer);
      // COMPUTE_FRAMES tells ASM to recompute stack map frames from scratch
      // after transformation (inserting an INVOKESTATIC changes stack depth).
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
      reader.accept(new EclairClassVisitor(writer, className), 0);
      return writer.toByteArray();
    }
  }

  static class EclairClassVisitor extends ClassVisitor {

    private final String className;

    EclairClassVisitor(ClassVisitor cv, String className) {
      super(Opcodes.ASM9, cv);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {

      MethodVisitor mv =
          super.visitMethod(access, name, descriptor, signature, exceptions);

      if ((access & Opcodes.ACC_ABSTRACT) != 0 ||
          (access & Opcodes.ACC_NATIVE) != 0) {
        return mv;
      }

      String key = className + "#" + name + "#" + descriptor;
      Integer edgeId = EclairSanCov.edgeIds.get(key);
      if (edgeId == null) {
        // Class was not found in the prescan (e.g. dynamically generated at
        // runtime). Scala closures compiled into JARs are picked up by the
        // prescan; true runtime-generated classes (e.g. reflection proxies)
        // typically have non-Eclair names and are excluded by the prefix filter
        // before reaching here.
        return mv;
      }

      return new EclairMethodVisitor(mv, edgeId);
    }
  }

  static class EclairMethodVisitor extends MethodVisitor {

    private final int edgeId;

    EclairMethodVisitor(MethodVisitor mv, int edgeId) {
      super(Opcodes.ASM9, mv);
      this.edgeId = edgeId;
    }

    @Override
    public void visitCode() {
      // visitCode() opens the Code attribute and must be called first. Probe
      // instructions inserted after it appear at the top of the method body,
      // before any original bytecode.
      super.visitCode();
      // Push edgeId constant and call EclairSanCov.edge(int).
      super.visitLdcInsn(edgeId);
      super.visitMethodInsn(Opcodes.INVOKESTATIC, "EclairSanCov", "edge",
                            "(I)V", false);
    }
  }
}
