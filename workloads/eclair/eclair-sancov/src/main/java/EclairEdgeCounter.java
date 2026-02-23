import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

// Counts the number of instrumentable methods in Eclair JARs.
//
// Used at Docker build time to determine TARGET_MAP_SIZE for the smite scenario
// binary. Counts the same methods that EclairSanCov.prescan() assigns IDs to:
// non-abstract, non-native methods in fr/acinq/eclair/ classes, which are the
// only methods that EclairTransformer instruments.
//
// Usage: java -cp eclair-sancov.jar EclairEdgeCounter <jar1> [<jar2> ...]
//
// Prints the method count to stdout.
public class EclairEdgeCounter {

  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      System.err.println("Usage: EclairEdgeCounter <jar1> [<jar2> ...]");
      System.exit(1);
    }

    int count = 0;

    for (String jarPath : args) {
      if (!jarPath.endsWith(".jar")) {
        continue;
      }
      try (JarFile jar = new JarFile(jarPath)) {
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
          JarEntry je = entries.nextElement();
          String name = je.getName();
          if (!name.startsWith("fr/acinq/eclair/") ||
              !name.endsWith(".class")) {
            continue;
          }
          try (InputStream is = jar.getInputStream(je)) {
            byte[] bytecode = is.readAllBytes();
            ClassReader reader = new ClassReader(bytecode);
            // methodCount[0] is used instead of a plain int because the
            // anonymous ClassVisitor requires any captured variable to be
            // effectively final.
            int[] methodCount = {0};
            reader.accept(
                new ClassVisitor(Opcodes.ASM9) {
                  @Override
                  public MethodVisitor visitMethod(
                      int access, String name, String descriptor,
                      String signature, String[] exceptions) {
                    if ((access & Opcodes.ACC_ABSTRACT) == 0 &&
                        (access & Opcodes.ACC_NATIVE) == 0) {
                      ++methodCount[0];
                    }
                    return null;
                  }
                  // SKIP_CODE, SKIP_DEBUG, SKIP_FRAMES tell ASM not to parse
                  // the method bodies, debug info, or stack frames -- we only
                  // need names and access flags for the prescan, so this is
                  // significantly faster.
                },
                ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG |
                    ClassReader.SKIP_FRAMES);
            count += methodCount[0];
          }
        }
      } catch (Exception e) {
        throw new RuntimeException(
            "EclairEdgeCounter: failed to scan JAR: " + jarPath, e);
      }
    }

    System.out.println(count);
  }
}
