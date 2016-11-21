// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.javaassertionenabler;

import com.google.common.io.ByteStreams;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * An application that enables Java ASSERT statements by modifying Java bytecode. It takes in a JAR
 * file, modifies bytecode of classes that use ASSERT, and outputs the bytecode to a new JAR file.
 */
class AssertionEnabler {
    static final String CLASS_FILE_SUFFIX = ".class";
    static final String STATIC_INITIALIZER_NAME = "<clinit>";
    static final String ASSERTION_DISABLED_NAME = "$assertionsDisabled";

    static class AssertionEnablerVisitor extends ClassVisitor {
        AssertionEnablerVisitor(ClassWriter writer) {
            super(Opcodes.ASM5, writer);
        }

        @Override
        public MethodVisitor visitMethod(final int access, final String name, String desc,
                String signature, String[] exceptions) {
            // Patch static initializer.
            if ((access & Opcodes.ACC_STATIC) != 0 && name.equals(STATIC_INITIALIZER_NAME)) {
                return new MethodVisitor(Opcodes.ASM5,
                        super.visitMethod(access, name, desc, signature, exceptions)) {
                    // The following bytecode is generated for each class with ASSERT statements:
                    // 0: ldc #8 // class CLASSNAME
                    // 2: invokevirtual #9 // Method java/lang/Class.desiredAssertionStatus:()Z
                    // 5: ifne 12
                    // 8: iconst_1
                    // 9: goto 13
                    // 12: iconst_0
                    // 13: putstatic #2 // Field $assertionsDisabled:Z
                    //
                    // This function replaces line #13 to the following:
                    // 13: pop
                    // Consequently, $assertionsDisabled is assigned the default value FALSE.
                    @Override
                    public void visitFieldInsn(int opcode, String owner, String name, String desc) {
                        if (opcode == Opcodes.PUTSTATIC && name.equals(ASSERTION_DISABLED_NAME)) {
                            mv.visitInsn(Opcodes.POP);
                        } else {
                            super.visitFieldInsn(opcode, owner, name, desc);
                        }
                    }
                };
            }
            return super.visitMethod(access, name, desc, signature, exceptions);
        }
    }

    static void enableAssertionInJar(String inputJarPath, String outputJarPath) {
        try (JarOutputStream outputStream = new JarOutputStream(
                new BufferedOutputStream(new FileOutputStream(outputJarPath)))) {
            JarFile jarFile = new JarFile(inputJarPath);
            for (JarEntry entry : Collections.list(jarFile.entries())) {
                try (BufferedInputStream inputStream = new BufferedInputStream(
                        jarFile.getInputStream(entry))) {
                    byte[] byteCode = ByteStreams.toByteArray(inputStream);

                    if (entry.isDirectory() || !entry.getName().endsWith(CLASS_FILE_SUFFIX)) {
                        outputStream.putNextEntry(entry);
                        outputStream.write(byteCode);
                        outputStream.closeEntry();
                        continue;
                    }
                    ClassReader reader = new ClassReader(byteCode);
                    ClassWriter writer = new ClassWriter(reader, 0);
                    reader.accept(new AssertionEnablerVisitor(writer), 0);
                    byte[] patchedByteCode = writer.toByteArray();
                    outputStream.putNextEntry(new JarEntry(entry.getName()));
                    outputStream.write(patchedByteCode);
                    outputStream.closeEntry();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Incorrect number of arguments.");
            System.out.println("Example usage: java_assertion_enabler input.jar output.jar");
            System.exit(-1);
        }
        enableAssertionInJar(args[0], args[1]);
    }
}
