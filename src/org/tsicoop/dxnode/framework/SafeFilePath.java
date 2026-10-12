package org.tsicoop.dxnode.framework;

import java.nio.file.Path;

/**
 * Resolves a caller-supplied file name inside the node's storage directory.
 *
 * File names arrive from client applications and from peer nodes and are used to build paths on the
 * local filesystem. A name is accepted only if it is a single plain path segment, so it can never
 * point outside the storage directory.
 */
public final class SafeFilePath {

    private static final int MAX_NAME_LENGTH = 255;

    private SafeFilePath() {}

    /** Validates {@code fileName} and returns it unchanged; throws IllegalArgumentException otherwise. */
    public static String requireSafeName(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            throw new IllegalArgumentException("file_name is required.");
        }
        if (fileName.length() > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException("file_name is too long.");
        }
        if (fileName.equals(".") || fileName.equals("..")
                || fileName.indexOf('/') >= 0 || fileName.indexOf('\\') >= 0
                || fileName.indexOf('\0') >= 0 || fileName.indexOf(':') >= 0) {
            throw new IllegalArgumentException(
                "file_name must be a plain file name without path separators or relative segments.");
        }
        for (int i = 0; i < fileName.length(); i++) {
            if (Character.isISOControl(fileName.charAt(i))) {
                throw new IllegalArgumentException("file_name contains control characters.");
            }
        }
        return fileName;
    }

    /** Resolves the file inside {@code baseDir}, verifying the result cannot escape it. */
    public static Path resolve(String baseDir, String fileName) {
        requireSafeName(fileName);
        Path base = Path.of(baseDir).toAbsolutePath().normalize();
        Path target = base.resolve(fileName).normalize();
        if (!target.startsWith(base) || target.equals(base)) {
            throw new IllegalArgumentException("file_name resolves outside the storage directory.");
        }
        return target;
    }
}
