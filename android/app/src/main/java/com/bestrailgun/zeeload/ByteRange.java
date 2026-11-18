package com.bestrailgun.zeeload;

/** Single-range HTTP parsing. Unsatisfiable/multipart requests produce 416, never a clamped wrong slice. */
final class ByteRange {
    final long start, end; final boolean partial;
    private ByteRange(long s, long e, boolean p) { start = s; end = e; partial = p; }
    long length() { return end - start + 1; }
    static ByteRange parse(String header, long total) {
        if (total <= 0) throw new IllegalArgumentException("empty file");
        if (header == null || header.isEmpty()) return new ByteRange(0, total - 1, false);
        if (!header.matches("bytes=(?:[0-9]+-[0-9]*|-[0-9]+)")) throw new IllegalArgumentException("invalid range");
        String[] p = header.substring(6).split("-", -1);
        try {
            long start, end;
            if (p[0].isEmpty()) {
                long suffix = Long.parseLong(p[1]); if (suffix <= 0) throw new IllegalArgumentException("empty suffix");
                start = Math.max(0, total - suffix); end = total - 1;
            } else {
                start = Long.parseLong(p[0]); end = p[1].isEmpty() ? total - 1 : Math.min(total - 1, Long.parseLong(p[1]));
            }
            if (start >= total || end < start) throw new IllegalArgumentException("unsatisfiable range");
            return new ByteRange(start, end, true);
        } catch (NumberFormatException e) { throw new IllegalArgumentException("range overflow", e); }
    }
}
