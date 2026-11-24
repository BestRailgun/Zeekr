package com.bestrailgun.zeeload;

import org.junit.Assume;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class RootRulesTest {
    @Test
    public void redirectInstallsWithLegacyAndNftBackends() throws Exception {
        Assume.assumeTrue("Runs in the Linux CI network namespace", "1".equals(System.getenv("ZEELOAD_TEST_FIREWALL")));

        for (String backend : new String[]{"iptables-legacy", "iptables-nft"}) {
            String command = RootRules.redirectCommand().replaceFirst("^iptables ", backend + " ");
            String withoutProtocol = command.replace(" -p tcp", "");
            String script = "set -eu\n"
                + backend + " --version\n"
                + backend + " -w 5 -t nat -N ZLAD_N\n"
                // Reproduce the old failure using the real extension parser before installing the fixed rule.
                + "if " + withoutProtocol + " >old-error.txt 2>&1; then cat old-error.txt; exit 1; fi\n"
                + "grep -q 'Need TCP, UDP' old-error.txt\n"
                + command + "\n"
                + command.replace(" -A ZLAD_N", " -C ZLAD_N") + "\n"
                + backend + " -w 5 -t nat -S ZLAD_N\n"
                + backend + " -w 5 -t nat -F ZLAD_N\n"
                + backend + " -w 5 -t nat -X ZLAD_N\n";

            // A fresh network namespace confines every rule to this test process.
            Process process = new ProcessBuilder("sudo", "-n", "unshare", "--net", "/bin/sh", "-c", script)
                .directory(java.nio.file.Files.createTempDirectory("zeeload-firewall-").toFile())
                .redirectErrorStream(true)
                .start();
            ByteArrayOutputStream captured = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> {
                try (InputStream output = process.getInputStream()) {
                    byte[] buffer = new byte[4096];
                    int count;
                    while ((count = output.read(buffer)) != -1) captured.write(buffer, 0, count);
                } catch (java.io.IOException ignored) { }
            });
            reader.setDaemon(true);
            reader.start();
            try {
                assertTrue(backend + " timed out", process.waitFor(30, TimeUnit.SECONDS));
                reader.join(2000);
                String output = captured.toString(StandardCharsets.UTF_8.name());
                System.out.println(output);
                assertEquals(backend + "\n" + output, 0, process.exitValue());
                assertTrue(output, output.contains("-p tcp"));
            } finally {
                process.destroyForcibly();
            }
        }
    }
}
