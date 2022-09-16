package com.example;


import com.code_intelligence.jazzer.api.Jazzer;

import java.io.*;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class IntentFuzzer {
    // intender-to-jazzer (i2j), jazzer-to-intender (j2i)
    private static final String i2j_path = "/tmp/ifuzzer/i2j-pipe";
    private static final String j2i_path = "/tmp/ifuzzer/j2i-pipe";
    private static final byte[] HELLO_MSG = {'H', 'E', 'L', 'O'};

    private static File i2jFile, j2iFile;
    private static InputStream proxyInput;
    private static OutputStream proxyOutput;
    private static int test_cnt;
    private static final int COVERAGE_MAP_SIZE = 1 << 16;
    private static final byte[] FEEDBACK_ZEROS = new byte[COVERAGE_MAP_SIZE + 1];
    private static byte[] feedback = new byte[COVERAGE_MAP_SIZE + 1];

    public static void fuzzerInitialize() {
        // Optional initialization to be run before the first call to fuzzerTestOneInput.
        System.out.println("Initialize Fuzzer!!");
        i2jFile = new File(i2j_path);
        j2iFile = new File(j2i_path);
//        feedback = ByteBuffer.allocate(COVERAGE_MAP_SIZE + 1);
//        feedback.order(ByteOrder.LITTLE_ENDIAN);

        if (i2jFile.exists() && j2iFile.exists())
            System.out.println("Pipe exists.");

        try {
            proxyOutput = new BufferedOutputStream(new FileOutputStream(j2iFile));
            System.out.println("OutputStream is opened.");
            proxyInput = new BufferedInputStream(new FileInputStream(i2jFile));
            System.out.println("InputStream is opened.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void fuzzerTestOneInput(byte[] data) {
        String fuzzStr = new String(data, StandardCharsets.US_ASCII);
        try {
//            System.out.printf("[%d] %s\n", test_cnt, fuzzStr);
            Files.write(Paths.get("/tmp/ifuzzer/output"), data);

            proxyOutput.write(HELLO_MSG, 0, 4);
            proxyOutput.flush();
        } catch (IOException e) {
            throw new EndFuzzException("done");
        }

        try {
            byte[] status = new byte[4];
            // 1. read first input (int), throw error message
            proxyInput.read(status, 0, 4);

//            ByteBuffer feedback = ByteBuffer.wrap(proxyInput.readAllBytes());
//            System.out.printf("%d\n", feedback.position());
//            System.out.printf("Read now! %d\n", ByteBuffer.wrap(status).order(ByteOrder.LITTLE_ENDIAN).getInt());

            int len = 0;
            while (len < COVERAGE_MAP_SIZE) {
                len += proxyInput.read(feedback, len, COVERAGE_MAP_SIZE - len);
//                System.out.printf(" %d/%d", len, COVERAGE_MAP_SIZE);
            }

            // i has 16 bits (7bits for state, 9bits for ID)
            for (int i = 0; i < COVERAGE_MAP_SIZE; i++) {
                if (feedback[i] > 0) {
//        int lowerBits = (state & 0x7f) | (id << 7);       // 12bits
//        int upperBits = id >>> 5;                         // 12bits
                    Jazzer.exploreState((byte) (i & 0x7f), i >>> 7);
                }
            }

            // NOTE: coverage for 3 bytes?? vs 65536 bytes for AFL?
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class EndFuzzException extends RuntimeException {
        EndFuzzException(String msg) { super(msg); }
    }
}
