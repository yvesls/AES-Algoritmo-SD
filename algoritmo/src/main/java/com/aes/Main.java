package com.aes;

public class Main {
    public static void main(String[] args) {
        byte[] key = { (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xae, (byte) 0xd2,
                (byte) 0xa6, (byte) 0xab, (byte) 0xf7, (byte) 0xcf, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xcf,
                (byte) 0x4f };
        AES128 aes = new AES128(key);

        AESTCPServer server = new AESTCPServer(aes, 54321);

        server.start();

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        AESTCPClient client = new AESTCPClient(aes, "localhost", 54321);

        client.start();
    }
}
