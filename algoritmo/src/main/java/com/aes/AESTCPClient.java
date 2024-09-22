package com.aes;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

public class AESTCPClient extends Thread {
    private AES128 aes;
    private String serverHost;
    private int serverPort;

    public AESTCPClient(AES128 aes, String serverHost, int serverPort) {
        this.aes = aes;
        this.serverHost = serverHost;
        this.serverPort = serverPort;
    }

    @Override
    public void run() {
        try (Socket socket = new Socket(serverHost, serverPort);
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            System.out.println("Conectado ao servidor.");

            String mensagem = "Olá, servidor!";
            byte[] encryptedMessage = aes.encrypt(aes.pad(mensagem.getBytes(StandardCharsets.UTF_8)));

            out.write(encryptedMessage);
            out.flush();
            System.out.println("Mensagem criptografada enviada ao servidor.");

            byte[] encryptedResponse = new byte[16];
            in.readFully(encryptedResponse);

            byte[] decryptedResponse = aes.decrypt(encryptedResponse);
            System.out.println("Resposta descriptografada do servidor: " + new String(decryptedResponse));

        } catch (IOException e) {
            System.out.println("Erro no cliente: " + e.getMessage());
        }
    }
}
