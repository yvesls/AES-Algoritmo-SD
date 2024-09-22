package com.aes;

import java.io.*;
import java.net.*;

public class AESTCPServer extends Thread {
    private AES128 aes;
    private int port;

    public AESTCPServer(AES128 aes, int port) {
        this.aes = aes;
        this.port = port;
    }

    @Override
    public void run() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Servidor esperando conexão na porta " + port);

            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                        DataInputStream in = new DataInputStream(clientSocket.getInputStream());
                        DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {

                    System.out.println("Cliente conectado.");

                    byte[] encryptedMessage = new byte[16];
                    in.readFully(encryptedMessage);

                    byte[] decryptedMessage = aes.decrypt(encryptedMessage);
                    System.out.println("Mensagem descriptografada: " + new String(decryptedMessage));

                    String resposta = "Olá, cliente!";
                    byte[] encryptedResponse = aes.encrypt(resposta.getBytes());
                    out.write(encryptedResponse);
                    out.flush();

                    System.out.println("Resposta criptografada enviada ao cliente.");
                } catch (IOException e) {
                    System.out.println("Erro na conexão com o cliente: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.out.println("Erro no servidor: " + e.getMessage());
        }
    }
}
