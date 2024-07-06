package org.example;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

public class ChatServer {
    private static final Logger logger = Logger.getLogger(ChatServer.class.getName());
    private static Set<ClientHandler> clientHandlers = new HashSet<>();
    private static final String BASE_KEY = "your-secure-base-key";

    public static void main(String[] args) {
        int port = 30023;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("Server started on port " + port);

            new Thread(new ServerInputHandler()).start();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                ClientHandler clientHandler = new ClientHandler(clientSocket, BASE_KEY);
                clientHandlers.add(clientHandler);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error starting the server", e);
        }
    }

    public static void broadcastMessage(String message, ClientHandler sender) {
        for (ClientHandler clientHandler : clientHandlers) {
            if (clientHandler != sender) {
                clientHandler.sendMessage(message);
            }
        }
    }

    public static void broadcastMessageFromServer(String message) {
        for (ClientHandler clientHandler : clientHandlers) {
            clientHandler.sendMessage("Server: " + message);
        }
    }

    public static void removeClient(ClientHandler clientHandler) {
        clientHandlers.remove(clientHandler);
    }
}

class ClientHandler implements Runnable {
    private static final Logger logger = Logger.getLogger(ClientHandler.class.getName());
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private String clientName;
    private String baseKey;

    public ClientHandler(Socket socket, String baseKey) {
        this.socket = socket;
        this.baseKey = baseKey;
    }

    @Override
    public void run() {
        try {
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Read the client's name (unencrypted)
            clientName = in.readLine();
            logger.info(clientName + " has joined the chat");
            ChatServer.broadcastMessage(clientName + " has joined the chat", this);

            String message;
            while ((message = in.readLine()) != null) {
                try {
                    long ntpTime = CryptoUtils.getNTPTime() / 1000;
                    SecretKey key = CryptoUtils.deriveKey(baseKey, ntpTime);
                    String decryptedMessage = CryptoUtils.decrypt(message, key);
                    ChatServer.broadcastMessage("\n[" + clientName + "]" + ": " + decryptedMessage, this);
                    System.out.println("\n[" + clientName + "]" + ": " + decryptedMessage);
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error decrypting message", e);
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error in client handler", e);
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                logger.log(Level.INFO, "Error closing socket", e);
            }
            ChatServer.removeClient(this);
            logger.info(clientName + " has left the chat");
            ChatServer.broadcastMessage(clientName + " has left the chat", this);
        }
    }

    public void sendMessage(String message) {
        try {
            long ntpTime = CryptoUtils.getNTPTime() / 1000;
            SecretKey key = CryptoUtils.deriveKey(baseKey, ntpTime);
            String encryptedMessage = CryptoUtils.encrypt(message, key);
            out.println(encryptedMessage);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error encrypting message", e);
        }
    }
}
class ServerInputHandler implements Runnable {
    private static final Logger logger = Logger.getLogger(ServerInputHandler.class.getName());
    private BufferedReader stdIn;

    public ServerInputHandler() {
        stdIn = new BufferedReader(new InputStreamReader(System.in));
    }

    @Override
    public void run() {
        String serverInput;
        try {
            while ((serverInput = stdIn.readLine()) != null) {
                ChatServer.broadcastMessageFromServer(serverInput);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error reading from server console", e);
        }
    }
}

