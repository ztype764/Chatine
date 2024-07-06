package org.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ChatServer {
    private static final Logger logger = Logger.getLogger(ChatServer.class.getName());
    static Set<ClientHandler> clientHandlers = new HashSet<>();
    private static final Set<String> clientNames = new HashSet<>();

    public static void main(String[] args) {
        int port = 30023;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("Server started on port " + port);

            new Thread(new ServerInputHandler()).start();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                ClientHandler clientHandler = new ClientHandler(clientSocket);
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
        String upperCaseMessage = message.toUpperCase();
        String redMessage = "\u001B[31m" + upperCaseMessage + "\u001B[0m";
        for (ClientHandler clientHandler : clientHandlers) {
            clientHandler.sendMessage("Server: " + redMessage);
        }
    }

    public static void removeClient(String client) {
        clientNames.remove(client);
    }
    public static boolean isNameAvailable(String name) {
        return !clientNames.contains(name);
    }

    public static void addClientName(String name) {
        clientNames.add(name);
    }
}
class ServerInputHandler implements Runnable {
    private static final Logger logger = Logger.getLogger(ServerInputHandler.class.getName());
    private final BufferedReader stdIn;

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

