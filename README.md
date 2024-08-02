Key Components and Considerations
We designed the blockchain-enabled fog cloud networks for digital applications. 
The usage of digital and intelligent healthcare applications on mobile devices has grown progressively. These applications are generally distributed and access remote healthcare services on the user’s applications from different hospital sources. These applications are designed based on client–server architecture and different paradigms such as socket, remote procedure call, and remote method invocation (RMI). However, these existing paradigms do not offer a security mechanism for healthcare applications in distributed mobile-fog-cloud networks. This paper devises a blockchain-socket-RMI-based framework for fine-grained healthcare applications in the mobile-fog-cloud network. This study introduces a new open healthcare framework for applied research purposes and has blockchain-socket-RMI abstraction level classes for healthcare applications. The goal is to meet the security and deadline requirements of fine-grained healthcare tasks and minimize execution and data validation costs during processing applications in the system. This study introduces a partial proof of validation (PPoV) scheme that converts the workload into the hash and validates it among mobile, fog, and cloud nodes during offloading, execution, and storing data in the secure form. Simulation discussions illustrate that the proposed blockchain-socket-RMI minimizes the processing and blockchain costs and meets the security and deadline requirements of fine-grained healthcare tasks of applications as compared to existing frameworks in work.
Blockchain: The Block class represents a block in the blockchain, while the Blockchain class manages the chain itself.
Server: The BlockchainServer listens for client connections and handles requests for adding blocks and retrieving the blockchain.
Client: The BlockchainClient sends requests to the server to add new blocks or retrieve the blockchain.
Security and Improvements
Encryption: Consider encrypting data before storing it in the blockchain.
Authentication: Implement authentication mechanisms to secure connections and data.
Error Handling: Add robust error handling for real-world applications.
This example provides a basic framework. For a production-level system, further enhancements, including robust security measures, are necessary.

![sensors-22-05833-g001](https://github.com/user-attachments/assets/de131073-feb4-472b-81b7-79ce1fadd728)

![image](https://github.com/user-attachments/assets/4d4cf7b2-5dca-465c-ad7c-465f297b5733)

![image](https://github.com/user-attachments/assets/fc5f506b-0dfa-4950-90a0-1832a36be792)


![image](https://github.com/user-attachments/assets/54c897a4-841a-45bf-a157-c87cd5a099c8)


import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

class Block {
    public String hash;
    public String previousHash;
    private String data; // Patient data (could be JSON or encrypted)
    private long timeStamp;
    private int nonce;

    public Block(String data, String previousHash) {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = new Date().getTime();
        this.hash = calculateHash();
    }

    public String calculateHash() {
        String input = previousHash + Long.toString(timeStamp) + Integer.toString(nonce) + data;
        return applySha256(input);
    }

    public void mineBlock(int difficulty) {
        String target = new String(new char[difficulty]).replace('\0', '0');
        while (!hash.substring(0, difficulty).equals(target)) {
            nonce++;
            hash = calculateHash();
        }
        System.out.println("Block Mined! : " + hash);
    }

    public static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

class Blockchain {
    public static List<Block> blockchain = new ArrayList<>();
    public static int difficulty = 4;

    public static Boolean isChainValid() {
        Block currentBlock;
        Block previousBlock;
        String hashTarget = new String(new char[difficulty]).replace('\0', '0');

        for (int i = 1; i < blockchain.size(); i++) {
            currentBlock = blockchain.get(i);
            previousBlock = blockchain.get(i - 1);

            if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                System.out.println("Current Hashes not equal");
                return false;
            }
            if (!previousBlock.hash.equals(currentBlock.previousHash)) {
                System.out.println("Previous Hashes not equal");
                return false;
            }
            if (!currentBlock.hash.substring(0, difficulty).equals(hashTarget)) {
                System.out.println("This block hasn't been mined");
                return false;
            }
        }
        return true;
    }

    public static void addBlock(Block newBlock) {
        newBlock.mineBlock(difficulty);
        blockchain.add(newBlock);
    }
}




import java.io.*;
import java.net.Socket;
import java.util.List;

public class BlockchainClient {
    private static final String HOST = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try (Socket socket = new Socket(HOST, PORT);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // Example of adding a new block
            out.writeObject("addBlock");
            out.writeObject("Patient A data...");

            String response = (String) in.readObject();
            System.out.println(response);

            // Example of getting the blockchain
            out.writeObject("getBlockchain");
            @SuppressWarnings("unchecked")
			List<Block> blockchain = (List<Block>) in.readObject();
            for (Block block : blockchain) {
                System.out.println("Block: " + block.hash + ", Previous: " + block.previousHash + ", Data: " + block);
            }
        } catch (IOException | ClassNotFoundException e) {
            //e.printStackTrace();
        }
    }
}




import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class BlockchainServer {
    private static final int PORT = 12345;

    public static void main(String[] args) {
        Blockchain.addBlock(new Block("Genesis Block", "0"));
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is listening on port " + PORT);
            while (true) {
                Socket socket = serverSocket.accept();
                new ClientHandler(socket).start();
            }
        } catch (IOException e) {
            //e.printStackTrace();
        }
    }
}

class ClientHandler extends Thread {
    private Socket socket;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

            String action = (String) in.readObject();
            switch (action) {
                case "addBlock":
                    String data = (String) in.readObject();
                    Block newBlock = new Block(data, Blockchain.blockchain.get(Blockchain.blockchain.size() - 1).hash);
                    Blockchain.addBlock(newBlock);
                    out.writeObject("Block added: " + newBlock.hash);
                    break;
                case "getBlockchain":
                    out.writeObject(Blockchain.blockchain);
                    break;
                default:
                    out.writeObject("Invalid action");
                    break;
            }
        } catch (IOException | ClassNotFoundException e) {
           // e.printStackTrace();
        }
    }
}



