import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

public class ServerWithoutSecurity {

	public static void main(String[] args) throws IOException {

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(4321);
			System.out.println("Waiting for connection...");
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();
				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					fromClient.read(filename);
					fileOutputStream = new FileOutputStream("recv/"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {
					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.read(block);
					if (numBytes > 0) {
						bufferedFileOutputStream.write(block, 0, numBytes);
					}

				} else if (packetType == 2) {
					System.out.println("Closing connection...");
					if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
					if (bufferedFileOutputStream != null) fileOutputStream.close();
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}
				else if (packetType == 3){
					System.out.println("Sending certificate...");
					FileInputStream fileInputStream = new FileInputStream("server.crt");
					BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);
					byte [] fromFileBuffer = new byte[117];
					// Send the certificate
					for (boolean fileEnded = false; !fileEnded;) {
						int numBytes = bufferedFileInputStream.read(fromFileBuffer);
						fileEnded = numBytes < fromFileBuffer.length;
						toClient.writeInt(numBytes);
						toClient.write(fromFileBuffer,0,numBytes);
						toClient.flush();
					}
					toClient.writeInt(-1);
					bufferedFileInputStream.close();
					fileInputStream.close();
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
