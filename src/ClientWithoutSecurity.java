import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ClientWithoutSecurity {

	public static void main(String[] args) {

    	String filename = "rr.txt";

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket("localhost", 4321);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			//first authenticate with the server by asking for its certificate

			//packet type of 3 represents a request for the certificate
			System.out.println("Requesting for server's certificate..");
			toServer.writeInt(3);
			int certSize;
			FileOutputStream fileOutputStream = new FileOutputStream("recv/server.crt");
			BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
			while ((numBytes = fromServer.readInt()) != -1){
				byte[] cert = new byte[numBytes];
				fromServer.read(cert);
				bufferedFileOutputStream.write(cert);
			}
			bufferedFileOutputStream.close();

			//open the certificate
			InputStream certStream = new FileInputStream("recv/server.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate serverCert = (X509Certificate) cf.generateCertificate(certStream);
			certStream.close();

			//get CA's public key
			InputStream CAcertStream = new FileInputStream("CA.crt");
			X509Certificate CAcert = (X509Certificate) cf.generateCertificate(CAcertStream);
			PublicKey CAkey = CAcert.getPublicKey();

			//verify server's identity using CA's public key
			serverCert.checkValidity();
			serverCert.verify(CAkey);


			System.out.println("Sending file...");
			// Send the filename
			toServer.writeInt(0);
			toServer.writeInt(filename.getBytes().length);
			toServer.write(filename.getBytes());
			toServer.flush();

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte [] fromFileBuffer = new byte[117];

	        // Send the file
	        for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < fromFileBuffer.length;
				toServer.writeInt(1);
				toServer.writeInt(numBytes);
				toServer.write(fromFileBuffer,0,numBytes);
				toServer.flush();
			}

	        bufferedFileInputStream.close();
	        fileInputStream.close();


			System.out.println("Closing connection...");
			toServer.writeInt(2);
	        toServer.flush();

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
