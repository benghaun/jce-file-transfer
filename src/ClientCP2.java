import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

public class ClientCP2 {

	public static void main(String[] args) {
        String filename = "kwtest.txt";
//        String filename = "rr.txt";
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
			FileOutputStream fileOutputStream = new FileOutputStream("recv\\server.crt");
			BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
			while ((numBytes = fromServer.readInt()) != -1){
				byte[] cert = new byte[numBytes];
				fromServer.read(cert);
				bufferedFileOutputStream.write(cert);
			}
			bufferedFileOutputStream.close();

			//open the certificate
			InputStream certStream = new FileInputStream("recv\\server.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate serverCert = (X509Certificate) cf.generateCertificate(certStream);
			certStream.close();

			//get CA's public key
			InputStream CAcertStream = new FileInputStream("CA.crt");
			X509Certificate CAcert = (X509Certificate) cf.generateCertificate(CAcertStream);
			PublicKey CAkey = CAcert.getPublicKey();
			PublicKey kwserverKey = serverCert.getPublicKey();

			//verify server's identity using CA's public key
			serverCert.checkValidity();
			serverCert.verify(CAkey);
			String[] certInfo = serverCert.getSubjectX500Principal().getName().split(",");

			//handle case where certificates belonging to other people are sent instead of the server's cert
			if (!certInfo[1].equals("CN=Beng Haun")){
				System.out.println("Incorrect certificate, closing connection now");
				toServer.writeInt(2);
				return;
			}

			System.out.println("Certificate verified");

			System.out.println("Sending nonce..");
			//generate a nonce based on the current date and time
			String dateTimeString = Long.toString(new Date().getTime());
			byte[] nonceByte = dateTimeString.getBytes();

			//send the nonce to the server as a challenge
			toServer.writeInt(4);
			toServer.writeInt(nonceByte.length);
			toServer.write(nonceByte);

			//wait for the response, which will be the same nonce encrypted using the server's private key
			numBytes = fromServer.readInt();
			byte[] encryptedNonce = new byte[numBytes];
			fromServer.read(encryptedNonce);

			//decrypt the nonce using the server's public key obtained from the certificate and verify that it matches the original nonce
			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.DECRYPT_MODE,serverCert.getPublicKey());
			byte[] decryptedNonce = rsaCipher.doFinal(encryptedNonce);
			String decryptedNonceString = new String(decryptedNonce);

			if (!decryptedNonceString.equals(dateTimeString)){
				System.out.println("Incorrect nonce, closing connection now");
				toServer.writeInt(2);
				return;
			}

			System.out.println("Nonce verified");




			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte [] fromFileBuffer = new byte[117];

		//***********************Encrypt & send AES key ************************************************************
	        //Initiate Ciphher object for key encryption, using encrypt mode and server's public key
			Cipher rsaCipherEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE,kwserverKey);
			System.out.println("Generating AES key...");
			//Generate AES key
			KeyGenerator AESkeyGenerator = KeyGenerator.getInstance("AES");
			AESkeyGenerator.init(128);
			SecretKey AESkey=AESkeyGenerator.generateKey();

			//Convery AES to byte[]
			byte[] AESKeybyteformat=AESkey.getEncoded();
			byte[] encryptedAESKeybyteformat=rsaCipherEncrypt.doFinal(AESKeybyteformat);


			//send encrypted AES key
			System.out.println("Sending AES key...");
			toServer.writeInt(6);
			toServer.writeInt(encryptedAESKeybyteformat.length);
			//toServer.write(encryptedAESKeybyteformat);
			toServer.write(encryptedAESKeybyteformat,0,encryptedAESKeybyteformat.length);
			toServer.flush();


			//***********************Encrypt & Send File************************************************************


			//Send filename
			System.out.println("Sending filename...");
			//Encrypt Filename
			Cipher Filecipher=Cipher.getInstance("AES/ECB/PKCS5Padding");
			Filecipher.init(Cipher.ENCRYPT_MODE,AESkey);
			byte[] encryptedFilename=Filecipher.doFinal(filename.getBytes());
			// Send the filename
			toServer.writeInt(0);
			toServer.writeInt(encryptedFilename.length);
			//toServer.write(filename.getBytes());
			toServer.write(encryptedFilename,0,encryptedFilename.length);
			toServer.flush();


			System.out.println("Sending file...");
			for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer); //read 117 bytes
				fileEnded = numBytes < fromFileBuffer.length;  //************************************************************
				if(numBytes<117 && numBytes>0){
					byte[] temp =new byte[numBytes];
					System.arraycopy(fromFileBuffer,0,temp,0,numBytes);
					fromFileBuffer = temp;
				}

				//Encrypt file using AES key
				Cipher CP2cipher=Cipher.getInstance("AES/ECB/PKCS5Padding");
				CP2cipher.init(Cipher.ENCRYPT_MODE,AESkey);
				byte[] encryptedCP2File=CP2cipher.doFinal(fromFileBuffer);

				//Send encrypted file
				toServer.writeInt(1);
				toServer.writeInt(encryptedCP2File.length);
				toServer.writeInt(numBytes);
				toServer.write(encryptedCP2File,0,encryptedCP2File.length);
				//toServer.write(encryptedCP1File);    -> BUG**********************
				toServer.flush();
			}

			System.out.println("File Sent, End of CP1");
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
