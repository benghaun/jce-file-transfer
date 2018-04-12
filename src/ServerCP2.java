import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.transform.SourceLocator;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

public class ServerCP2 {

	public static void main(String[] args) throws IOException {

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		PrivateKey privateKey=null;
		SecretKey AESKey=null;
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
					fileOutputStream = new FileOutputStream("C:\\Users\\lowka\\Documents\\GitHub\\jce-file-transfer\\recv\\rr.txt");
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 5) {
					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.read(block);
					if (numBytes > 0) {
						bufferedFileOutputStream.write(block, 0, numBytes);
					}

				// Packet for connection closing
				}
				else if(packetType==1){
					System.out.println("Receiving file****************");
					int numBytes = fromClient.readInt();
					int decrypByte=fromClient.readInt();
					System.out.println("numbyte "+numBytes);
					System.out.println("decryptByte "+decrypByte);
					byte [] block = new byte[numBytes];
					fromClient.read(block);

					System.out.println(Arrays.toString(block));
					System.out.println("length: "+block.length);
					//create cipher object, initialize the ciphers with the given key, choose decryption mode as DES
					Cipher CP2dcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					CP2dcipher.init(Cipher.DECRYPT_MODE, AESKey);

					byte[] CP2decryptedBlock= CP2dcipher.doFinal(block);


					if(numBytes>0){
						bufferedFileOutputStream.write(CP2decryptedBlock, 0, CP2decryptedBlock.length);

					}
				}
				else if(packetType==6){
					//Decrypt encrypedAESkey
					int numBytes = fromClient.readInt();
					System.out.println("Numbytes "+numBytes);
					byte [] block = new byte[numBytes];
					fromClient.read(block);
					System.out.println("EncryptedAESkey "+Arrays.toString(block));

					//cr8 RSA Cipher object to decrypt AES key
					Cipher rsaCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					rsaCipherDecrypt.init(Cipher.DECRYPT_MODE,privateKey);
					byte[] AeskeyByteFormat=rsaCipherDecrypt.doFinal(block);
					AESKey=new SecretKeySpec(AeskeyByteFormat,0,AeskeyByteFormat.length,"AES");
					System.out.println("AES key Decrypted");
				}


				else if (packetType == 2) {
					System.out.println("Closing connection...");
					if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
					if (bufferedFileOutputStream != null) fileOutputStream.close();
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

				// Packet which is requesting for certificate
				else if (packetType == 3){
					System.out.println("Sending certificate...");
					FileInputStream fileInputStream = new FileInputStream("C:\\Users\\lowka\\Documents\\GitHub\\jce-file-transfer\\server.crt");
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

				// Packet sending nonce
				else if (packetType == 4){
					System.out.println("Reading nonce..");
					//first read the nonce
					int numBytes = fromClient.readInt();
					byte[] nonce = new byte[numBytes];
					fromClient.read(nonce);

					//encrypt the nonce using server's private key
					File privateKeyFile = new File("C:\\Users\\lowka\\Documents\\GitHub\\jce-file-transfer\\privateServer.pem");
					FileInputStream fis = new FileInputStream(privateKeyFile);
					DataInputStream dis = new DataInputStream(fis);
					byte[] privateKeyBytes = new byte[(int) privateKeyFile.length()];
					dis.readFully(privateKeyBytes);
					dis.close();
					String privateKeyString = new String(privateKeyBytes);
					String[] parts = privateKeyString.split("-----");
					byte[] privateKeyb64 = DatatypeConverter.parseBase64Binary(parts[parts.length / 2]);
					PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyb64);
					KeyFactory kf = KeyFactory.getInstance("RSA");
					//PrivateKey privateKey = kf.generatePrivate(spec);
					privateKey = kf.generatePrivate(spec);
					Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					rsaCipher.init(Cipher.ENCRYPT_MODE,privateKey);
					byte[] encryptedNonce = rsaCipher.doFinal(nonce);

					//send the encrypted nonce back to client
					toClient.writeInt(encryptedNonce.length);
					toClient.write(encryptedNonce);

				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}







	public static byte[] decryptCP2(byte[] data, Cipher cipher) throws Exception{



		byte[] decryptedBytes=cipher.doFinal(data);
		return decryptedBytes;
	}


}
