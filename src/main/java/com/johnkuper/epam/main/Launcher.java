package com.johnkuper.epam.main;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Launcher {

	final static Logger logger = LoggerFactory.getLogger("JohnKuper");
	private static Signature signature;
	private static PrivateKey priv;
	private static PublicKey pub;

	public static void main(String[] args) {

		generateSignatureAndPublicKey();
		verifySignature();

	}

	public static KeyPair getPair(FileInputStream in, String alias,
			char[] passKeyStore, char[] passAlias) throws KeyStoreException,
			IOException, CertificateException, NoSuchAlgorithmException,
			UnrecoverableEntryException {
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(in, passKeyStore);
		Key key = ks.getKey(alias, passAlias);
		if (key instanceof PrivateKey) {
			// Get certificate of public key
			Certificate cert = ks.getCertificate(alias);
			PublicKey publicKey = cert.getPublicKey();
			return new KeyPair(publicKey, (PrivateKey) key);
		}
		return null;
	}

	public static boolean verifyMessage(FileInputStream msg, FileInputStream sgn)
			throws InvalidKeyException, FileNotFoundException, IOException,
			SignatureException {

		if ((msg == null) || (sgn == null)) {
			throw new NullPointerException();
		}

		// Reading open text
		BufferedInputStream bufReadMsg = new BufferedInputStream(msg);
		byte[] byteMsg = new byte[bufReadMsg.available()];
		bufReadMsg.read(byteMsg);

		// Reading signature file
		BufferedInputStream bufReadSgn = new BufferedInputStream(sgn);
		byte[] byteSgn = new byte[bufReadSgn.available()];
		bufReadSgn.read(byteSgn);

		// Verifying message
		signature.initVerify(pub);
		signature.update(byteMsg);

		// Closing all open files
		bufReadMsg.close();
		bufReadSgn.close();

		boolean result = signature.verify(byteSgn);
		return result;
	}

	public static void generateSignatureAndPublicKey() {
		try {
			FileInputStream fis = new FileInputStream(
					"src/main/resources/task13.jks");
			char[] storePass = "task13store".toCharArray();
			char[] keyPass = "task13key".toCharArray();
			KeyPair keyPair = getPair(fis, "johnkuper", storePass, keyPass);
			priv = keyPair.getPrivate();
			pub = keyPair.getPublic();

			signature = Signature.getInstance("SHA1withDSA", "SUN");
			signature.initSign(priv);

			FileInputStream teststream = new FileInputStream(
					"src/main/resources/signatureTest.txt");
			BufferedInputStream bufin = new BufferedInputStream(teststream);
			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				signature.update(buffer, 0, len);
			}
			;

			bufin.close();

			/*
			 * Now that all the data to be signed has been read in, generate a
			 * signature for it
			 */

			byte[] realSig = signature.sign();

			/* Save the signature in a file */
			FileOutputStream sigfos = new FileOutputStream(
					"src/main/resources/signature");
			sigfos.write(realSig);

			sigfos.close();

			/* Save the public key in a file */
			byte[] key = pub.getEncoded();
			FileOutputStream keyfos = new FileOutputStream(
					"src/main/resources/publickey");
			keyfos.write(key);

			keyfos.close();

		} catch (Exception e) {
			logger.error("Exception: ", e);
		}
	}

	public static void verifySignature() {

		try {
			FileInputStream fileStream = new FileInputStream(
					"src/main/resources/signatureFake.txt");
			FileInputStream sigStream = new FileInputStream(
					"src/main/resources/signature");
			boolean verify = verifyMessage(fileStream, sigStream);
			if (verify) {
				logger.debug("Verifying is successfull");
			} else {
				logger.debug("Verifying is failed. This file is fake!");
			}
		} catch (Exception e) {
			logger.error("Exception during verify: ", e);
		}
	}

}
