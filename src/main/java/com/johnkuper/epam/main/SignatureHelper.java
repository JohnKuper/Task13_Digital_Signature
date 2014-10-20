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
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author Дмитрий Коробейников
 * @version 1.0.0 Creates digital signature and saves it to file.
 */
public class SignatureHelper {

	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Signature signature;
	final static Logger logger = LoggerFactory.getLogger("JohnKuper");

	public SignatureHelper(String signAlg, String provName) {
		try {
			if (signAlg == null) {
				throw new NullPointerException(
						"Digital Signature Algorithm can't be null");
			} else {
				if (provName == null) {
					signature = Signature.getInstance(signAlg);
				} else {
					signature = Signature.getInstance(signAlg, provName);
				}
			}
		} catch (NoSuchProviderException ex) {
			logger.error("NoSuchProviderException: ", ex);
		} catch (NoSuchAlgorithmException ex) {
			logger.error("NoSuchAlgorithmException: ", ex);
		}
	}
	
	public void initKeys(FileInputStream keyStore) {
		
	}

	public KeyPair getKeyPair(FileInputStream in, String alias,
			char[] passKeyStore, char[] passAlias) {
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(in, passKeyStore);
			Key key = ks.getKey(alias, passAlias);
			if (key instanceof PrivateKey) {
				// Get certificate of public key
				Certificate cert = ks.getCertificate(alias);
				PublicKey publicKey = cert.getPublicKey();
				return new KeyPair(publicKey, (PrivateKey) key);
			}
		} catch (KeyStoreException ex) {
			logger.error("KeyStoreException: ", ex);
		} catch (IOException ex) {
			logger.error("IOException: ", ex);
		} catch (CertificateException ex) {
			logger.error("CertificateException: ", ex);
		} catch (NoSuchAlgorithmException ex) {
			logger.error("NoSuchAlgorithmException: ", ex);
		} catch (UnrecoverableEntryException ex) {
			logger.error("UnrecoverableEntryException: ", ex);
		}
		return null;
	}

	public void generateDigitalSignature(FileInputStream srcFile,
			FileOutputStream signatureFile, PrivateKey privateKey) {

		try {

			signature.initSign(privateKey);

			BufferedInputStream bufin = new BufferedInputStream(srcFile);
			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				signature.update(buffer, 0, len);
			}
			;

			bufin.close();

			byte[] realSig = signature.sign();
			signatureFile.write(realSig);
			signatureFile.close();

		} catch (InvalidKeyException ex) {
			logger.error("InvalidKeyException: ", ex);
		} catch (IOException ex) {
			logger.error("IOException: ", ex);
		} catch (SignatureException ex) {
			logger.error("SinatureException: ", ex);
		}

	}

	public boolean isVerify(FileInputStream srcFile,
			FileInputStream signatureFile, PublicKey publicKey) {

		if ((srcFile == null) || (signatureFile == null)) {
			throw new NullPointerException();
		}
		boolean result = false;
		try {
			// Reading source file
			BufferedInputStream bufReadMsg = new BufferedInputStream(srcFile);
			byte[] byteMsg = new byte[bufReadMsg.available()];
			bufReadMsg.read(byteMsg);

			// Reading signature file
			BufferedInputStream bufReadSgn = new BufferedInputStream(
					signatureFile);
			byte[] byteSgn = new byte[bufReadSgn.available()];
			bufReadSgn.read(byteSgn);

			// Verifying message
			signature.initVerify(publicKey);
			signature.update(byteMsg);

			bufReadMsg.close();
			bufReadSgn.close();

			result = signature.verify(byteSgn);

		} catch (InvalidKeyException ex) {
			logger.error("InvalidKeyException: ", ex);
		} catch (FileNotFoundException ex) {
			logger.error("FileNotFoundException: ", ex);
		} catch (IOException ex) {
			logger.error("IOException: ", ex);
		} catch (SignatureException ex) {
			logger.error("SignatureException: ", ex);
		}
		return result;
	}
}
