package com.johnkuper.epam.main;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
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
 * @version 1.1 Creates digital signature and saves it to file.
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

	public void initKeys(String storePath, String alias, char[] passKeyStore,
			char[] passAlias) {
		FileInputStream in = null;
		try {
			in = new FileInputStream(storePath);
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(in, passKeyStore);
			Key key = ks.getKey(alias, passAlias);
			if (key instanceof PrivateKey) {
				Certificate cert = ks.getCertificate(alias);
				this.privateKey = (PrivateKey) key;
				this.publicKey = cert.getPublicKey();
				in.close();
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
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException ex) {
					logger.error(
							"IOException during 'initKeys' while closing FileInputStream: ",
							ex);
				}
			}
		}
	}

	public void generateDigitalSignature(String srcFilePath,
			String signatureFilePath) {

		FileInputStream srcFile = null;
		FileOutputStream signatureFile = null;
		BufferedInputStream bufin = null;
		try {
			srcFile = new FileInputStream(srcFilePath);
			signatureFile = new FileOutputStream(signatureFilePath);
			signature.initSign(privateKey);

			bufin = new BufferedInputStream(srcFile);
			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				signature.update(buffer, 0, len);
			}
			;

			bufin.close();
			srcFile.close();

			byte[] realSig = signature.sign();
			signatureFile.write(realSig);
			signatureFile.close();

		} catch (InvalidKeyException ex) {
			logger.error("InvalidKeyException: ", ex);
		} catch (IOException ex) {
			logger.error("IOException: ", ex);
		} catch (SignatureException ex) {
			logger.error("SinatureException: ", ex);
		} finally {
			try {
				if (srcFile != null) {
					srcFile.close();
				}
				if (signatureFile != null) {
					signatureFile.close();
				}
				if (bufin != null) {
					bufin.close();
				}
			} catch (IOException ex) {
				logger.error(
						"IOException during 'generateDigitalSignature' while closing streams: ",
						ex);
			}
		}

	}

	public boolean isVerify(String srcFilePath, String signatureFilePath) {

		boolean result = false;
		FileInputStream srcFile = null;
		FileInputStream signatureFile = null;
		BufferedInputStream bufReadMsg = null;
		BufferedInputStream bufReadSgn = null;

		try {
			srcFile = new FileInputStream(srcFilePath);
			signatureFile = new FileInputStream(signatureFilePath);
			// Reading source file
			bufReadMsg = new BufferedInputStream(srcFile);
			byte[] byteMsg = new byte[bufReadMsg.available()];
			bufReadMsg.read(byteMsg);

			// Reading signature file
			bufReadSgn = new BufferedInputStream(signatureFile);
			byte[] byteSgn = new byte[bufReadSgn.available()];
			bufReadSgn.read(byteSgn);

			// Verifying the file
			signature.initVerify(publicKey);
			signature.update(byteMsg);

			bufReadMsg.close();
			bufReadSgn.close();
			srcFile.close();
			signatureFile.close();

			result = signature.verify(byteSgn);

		} catch (InvalidKeyException ex) {
			logger.error("InvalidKeyException: ", ex);
		} catch (FileNotFoundException ex) {
			logger.error("FileNotFoundException: ", ex);
		} catch (IOException ex) {
			logger.error("IOException: ", ex);
		} catch (SignatureException ex) {
			logger.error("SignatureException: ", ex);
		} finally {
			try {
				if (bufReadMsg != null) {
					bufReadMsg.close();
				}
				if (bufReadSgn != null) {
					bufReadSgn.close();
				}
				if (srcFile != null) {
					srcFile.close();
				}
				if (signatureFile != null) {
					signatureFile.close();
				}

			} catch (IOException ex) {
				logger.error(
						"IOException during 'isVerify' while closing streams: ",
						ex);
			}
		}
		return result;
	}
}
