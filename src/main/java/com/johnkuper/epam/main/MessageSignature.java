package com.johnkuper.epam.main;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
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

/**
 * 
 * @author �������� ��������
 * @version 1.0.0 ����� <code>SigningMessage</code> c������ ���.
 */
public class MessageSignature implements Serializable {
	static final long serialVersionUID = 356346345363456L;
	private PrivateKey privateKey; // ��������� ����
	private PublicKey publicKey; // �������� ����
	private Signature signature; // �������� ������
	private byte[] realSign;

	/**
	 * ����������� ������ <code>SigningMessage</code> ������������� �����, �����
	 * ������� ���� ������, � ��� ��������� � �����������, � � ��������� ������
	 * 
	 * @param signAlg
	 *            - �������� �������� �������. ������ - SHA1withDSA, DSA, RSA �
	 *            ��.
	 * @param provName
	 *            - �������� ������ ����������. ������ - SUN � �� (���� ���
	 *            ������������� � ����� �������� ������ ����������, �����
	 *            ������� null)
	 * @throws NullPointerException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public MessageSignature(String signAlg, String provName)
			throws NullPointerException, NoSuchAlgorithmException,
			NoSuchProviderException {

		if (signAlg == null) {
			throw new NullPointerException();
		} else {
			if (provName == null) {
				signature = Signature.getInstance(signAlg);
			} else {
				signature = Signature.getInstance(signAlg, provName);
			}
		}
	}

	/**
	 * ����� <code>signingMessage</code> ������� �������� ������� �� ���������
	 * ��������� ������
	 * 
	 * @param msgPath
	 *            - ����� ����� � �������� �������
	 * @param sgnPath
	 *            - ����� ������ � �������� �������� ��������
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public void signingMessage(FileInputStream msgPath, FileOutputStream sgnPath)
			throws IOException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException {
		if ((msgPath == null) || (sgnPath == null)) {
			throw new NullPointerException();
		}

		// Set private key
		if (privateKey == null) {
			throw new IllegalArgumentException();
		}
		signature.initSign(privateKey);

		// Reading open text and signing message
		BufferedInputStream bufRead = new BufferedInputStream(msgPath);
		byte[] byteMsg = new byte[bufRead.available()];
		bufRead.read(byteMsg);
		signature.update(byteMsg);

		bufRead.close();

		realSign = signature.sign();
		sgnPath.write(realSign);

	}

	/**
	 * ����� <code>verifyMessage</code> ��������� ���������������� ��������
	 * �������
	 * 
	 * @param msg
	 *            - ����� ����� � �������� �������
	 * @param sgn
	 *            - ����� ����� � �������� ��������
	 * @return - ���������� ��������� �������� �������� �������
	 * @throws InvalidKeyException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws SignatureException
	 */
	public boolean verifyMessage(FileInputStream msg, FileInputStream sgn)
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
		signature.initVerify(publicKey);
		signature.update(byteMsg);

		// Closing all open files
		bufReadMsg.close();
		bufReadSgn.close();

		boolean result = signature.verify(byteSgn);
		return result;
	}

	/**
	 * ����� <code>getSign</code> ���������� �������� ������� ��� ������ ������
	 * 
	 * @return �������� �������
	 */
	public byte[] getSign() {
		return realSign;
	}

	/**
	 * ����� <code>savePrivateKey</code> ��������� ��������� ����
	 * 
	 * @param file
	 *            - ����� ������
	 * @throws IOException
	 */
	public void savePrivateKey(FileOutputStream file) throws IOException {

		if (file == null && privateKey == null) {
			return;
		} else {
			ObjectOutputStream objStrm = new ObjectOutputStream(file);
			objStrm.writeObject(privateKey);
			objStrm.close();
		}
	}

	/**
	 * ����� <code>savePublicKey</code> ��������� �������� ����
	 * 
	 * @param file
	 *            - ����� ������
	 * @throws IOException
	 */
	public void savePublicKey(FileOutputStream file) throws IOException {

		if (file == null && publicKey == null) {
			return;
		} else {
			ObjectOutputStream objStrm = new ObjectOutputStream(file);
			objStrm.writeObject(publicKey);
			objStrm.close();
		}
	}

	/**
	 * ����� <code>readPrivateKey</code> ��������� ���� �� ���������� ������
	 * 
	 * @param fRead
	 *            - ������ �����
	 * @return ���������� ��������� ���� �� �������� ������ �����
	 * @throws NullPointerException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws ClassCastException
	 */
	public PrivateKey readPrivateKey(FileInputStream fRead)
			throws NullPointerException, IOException, ClassNotFoundException,
			ClassCastException {
		if (fRead == null) {
			throw new NullPointerException();
		} else {
			ObjectInputStream obRead = new ObjectInputStream(fRead);
			Object ob = obRead.readObject();
			if (ob instanceof PrivateKey) {
				PrivateKey privKey = (PrivateKey) ob;
				return privKey;
			} else {
				throw new ClassCastException();
			}
		}
	}

	/**
	 * ����� <code>readPublicKey</code> ��������� �������� ���� �� ����������
	 * ������ �����
	 * 
	 * @param fRead
	 *            - ����� �����
	 * @return �������� ����
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws ClassCastException
	 */
	public PublicKey readPublicKey(FileInputStream fRead) throws IOException,
			ClassNotFoundException, ClassCastException {

		if (fRead == null) {
			throw new NullPointerException();
		} else {
			ObjectInputStream obRead = new ObjectInputStream(fRead);
			Object ob = obRead.readObject();
			if (ob instanceof PublicKey) {
				PublicKey privKey = (PublicKey) ob;
				return privKey;
			} else {
				throw new ClassCastException();
			}
		}
	}

	/**
	 * ����� <code>getPair</code> ���������� ���� ������ �� ��������� ������ �
	 * ����������� ��������� �����
	 * 
	 * @param in
	 *            - ����� �����, ��� ��������� ��������� .jks
	 * @param alias
	 *            - �������� ������������ ��������� �����
	 * @param passKeyStore
	 *            - ������ ��� ��������� ������
	 * @param passAlias
	 *            - ������ ��� �����������
	 * @return ����� ���������� ���� ������
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 */
	public KeyPair getPair(FileInputStream in, String alias,
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

	/**
	 * ����� <code>setPrivateKey</code> ������������� ��������� ����
	 * ������������
	 * 
	 * @param prk
	 *            - ��������� ������������
	 */
	public void setPrivateKey(PrivateKey prk) {

		privateKey = prk;
	}

	/**
	 * ����� <code>getPrivateKey</code> ���������� ��������� ���� ������������
	 * 
	 * @return ��������� ����
	 */
	public PrivateKey getPrivateKey() {

		return privateKey;
	}

	/**
	 * ����� <code>setPublicKey</code> ������������� �������� ���� ������������
	 * 
	 * @param pbk
	 *            - �������� ����
	 */
	public void setPublicKey(PublicKey pbk) {

		publicKey = pbk;
	}

	/**
	 * ����� <code>getPublicKey</code> ���������� �������� ���� ������������
	 * 
	 * @return �������� ����
	 */
	public PublicKey getPublicKey() {

		return publicKey;
	}
}
