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
 * @author Владимир Кирьяков
 * @version 1.0.0 Класс <code>SigningMessage</code> cоздает ЭЦП.
 */
public class MessageSignature implements Serializable {
	static final long serialVersionUID = 356346345363456L;
	private PrivateKey privateKey; // Приватный ключ
	private PublicKey publicKey; // Открытый ключ
	private Signature signature; // Цифровая подпсь
	private byte[] realSign;

	/**
	 * Конструктор класса <code>SigningMessage</code> используеться тогда, когда
	 * имеется пара ключей, и они находится в сертификате, и в хранилище ключей
	 * 
	 * @param signAlg
	 *            - алгоритм ключевой подписи. Пример - SHA1withDSA, DSA, RSA и
	 *            пр.
	 * @param provName
	 *            - название крипто провайдера. Пример - SUN и пр (Если нет
	 *            необходимости в явном указании крипто провайдера, можно
	 *            указать null)
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
	 * Метод <code>signingMessage</code> создает цифровую подпись из указаного
	 * открытого текста
	 * 
	 * @param msgPath
	 *            - Поток ввода с открытым текстом
	 * @param sgnPath
	 *            - Поток вывода с созданой цифровой подпсиью
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
	 * Метод <code>verifyMessage</code> проверяет действительность цифровой
	 * подписи
	 * 
	 * @param msg
	 *            - Поток ввода с открытым текстом
	 * @param sgn
	 *            - Поток ввода с цифровой подписью
	 * @return - Возвращяет результат проверки цифровой подписи
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
	 * Метод <code>getSign</code> возвращает цифровую подпись как массив байтов
	 * 
	 * @return Цифровую подпись
	 */
	public byte[] getSign() {
		return realSign;
	}

	/**
	 * Метод <code>savePrivateKey</code> сохраняет приватный ключ
	 * 
	 * @param file
	 *            - поток вывода
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
	 * Метод <code>savePublicKey</code> сохраняет открытый ключ
	 * 
	 * @param file
	 *            - поток вывода
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
	 * Метод <code>readPrivateKey</code> считывает файл из указанного потока
	 * 
	 * @param fRead
	 *            - потока ввода
	 * @return Возвращает приватный ключ из заданого потока ввода
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
	 * Метод <code>readPublicKey</code> считывает открытый ключ из указанного
	 * потока ввода
	 * 
	 * @param fRead
	 *            - поток ввода
	 * @return Открытый ключ
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
	 * Метод <code>getPair</code> возвращает пару ключей из хранилища ключей и
	 * сертификата открытого ключа
	 * 
	 * @param in
	 *            - поток ввода, где находится хранилише .jks
	 * @param alias
	 *            - название сертиффиката открытого ключа
	 * @param passKeyStore
	 *            - пароль для хранилища ключей
	 * @param passAlias
	 *            - пароль для сертификата
	 * @return Метод возвращает пару ключей
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
	 * Метод <code>setPrivateKey</code> устанавливает приватный ключ
	 * пользователя
	 * 
	 * @param prk
	 *            - приватный пользователя
	 */
	public void setPrivateKey(PrivateKey prk) {

		privateKey = prk;
	}

	/**
	 * Метод <code>getPrivateKey</code> возвращает приватный ключ пользователя
	 * 
	 * @return Приватный ключ
	 */
	public PrivateKey getPrivateKey() {

		return privateKey;
	}

	/**
	 * Метод <code>setPublicKey</code> устанавливает открытый ключ пользователя
	 * 
	 * @param pbk
	 *            - Открытый ключ
	 */
	public void setPublicKey(PublicKey pbk) {

		publicKey = pbk;
	}

	/**
	 * Метод <code>getPublicKey</code> возвращает открытый ключ пользователя
	 * 
	 * @return Открытый ключ
	 */
	public PublicKey getPublicKey() {

		return publicKey;
	}
}
