package com.johnkuper.epam.main;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Launcher {

	final static Logger logger = LoggerFactory.getLogger("JohnKuper");
	private static final String KEYSTORE_FILE_PATH = "src/main/resources/task13.jks";
	private static final String SOURCE_FILE_PATH = "src/main/resources/Car.java";
	private static final String SIGNATURE_FILE_PATH = SOURCE_FILE_PATH
			+ ".signature";
	private static final String PUBLIC_KEY_PATH = "src/main/resources/task13.pk";
	private static final String FAKE_FILE_PATH = "src/main/resources/CarFake.java";

	public static void main(String[] args) {
		generateAndTestSignature();
	}

	public static void generateAndTestSignature() {

		SignatureHelper sigHelper = new SignatureHelper("SHA1withDSA", "SUN");
		String keyAlias = "johnkuper";
		char[] storePass = "task13store".toCharArray();
		char[] keyPass = "task13key".toCharArray();
		sigHelper.initKeys(KEYSTORE_FILE_PATH, keyAlias, storePass, keyPass);

		sigHelper.generateDigitalSignature(SOURCE_FILE_PATH);
		sigHelper.savePublicKeyInFile(PUBLIC_KEY_PATH);

		verifyFiles(sigHelper);

	}

	private static void verifyFiles(SignatureHelper sigHelper) {

		String[] paths = { SOURCE_FILE_PATH, FAKE_FILE_PATH };
		int i;
		for (i = 0; i < paths.length; i++) {
			boolean isFileVerify = sigHelper.isFileCorrect(paths[i],
					SIGNATURE_FILE_PATH);
			if (isFileVerify) {
				logger.debug("File {} verification was successful", paths[i]);
			} else {
				logger.debug(
						"File {} verification was failed. This file is fake!",
						paths[i]);
			}
		}
	}
}