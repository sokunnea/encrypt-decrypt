package com.example.encryptDecrypt;

import java.security.*;

public class EncryptionDecryption4Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        System.out.println("Is it possible to verify a SHA256withRSA signature with a SHA256 hash of the original data?");

        // create a rsa keypair of 2048 bit keylength
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        rsaGenerator.initialize(2048, random);
        KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
        PublicKey publicKey = rsaKeyPair.getPublic();
        PrivateKey privateKey = rsaKeyPair.getPrivate();

        String document = "dpb";//The quick brown fox jumps over the lazy dog
        // sign
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(document.getBytes());
        byte[] sig = signature.sign();
//        System.out.println("sig :"+sig);

        // verify sign with document
        System.out.println("verify the signature with document");
        Signature signatureVerify = Signature.getInstance("SHA256withRSA");
        signatureVerify.initVerify(publicKey);
        signatureVerify.update(document.getBytes());
        boolean sigVerified =  signatureVerify.verify(sig);
        System.out.println("Verified: " + sigVerified);
        System.out.println("public key: "+publicKey);
        System.out.println("private key: "+privateKey);

        // verify SHA256 hash of the document
        System.out.println("verify the signature SHA256 of the document");
        byte[] documentHash = MessageDigest.getInstance("SHA-256").digest(document.getBytes());
        String prependSha256String = "3031300D060960864801650304020105000420";
        byte[] prependSha256 = hexStringToByteArray(prependSha256String);
        int combinedLength = prependSha256.length + documentHash.length;
        byte[] documentHashFull = new byte[combinedLength];
        System.arraycopy(prependSha256, 0, documentHashFull, 0, prependSha256.length);
        System.arraycopy(documentHash, 0, documentHashFull, prependSha256.length, documentHash.length);

        // lets verify
        Signature signatureVerifyHash = Signature.getInstance("NonewithRSA");
        signatureVerifyHash.initVerify(publicKey);
        signatureVerifyHash.update(documentHashFull);
        boolean sigVerifiedHash =  signatureVerifyHash.verify(sig);
        System.out.println("VerifiedHash: " + sigVerifiedHash);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
