
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

/**
 *
 * @author Mauricio
 */
public class RSAEncrypter {

    public static void gerarChaves() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4));
        KeyPair par = kpg.generateKeyPair();

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("ChavePublica")));
        oos.writeObject(par.getPublic());
        oos.close();

        oos = new ObjectOutputStream(new FileOutputStream(new File("ChavePrivada")));
        oos.writeObject(par.getPrivate());
        oos.close();
    }
    private byte[] buf = new byte[1024];

    public void criptografar(Key chave, InputStream in, OutputStream out) throws Exception {
        Cipher cifra = Cipher.getInstance("RSA");
        cifra.init(Cipher.ENCRYPT_MODE, chave);
        CipherOutputStream cipherOut = new CipherOutputStream(out, cifra);

        int numLido = 0;
        while ((numLido = in.read(buf)) >= 0) {
            cipherOut.write(buf, 0, numLido);
        }
        cipherOut.close();
    }

    public void descriptografar(Key chave, InputStream in, OutputStream out) throws Exception {
        Cipher cifra = Cipher.getInstance("RSA");
        cifra.init(Cipher.DECRYPT_MODE, chave);
        CipherInputStream cipherIn = new CipherInputStream(in, cifra);

        int numLido = 0;
        while ((numLido = cipherIn.read(buf)) >= 0) {
            out.write(buf, 0, numLido);
        }
        out.close();
    }

    public static Key obterKey(File arquivo, Class<? extends Key> clazz) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(arquivo));
        Key chave = clazz.cast(ois.readObject());
        ois.close();

        return chave;
    }

    public static void main(String[] args) throws Exception {
//        gerarChaves();

//        Key chavePrivada = obterKey(new File("ChavePrivada"), PrivateKey.class);
        Key chavePublica = obterKey(new File("ChavePublica"), PublicKey.class);

        RSAEncrypter rsa = new RSAEncrypter();
        rsa.criptografar(chavePublica, new FileInputStream("sms.txt"), new FileOutputStream("criptografado_resp"));
//        rsa.descriptografar(chavePublica, new FileInputStream("criptografado"), new FileOutputStream("sms.txt"));
    }

}
