import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class Asimetrico {

	public Asimetrico() {}
	
	
	public void generarClaves(String ficheroKPublica, String ficheroKPrivada) {
		
		//1. Parámetros para el método init de generadorClaves:
		RSAKeyGenerationParameters parametros = new RSAKeyGenerationParameters(BigInteger.valueOf(3),new SecureRandom(), 2048, 10); 
		
		//2. Instanciar generador de claves
		RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
		generadorClaves.init(parametros);
		
		//3. Inicializarlo. Generar el par de claves necesario
		AsymmetricCipherKeyPair claves = generadorClaves.generateKeyPair();
		
		
		//4. Escritura de las claves en los ficheros correspondientes
		try {
			PrintWriter ficheroPrivada = new PrintWriter(new FileWriter(ficheroKPrivada));
			PrintWriter ficheroPublica = new PrintWriter(new FileWriter(ficheroKPublica));
			
			RSAKeyParameters privada=(RSAKeyParameters) claves.getPublic();
			RSAKeyParameters publica=(RSAKeyParameters) claves.getPublic();
			
			ficheroPrivada.println(new String (Hex.encode(privada.getModulus().toByteArray())));
			ficheroPrivada.print(new String (Hex.encode(privada.getExponent().toByteArray())));
			
			ficheroPrivada.println(new String (Hex.encode(publica.getModulus().toByteArray())));
			ficheroPrivada.print(new String (Hex.encode(publica.getExponent().toByteArray())));
			
			ficheroPrivada.close();
			ficheroPublica.close();
			
			
			} catch (FileNotFoundException e) {
			e.printStackTrace();
			} catch (IOException e) {
			e.printStackTrace();
			}
		
		
		
	}
	
}
