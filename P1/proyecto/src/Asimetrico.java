import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

public class Asimetrico {

	public Asimetrico() {}
	
	
	public void generarClaves(String ficheroKPublica, String ficheroKPrivada) {
		
		//1. Par�metros para el m�todo init de generadorClaves:
		RSAKeyGenerationParameters parametros = new RSAKeyGenerationParameters(BigInteger.valueOf(3),new SecureRandom(), 2048, 10); 
		
		//2. Instanciar generador de claves
		RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
		generadorClaves.init(parametros);
		
		
	}
	
}
