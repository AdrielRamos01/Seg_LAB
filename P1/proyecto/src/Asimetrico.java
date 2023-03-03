import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class Asimetrico {

	public Asimetrico() {}
	
	
	public void generarClaves(String ficheroKPublica, String ficheroKPrivada) {
		
		//1. Par�metros para el m�todo init de generadorClaves:
		RSAKeyGenerationParameters parametros = new RSAKeyGenerationParameters(BigInteger.valueOf(3),new SecureRandom(), 2048, 10); 
		
		//2. Instanciar generador de claves
		RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
		generadorClaves.init(parametros);
		
		//3. Inicializarlo. Generar el par de claves necesario
		AsymmetricCipherKeyPair claves = generadorClaves.generateKeyPair();
		
		//sacamos por individual el publico y el priovado para guardarlo en formato PEM
		AsymmetricKeyParameter publicaPEM = claves.getPublic();
		AsymmetricKeyParameter privadaPEM = claves.getPrivate();
		
		//Guardamos en formato PEM
		GuardarFormatoPEM PEM = new GuardarFormatoPEM();
		PEM.guardarClavesPEM(publicaPEM, privadaPEM);
		
		
		//4. Escritura de las claves en los ficheros correspondientes
		try {
			PrintWriter ficheroPrivada = new PrintWriter(new FileWriter(ficheroKPrivada));
			PrintWriter ficheroPublica = new PrintWriter(new FileWriter(ficheroKPublica));
			
			RSAKeyParameters privada = (RSAKeyParameters) claves.getPublic();
			RSAKeyParameters publica = (RSAKeyParameters) claves.getPrivate();
			
			ficheroPrivada.println(new String (Hex.encode(privada.getModulus().toByteArray())));
			ficheroPrivada.print(new String (Hex.encode(privada.getExponent().toByteArray())));
			
			ficheroPublica.println(new String (Hex.encode(publica.getModulus().toByteArray())));
			ficheroPublica.print(new String (Hex.encode(publica.getExponent().toByteArray())));
			
			ficheroPrivada.close();
			ficheroPublica.close();
			
			
			} catch (FileNotFoundException e) {
			e.printStackTrace();
			} catch (IOException e) {
			e.printStackTrace();
			}
		
		
		
	}
	
	
	public void Cifrar (String tipo, String ficheroClave, String ficheroClaro, String ficheroCifrado) {
		
	
		//1. Leer el modulo y el exponente de la clave
		BufferedReader rd;
		try {
			rd = new BufferedReader(new FileReader(ficheroClave));
			BigInteger modulo = new BigInteger(Hex.decode(rd.readLine()));
			BigInteger exponente = new BigInteger(Hex.decode(rd.readLine()));
			
			//2. Par�metros para el m�todo init de cifrador o descifrador:
			//el primer parametro se hace asi ya que la API indica que seria true si ciframos con privada y false con publica
			RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);
			
			//3. Instanciar el cifrador e inicializar
			//recuerda que en el init es true para cifrar y false para descifrar
			AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
			cifrador.init(true, parametros);
			
			//4.Lectura de los bytes
			BufferedInputStream entrada = new  BufferedInputStream(new FileInputStream(ficheroClaro));
			BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));
			byte[] datosClaros = new byte[cifrador.getInputBlockSize()];
			byte[] datosCifrados = new byte[cifrador.getOutputBlockSize()];
			
			int leidos = entrada.read(datosClaros, 0, cifrador.getInputBlockSize());
			
			while(leidos>0) {
				datosCifrados = cifrador.processBlock(datosClaros, 0, leidos);
				salida.write(datosCifrados, 0 ,datosCifrados.length);
				leidos = entrada.read(datosClaros, 0, cifrador.getInputBlockSize());
			}
			
			
			entrada.close();
			salida.close();
			rd.close();
			
			
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	
	public void descifrar (String tipo, String ficheroClave, String ficheroClaro, String ficheroCifrado) {
		
		
		//1. Leer el modulo y el exponente de la clave
		BufferedReader rd;
		try {
			rd = new BufferedReader(new FileReader(ficheroClave));
			BigInteger modulo = new BigInteger(Hex.decode(rd.readLine()));
			BigInteger exponente = new BigInteger(Hex.decode(rd.readLine()));
			
			//2. Par�metros para el m�todo init de cifrador o descifrador:
			//el primer parametro se hace asi ya que la API indica que seria true si ciframos con privada y false con publica
			RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);
			
			//3. Instanciar el cifrador e inicializar
			//recuerda que en el init es true para cifrar y false para descifrar
			AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
			cifrador.init(false, parametros);
			
			//4.Lectura de los bytes
			BufferedInputStream entrada = new  BufferedInputStream(new FileInputStream(ficheroClaro));
			BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));
			byte[] datosClaros = new byte[cifrador.getInputBlockSize()];
			byte[] datosCifrados = new byte[cifrador.getOutputBlockSize()];
			
			int leidos = entrada.read(datosClaros, 0, cifrador.getInputBlockSize());
			
			while(leidos>0) {
				datosCifrados = cifrador.processBlock(datosClaros, 0, leidos);
				salida.write(datosCifrados, 0 ,datosCifrados.length);
				leidos = entrada.read(datosClaros, 0, cifrador.getInputBlockSize());
			}
			
			
			entrada.close();
			salida.close();
			rd.close();
			
			
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
}
