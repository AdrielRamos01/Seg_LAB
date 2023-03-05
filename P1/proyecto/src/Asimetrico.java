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
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class Asimetrico {

	public Asimetrico() {}
	
	/**
	  * @brief  Funcion que genera una oareja de claves, una publica y una privada para un cifrado asimetrico
	  * @param  ficheroKPublica es el fichero donde se guardara la clave publica
	  * 		ficheroKPrivada es el fichero donde se guardara la clave privada
	  * @retval None
	  */
	
	public void generarClaves(String ficheroKPublica, String ficheroKPrivada) {
		
		//1. Parámetros para el método init de generadorClaves:
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
			
			RSAKeyParameters privada = (RSAKeyParameters) claves.getPrivate();
			RSAKeyParameters publica = (RSAKeyParameters) claves.getPublic();
			
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
	
	/**
	  * @brief  Funcion que cifra un fichero mediante RSA
	  * @param  tipo indicará si queremos cifrar con la clave publica o con la privada
	  * 		ficheroClave es el fichero donde se guardara la clave. Debe coincidir con el tipo indicado
	  * 		Este control se realiza por el usuario, no por el programa.
	  * 		ficheroClaro es el fichero que se quiere cifrar
	  * 		ficheroCifrado es el fichero cifrado
	  * @retval None
	  */
	
	
	public void cifrar (String tipo, String ficheroClave, String ficheroClaro, String ficheroCifrado) {
		
	
		//1. Leer el modulo y el exponente de la clave
		BufferedReader rd;
		try {
			rd = new BufferedReader(new FileReader(ficheroClave));
			BigInteger modulo = new BigInteger(Hex.decode(rd.readLine()));
			BigInteger exponente = new BigInteger(Hex.decode(rd.readLine()));
			
			//2. Parámetros para el método init de cifrador o descifrador:
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
	
	
	/**
	  * @brief  Funcion que descifra un fichero mediante RSA
	  * @param  tipo indicará si queremos cifrar con la clave publica o con la privada
	  * 		ficheroClave es el fichero donde se guardara la clave. Debe coincidir con el tipo indicado
	  * 		Este control se realiza por el usuario, no por el programa.
	  * 		ficheroCifrado es el fichero que se quiere descifrar
	  * 		ficheroDescifrado es el fichero descifrado
	  * @retval None
	  */
	
	public void descifrar (String tipo, String ficheroClave, String ficheroCifrado, String ficheroDescifrado) {
		
		
		//1. Leer el modulo y el exponente de la clave
		BufferedReader rd;
		try {
			rd = new BufferedReader(new FileReader(ficheroClave));
			BigInteger modulo = new BigInteger(Hex.decode(rd.readLine()));
			BigInteger exponente = new BigInteger(Hex.decode(rd.readLine()));
			
			//2. Parámetros para el método init de cifrador o descifrador:
			//el primer parametro se hace asi ya que la API indica que seria true si ciframos con privada y false con publica
			RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);
			
			//3. Instanciar el cifrador e inicializar
			//recuerda que en el init es true para cifrar y false para descifrar
			AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
			cifrador.init(false, parametros);
			
			//4.Lectura de los bytes
			BufferedInputStream entrada = new  BufferedInputStream(new FileInputStream(ficheroCifrado));
			BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(ficheroDescifrado));
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
	
	/**
	  * @brief  Funcion que descifra un fichero mediante RSA
	  * @param  ficheroClave es el fichero que almacena la clave para la firma. Debe ser la clave privada SIEMPRE.
	  *         Este control se realizará por el usuario y no por el programa.
	  *         ficheroFirmar es el fichero al que queremos aplicarle la firma
	  * 		ficheroConFirma es el fichero de destino donde guardaremos el archivo firmado.
	  * @retval None
	  */
	
	public void firmar (String ficheroClave, String ficheroFirmar, String ficheroConFirma) {
		//1. Instanciar la clase para generar el resumen
		Digest resumen = new SHA3Digest();
		
		//2. Generar el resumen: los bloques de lectura son del mismo tamaño que el resumen
		byte[] datosEntrada = new byte[resumen.getDigestSize()];
		byte[] datosResumen = new byte[resumen.getDigestSize()];
		
		//Bucle de lectura de bloques del fichero:Método update (a partir de cada bloque leído va actualizando el resumen)
		try {
			BufferedInputStream entrada = new  BufferedInputStream(new FileInputStream(ficheroFirmar));
			int leidos = entrada.read(datosEntrada);
			
			
			while(leidos>0) {
			resumen.update(datosEntrada, 0, datosEntrada.length);
			leidos = entrada.read(datosEntrada);
			}
			
			//Método doFinal (fuera del bucle. Genera resumen final)
			resumen.doFinal(datosResumen, 0);
			entrada.close();
			
			//Escribir el resumen en el fichero
			BufferedOutputStream wrResumen = new BufferedOutputStream(new FileOutputStream("Hash.txt"));
			wrResumen.write(datosResumen);
			wrResumen.close();
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
        //3. Cifrar el fichero que contien el resumen
		cifrar("privada", ficheroClave, "Hash.txt", ficheroConFirma);
		
		
		
	}
	
	/**
	  * @brief  Funcion que verifica si la firma de los ficheros se ha realizado correctamente
	  * @param  ficheroClave es el fichero que almacena la clave para la firma. Debe ser la clave privada SIEMPRE.
	  *         Este control se realizará por el usuario y no por el programa.
	  *         ficheroDatos es el fichero en claro del cual queremos comprobar la firma
	  * 		ficheroFirmaCifrado es un fichero firmado el cual hemos generado mediante el metodo firmar
	  * @retval verificado informa de si la firma se ha verificado o no con éxito
	  */
	public boolean verificarFirma (String ficheroClave, String ficheroDatos, String ficheroFirmaCifrado) {
		
		boolean verificado = false;
		
		//********************VOLVEMOS A GENERAR UN HASH DEL TEXTO EN CLARO********************//
		
		//1. Instanciar la clase para generar el resumen
				Digest resumen = new SHA3Digest();
				
				//2. Generar el resumen: los bloques de lectura son del mismo tamaño que el resumen
				byte[] datosEntrada = new byte[resumen.getDigestSize()];
				byte[] datosResumen = new byte[resumen.getDigestSize()];
				
				//Bucle de lectura de bloques del fichero:Método update (a partir de cada bloque leído va actualizando el resumen)
				try {
					BufferedInputStream entrada = new  BufferedInputStream(new FileInputStream(ficheroDatos));
					int leidos = entrada.read(datosEntrada);
					
					
					while(leidos>0) {
					resumen.update(datosEntrada, 0, datosEntrada.length);
					leidos = entrada.read(datosEntrada);
					}
					
					//Método doFinal (fuera del bucle. Genera resumen final)
					resumen.doFinal(datosResumen, 0);
					entrada.close();
					
					//Escribir el resumen en el fichero
					BufferedOutputStream wrResumen = new BufferedOutputStream(new FileOutputStream("HashVerificar.txt"));
					wrResumen.write(datosResumen);
					wrResumen.close();
					
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		//**************FIN GENERACION DE NUEVO HASH DEL TEXTO CLARO*****************//
		
		
		//DESCIFRAMOS EL HASH CIFRADO GENERADO EN FIRMAR
		
	    descifrar("publica", ficheroClave, ficheroFirmaCifrado, "HashDescifrado.txt");
	    
	    //PASAMOS EL HASHDESCIFRADO A UN BYTE[]
	    BufferedInputStream rdDescifrado;
	    try {
			rdDescifrado = new  BufferedInputStream(new FileInputStream("HashDescifrado.txt"));
			byte[] fich = rdDescifrado.readAllBytes();
			
			
			if(Arrays.equals(datosResumen, fich)) {
				verificado = true;
			} else {
				verificado = false;
			}
			
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	     
		
		return verificado;	
	}
	
}
