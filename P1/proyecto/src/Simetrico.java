

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;

import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class Simetrico {

	
	public void generarClave(String nombreFichero) {
		
		//DONDE GUARDAR LA CLAVE GENERADA
		byte [] clave; //guardado de clave binaria
		byte [] claveHex; //guardado de clave hexadecimal
		
		
		//PARTE DE GENERACION DE CLAVE
		
		/*La clase CipherKeyGenerator tiene los metodos generateKey()
		 * e init, los cuales se encargan de la generación de las claves
		 * de cifrado. Primero, creamos el generador*/
		CipherKeyGenerator generator = new CipherKeyGenerator();
		
		/* A continuación, generamos el SecureRandom, el cual nos 
		 * proporciona un numero aleatorio para el cifrado de nuestras claves.
		 * Posteriormente inicializamos el generador con el SecureRandom y el número
		 * de bits del cifrado, que en el caso de nuestra práctica es de 256.
		 * Por último, generamos la clave y la guardamos en el array de byte que hemos definido al principio */
		SecureRandom SR = new SecureRandom();
		generator.init(new KeyGenerationParameters(SR, 256));
		clave = generator.generateKey();
		
		/*Debemos transformar la clave que hemos generado de binario a hexadecimal, ya que
		 * si nos saltamos este paso, al visualizar la clave en el fichero encontraremos carácteres
		 * ilegibles.
		 * Para poder pasarlo, usamos la funcion encode de la clase Hex*/
		claveHex = Hex.encode(clave); 
		
		//PARTE DE GUARDADO DE CLAVE EN FICHERO	
		FileOutputStream salida= null;
			try {
				salida=new FileOutputStream(nombreFichero);
				salida.write(claveHex);
			} catch (FileNotFoundException e){
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			finally {
				if (salida!=null)
					try {
						salida.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
			}
	}
	
	
	public void Cifrar(String ficheroClave, String ficheroCifrar, String ficheroCifrado) {
	
	    String claveHexa;     // en string para poder leer del fichero
		byte[] clave = null;  //necesario inicializarla, si no da error a la hora de usar el KeyParameter
		

		
		try {
			
			//CREACION DE LAS LECTURAS Y ESCRITURAS DE LOS FICHEROS
			BufferedReader br = new BufferedReader (new FileReader(ficheroClave));
			BufferedInputStream leerCifrar = new BufferedInputStream(new FileInputStream(ficheroCifrar));
			BufferedOutputStream escribirCifrado = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));
			
			
			
			
			
			PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
			
			
			try {
				claveHexa = br.readLine();
				clave = Hex.decode(claveHexa);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			cifrador.init(true, new KeyParameter(clave));
			
			
			byte[] datosCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
			byte[] datosLeidos = new byte[cifrador.getBlockSize()];
			
			int leidos = 0;
			int cifrados = 0;
			
			try {
				leidos = leerCifrar.read(datosLeidos, 0, cifrador.getBlockSize());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			while(leidos > 0) {
				cifrados = cifrador.processBytes(datosLeidos, 0, leidos, datosCifrados, 0);
				try {
					leidos = leerCifrar.read(datosLeidos, 0, cifrador.getBlockSize());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
				try {
					escribirCifrado.write(datosCifrados, 0, cifrados);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			
			try {
				cifrados = cifrador.doFinal(datosCifrados, 0);
				try {
					escribirCifrado.write(datosCifrados, 0, cifrados);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} catch (DataLengthException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidCipherTextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			try {
				br.close();
				leerCifrar.close();
				escribirCifrado.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void Descifrar(String ficheroClave, String ficheroCifrado, String ficheroDescifrado) {
		
	    String claveHexa;     // en string para poder leer del fichero
		byte[] clave = null;  //necesario inicializarla, si no da error a la hora de usar el KeyParameter
		

		
		try {
			
			//CREACION DE LAS LECTURAS Y ESCRITURAS DE LOS FICHEROS
			BufferedReader br = new BufferedReader (new FileReader(ficheroClave));
			BufferedInputStream leerCifrado = new BufferedInputStream(new FileInputStream(ficheroCifrado));
			BufferedOutputStream escribirDescifrado = new BufferedOutputStream(new FileOutputStream(ficheroDescifrado));
		
			
			
			PaddedBufferedBlockCipher descifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
			

			
			try {
				claveHexa = br.readLine();
				clave = Hex.decode(claveHexa);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			descifrador.init(false, new KeyParameter(clave));
			
			byte[] datosDescifrados = new byte[descifrador.getOutputSize(descifrador.getBlockSize())];
			byte[] datosLeidos = new byte[descifrador.getBlockSize()];
			
			int descifrados = 0;
			int leidos = 0;
			

			try {
				leidos = leerCifrado.read(datosLeidos, 0, descifrador.getBlockSize());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			while(leidos > 0) {
				descifrados = descifrador.processBytes(datosLeidos, 0, leidos, datosDescifrados, 0);
				try {
					leidos = leerCifrado.read(datosLeidos, 0, descifrador.getBlockSize());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
				try {
					escribirDescifrado.write(datosDescifrados, 0, descifrados);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			
			try {
				descifrados = descifrador.doFinal(datosDescifrados, 0);
				try {
					escribirDescifrado.write(datosDescifrados, 0, descifrados);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} catch (DataLengthException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidCipherTextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			try {
				br.close();
				leerCifrado.close();
				escribirDescifrado.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	
}
