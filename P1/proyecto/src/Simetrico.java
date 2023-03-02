

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
	
        // Leer clave y decodificar de Hex a bin
        String claveLeida;
        byte[] claveBinario;
        try{
            BufferedReader reader = new BufferedReader(new FileReader(ficheroClave));
            claveLeida = reader.readLine();
            claveBinario = Hex.decode(claveLeida);

            // Generar parámetros y cargar clave
            KeyParameter params = new KeyParameter(claveBinario);

            // Crear motor de cifrado
            PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));

            // Iniciar motor de cifrado con params
            cifrador.init(true,params);

            // Ficheros y arrays de Datos
            BufferedInputStream ficheroEntrada = new BufferedInputStream(new FileInputStream(ficheroCifrar));
            BufferedOutputStream ficheroSalida = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));

            byte[] datosLeidos = new byte[cifrador.getBlockSize()];
            byte[] datosCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())]; //Múltiplo del tamaño del bloque

            int leidos;
            int cifrados;

            leidos = ficheroEntrada.read(datosLeidos,0,cifrador.getBlockSize());

            while (leidos > 0) {
                cifrados = cifrador.processBytes(datosLeidos, 0, leidos, datosCifrados, 0);
                ficheroSalida.write(datosCifrados, 0, cifrados);
                leidos = ficheroEntrada.read(datosLeidos, 0, cifrador.getBlockSize());
            }

            cifrados = cifrador.doFinal(datosCifrados,0);
            ficheroSalida.write(datosCifrados,0,cifrados);

            reader.close();
            ficheroEntrada.close();
            ficheroSalida.close();

        } catch (IOException | InvalidCipherTextException e){
            e.printStackTrace();
        }
	}
	
	public void Descifrar(String ficheroClave, String ficheroCifrado, String ficheroDescifrado) {
		
        // Leer clave y decodificar de Hex a bin
        String claveLeida;
        byte[] claveBinario;
        try{
            BufferedReader reader = new BufferedReader(new FileReader(ficheroClave));
            claveLeida = reader.readLine();
            claveBinario = Hex.decode(claveLeida);

            // Generar parámetros y cargar clave
            KeyParameter params = new KeyParameter(claveBinario);

            // Crear motor de cifrado
            PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));

            // Iniciar motor de cifrado con params
            cifrador.init(false, params);

            // Ficheros y arrays de Datos
            BufferedInputStream ficheroEntrada = new BufferedInputStream(new FileInputStream(ficheroCifrado));
            BufferedOutputStream ficheroSalida = new BufferedOutputStream(new FileOutputStream(ficheroDescifrado));

            byte[] datosCifrados = new byte[cifrador.getBlockSize()];
            byte[] datosDesCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())]; //Múltiplo del tamaño del bloque

            int leidos;
            int desCifrados;

            leidos = ficheroEntrada.read(datosCifrados,0,cifrador.getBlockSize());

            while (leidos > 0) {
                desCifrados = cifrador.processBytes(datosCifrados, 0, leidos, datosDesCifrados, 0);
                ficheroSalida.write(datosDesCifrados, 0, desCifrados);
                leidos = ficheroEntrada.read(datosCifrados, 0, cifrador.getBlockSize());
            }

            desCifrados = cifrador.doFinal(datosCifrados,0);
            ficheroSalida.write(datosCifrados,0,desCifrados);

            reader.close();
            ficheroEntrada.close();
            ficheroSalida.close();

        } catch (IOException | InvalidCipherTextException e){
            e.printStackTrace();
        }
		
	}
	
	
}
