
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.OperatorCreationException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;


/**
* Esta clase implementa el comportamiento de un usuario en una Infraestructura de Certificación
* @author Seg Red Ser
* @version 1.0
*/
public class Usuario {
	
	private RSAKeyParameters clavePrivada = null;
	private RSAKeyParameters clavePublica = null;


	/**
	 * Método que genera las claves del usuario.
	 * @param fichClavePrivada: String con el nombre del fichero donde se guardará la clave privada en formato PEM
	 * @param fichClavePublica: String con el nombre del fichero donde se guardará la clave publica en formato PEM
     * @throws IOException 	
	
	 */
	public void generarClavesUsuario (String fichClavePrivada, String fichClavePublica) throws IOException{
		
		// Esto es nuevo respecto de la P1. Se debe instanciar un objeto de la clase GestionClaves proporcionada
		// Tanto en Usuario como en CA
		GestionClaves gc = new GestionClaves (); 
		
		// Asignar claves a los atributos correspondientes
		AsymmetricCipherKeyPair claves = gc.generarClaves(BigInteger.valueOf(3), 2048);
		clavePublica = (RSAKeyParameters) claves.getPublic();
		clavePrivada = (RSAKeyParameters) claves.getPrivate();
				
		/*Ahora generamos las key con los formatos que se nos pide en la practica  (segun pdf 1ºparte formato ASN1)
		 * y lo guardamos en array de bytes como en la P1*/
		SubjectPublicKeyInfo publicInfo = gc.getClavePublicaSPKI(clavePublica);
		PrivateKeyInfo privateInfo = gc.getClavePrivadaPKCS8(clavePrivada);
		byte [] publicKey = publicInfo.getEncoded();
		byte [] privateKey = privateInfo.getEncoded();
		
		// Escribir las claves en un fichero en formato PEM 
		GestionObjetosPEM.escribirObjetoPEM("PUBLIC KEY",publicKey, fichClavePublica);
		GestionObjetosPEM.escribirObjetoPEM("PRIVATE KEY",privateKey, fichClavePrivada);	
    }

	
	/**
	 * Método que genera una petición de certificado en formato PEM, almacenando esta petición en un fichero.
	 * @param fichPeticion: String con el nombre del fichero donde se guardará la petición de certificado
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public void crearPetCertificado(String fichPeticion) throws OperatorCreationException, IOException {
		// IMPLEMENTAR POR EL ESTUDIANTE
 
	   	// Configurar hash para resumen y algoritmo firma (MIRAR DIAPOSITIVAS PRESENTACIÓN PRÁCTICA)
		// La solicitud se firma con la clave privada del usuario y se escribe en fichPeticion en formato PEM
		


		// IMPLEMENTAR POR EL ESTUDIANTE
		
	}
	
	
	/**
	 * Método que verifica un certificado de una entidad.
	 * @param fichCertificadoCA: String con el nombre del fichero donde se encuentra el certificado de la CA
	 * @param fichCertificadoUsu: String con el nombre del fichero donde se encuentra el certificado de la entidad
     	 * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws FileNotFoundException 	
	 * @return boolean: true si verificación OK, false en caso contrario.
	 */
    public boolean verificarCertificadoExterno(String fichCertificadoCA, String fichCertificadoUsu)throws OperatorCreationException, CertException, FileNotFoundException, IOException {
		return false;

    // IMPLEMENTAR POR EL ESTUDIANTE
	// Comprobar fecha validez del certificado
	// Si la fecha es válida, se comprueba la firma
	// Generar un contenedor para la verificación con la clave pública de CA,
	// el certificado del usuario tiene el resto de información
    	
   	// IMPLEMENTAR POR EL ESTUDIANTE
  		
	}	
}

	// EL ESTUDIANTE PODRÁ CODIFICAR TANTOS MÉTODOS PRIVADOS COMO CONSIDERE INTERESANTE PARA UNA MEJOR ORGANIZACIÓN DEL CÓDIGO