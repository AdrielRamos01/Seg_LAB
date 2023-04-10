
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import java.util.Date;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;


/**
* Esta clase implementa el comportamiento de una CA
* @author Seg Red Ser
* @version 1.0
*/
public class CA {
	
	private final X500Name nombreEmisor;
	private BigInteger numSerie;
	private final int añosValidez; 
	
	public final static String NOMBRE_FICHERO_CRT = "CertificadoCA.crt";
	public final static String NOMBRE_FICHERO_CLAVES = "CA-claves";
	
	private RSAKeyParameters clavePrivadaCA = null;
	private RSAKeyParameters clavePublicaCA = null;
	
	/**
	 * Constructor de la CA. 
	 * Inicializa atributos de la CA a valores por defecto
	 */
	public CA () {
		// Distinguished Name DN. C Country, O Organization name, CN Common Name. 
		this.nombreEmisor = new X500Name ("C=ES, O=DTE, CN=CA");
		this.numSerie = BigInteger.valueOf(1);
		this.añosValidez = 1; // Son los años de validez del certificado de usuario, para la CA el valor es 4
	}
	
	/**
	* Método que genera la parejas de claves y el certificado autofirmado de la CA.
	* @throws OperatorCreationException
	* @throws IOException 
	*/
	public void generarClavesyCertificado() throws OperatorCreationException, IOException {
      // Generar una pareja de claves (clase GestionClaves) y guardarlas EN FORMATO PEM en los ficheros 
      // indicados por NOMBRE_FICHERO_CLAVES (añadiendo al nombre las cadenas "_pri.txt" y "_pu.txt")
		
		// Esto es nuevo respecto de la P1. Se debe instanciar un objeto de la clase GestionClaves proporcionada
		// Tanto en Usuario como en CA
		GestionClaves gc = new GestionClaves (); 
				
		// Asignar claves a los atributos correspondientes
		AsymmetricCipherKeyPair claves = gc.generarClaves(BigInteger.valueOf(3), 2048);
		clavePublicaCA = (RSAKeyParameters) claves.getPublic();
		clavePrivadaCA = (RSAKeyParameters) claves.getPrivate();
						
	    /*Ahora generamos las key con los formatos que se nos pide en la practica  (segun pdf 1ºparte formato ASN1)
		 * y lo guardamos en array de bytes como en la P1*/
		SubjectPublicKeyInfo publicInfo = gc.getClavePublicaSPKI(clavePublicaCA);
		PrivateKeyInfo privateInfo = gc.getClavePrivadaPKCS8(clavePrivadaCA);
		byte [] publicKey = publicInfo.getEncoded();
		byte [] privateKey = privateInfo.getEncoded();
				
		// Escribir las claves en un fichero en formato PEM 
		GestionObjetosPEM.escribirObjetoPEM("PUBLIC KEY",publicKey, NOMBRE_FICHERO_CLAVES + "_pri.txt");
		GestionObjetosPEM.escribirObjetoPEM("PRIVATE KEY",privateKey, NOMBRE_FICHERO_CLAVES + "_pu.txt");
	
	// Generar un certificado autofirmado: 
	// 	1. Configurar parámetros para el certificado e instanciar objeto X509v3CertificateBuilder
		Calendar c1 = GregorianCalendar.getInstance();
        Date fechaInicioCert = c1.getTime();
        c1.add(Calendar.YEAR, 4); //añadir 4 años al calendario Para la CA.
    	Date fechaFinCert=c1.getTime(); 
		X509v3CertificateBuilder certBldr = new X509v3CertificateBuilder(nombreEmisor, numSerie, fechaInicioCert, fechaFinCert,
																		nombreEmisor, gc.getClavePublicaSPKI(clavePublicaCA));
		BasicConstraints basicConstraints = new BasicConstraints(3);
		certBldr.addExtension(Extension.basicConstraints,true,basicConstraints.getEncoded());
		
	// 	2. Configurar hash para resumen y algoritmo firma (MIRAR DIAPOSITIVAS DE APOYO EN MOODLE)
		DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();//Firma
		DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();//Resumen
		AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
		AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
		BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

	//	3. Generar certificado
		X509CertificateHolder holder = certBldr.build(csBuilder.build(this.clavePrivadaCA));
	//	4. Guardar el certificado en formato PEM como un fichero con extensión crt (NOMBRE_FICHERO_CRT)
		GestionObjetosPEM.escribirObjetoPEM("CERTIFICATE", holder.getEncoded(), NOMBRE_FICHERO_CRT);
	}




	/**
	 * Método que carga la parejas de claves
	 * @throws IOException 
	 */
	public void cargarClaves () throws IOException{
		// Carga la pareja de claves de los ficheros indicados por NOMBRE_FICHERO_CLAVES 
        // (añadiendo al nombre las cadenas "_pri.txt" y "_pu.txt")
		// No carga el certificado porque se lee de fichero cuando se necesita.
		
		GestionClaves gc = new GestionClaves(); // Clase con métodos para manejar las claves
		//COMPLETAR POR EL ESTUDIANTE

        SubjectPublicKeyInfo publicInfo = (SubjectPublicKeyInfo) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES + "_pu.txt");
        PrivateKeyInfo privateInfo = (PrivateKeyInfo) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES + "_pri.txt");

        clavePublicaCA = gc.getClavePublicaMotor(publicInfo);
        clavePrivadaCA = gc.getClavePrivadaMotor(privateInfo);
	}


	/**
	 * Método que genera el certificado de un usuario a partir de una petición de certificación
	 * @param ficheroPeticion:String. Parámetro con la petición de certificación
	 * @param ficheroCertUsu:String. Parámetro con el nombre del fichero en el que se guardará el certificado del usuario
	 * @throws IOException 
	 * @throws PKCSException 
	 * @throws OperatorCreationException
	 */
	public boolean certificarPeticion(String ficheroPeticion, String ficheroCertUsu) throws IOException, 
	OperatorCreationException, PKCSException{
		return false;
		
		//  Verificar que están generadas las clave privada y pública de la CA
		//  Verificar firma del solicitante (KPSolicitante en fichero de petición) 
		//  Si la verificación es ok, se genera el certificado firmado con la clave privada de la CA
		//  Se guarda el certificado en formato PEM como un fichero con extensión crt

		//  COMPLETAR POR EL ESTUDIANTE



	
	}
	
}
	// EL ESTUDIANTE PODRÁ CODIFICAR TANTOS MÉTODOS PRIVADOS COMO CONSIDERE INTERESANTE PARA UNA MEJOR ORGANIZACIÓN DEL CÓDIGO