
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

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
* Esta clase implementa el comportamiento de un usuario en una Infraestructura de Certificacion
* @author Seg Red Ser
* @version 1.0
*/
public class Usuario {
	
	private RSAKeyParameters clavePrivada = null;
	private RSAKeyParameters clavePublica = null;


	/**
	 * Metodo que genera las claves del usuario.
	 * @param fichClavePrivada: String con el nombre del fichero donde se guardara la clave privada en formato PEM
	 * @param fichClavePublica: String con el nombre del fichero donde se guardara la clave publica en formato PEM
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
				
		/*Ahora generamos las key con los formatos que se nos pide en la practica  (segun pdf 1 parte formato ASN1)
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
	 * Metodo que genera una peticion de certificado en formato PEM, almacenando esta peticion en un fichero.
	 * @param fichPeticion: String con el nombre del fichero donde se guardara la peticion de certificado
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public void crearPetCertificado(String fichPeticion) throws OperatorCreationException, IOException {
 
	   	// Configurar hash para resumen y algoritmo firma (MIRAR DIAPOSITIVAS PRESENTACION PRACTICA)
		// La solicitud se firma con la clave privada del usuario y se escribe en fichPeticion en formato PEM
		
		//EL usuario instancia un Objeto de la clase PKCS10CertificationRequestBuilder que contiene la informacion de la peticion. (1)
        PKCS10CertificationRequestBuilder requestBuilder = new BcPKCS10CertificationRequestBuilder(new X500Name("C=ES, O=DTE, CN=Adriel"), this.clavePublica);
		
		//Configura el resumen y la firma. Instancia un objeto de la clase BcContentSignerBuilder. (2)
        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
        BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
        PKCS10CertificationRequest pet = requestBuilder.build(csBuilder.build(this.clavePrivada));

        byte [] petToByte = pet.getEncoded();
        //guardamos el fichero de la peticion en formato PEM
        GestionObjetosPEM.escribirObjetoPEM("CERTIFICATE REQUEST",petToByte, fichPeticion);
	}
	
	
	/**
	 * Metodo que verifica un certificado de una entidad.
	 * @param fichCertificadoCA: String con el nombre del fichero donde se encuentra el certificado de la CA
	 * @param fichCertificadoUsu: String con el nombre del fichero donde se encuentra el certificado de la entidad
     	 * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws FileNotFoundException 	
	 * @return boolean: true si verificacion OK, false en caso contrario.
	 */
    public boolean verificarCertificadoExterno(String fichCertificadoCA, String fichCertificadoUsu)throws OperatorCreationException, 
    																									  CertException, FileNotFoundException, 
    																									  IOException {
		
    	boolean certificadoVerificado = false;
    	boolean fechaVerificada = false;
    	RSAKeyParameters clavePublicaCA = null;
    	
    	//Leemos certificado y Comprobar fecha validez del certificado
    	X509CertificateHolder certUsuario = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoUsu);
    	
        Date NotBefore = certUsuario.getNotBefore();
        Date notAfter = certUsuario.getNotAfter();
        Calendar calendar = GregorianCalendar.getInstance();
        Date now = calendar.getTime();
        
        if (!now.after(notAfter) && !now.before(NotBefore)){
        	fechaVerificada = true;
        	System.out.println("Fecha verificada");
        } else {
        	System.out.println("Fecha no verificada");
        }
    	
    	// Si la fecha es valida, se comprueba la firma
    	if(fechaVerificada) {
    		//Leer fichCertificadoCA (certificado CA) 
            X509CertificateHolder certCA = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoCA);
            GestionClaves gc = new GestionClaves();
            clavePublicaCA = gc.getClavePublicaMotor(certCA.getSubjectPublicKeyInfo());
            
    		//Generar un contenedor para la verificacion. 
            DefaultDigestAlgorithmIdentifierFinder signer = new DefaultDigestAlgorithmIdentifierFinder();
            ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(signer).build(clavePublicaCA);
            
    		//Verificar firma
            certificadoVerificado = certUsuario.isSignatureValid(contentVerifierProvider);
    	}
    
    	return certificadoVerificado;
	}	
}

	