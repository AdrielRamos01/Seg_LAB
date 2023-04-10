
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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
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


/**
* Esta clase implementa el comportamiento de una CA
* @author Seg Red Ser
* @version 1.0
*/
public class CA {
	
	private final X500Name nombreEmisor;
	private BigInteger numSerie;
	private final int aniosValidez; 
	
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
		this.aniosValidez = 1; // Son los anios de validez del certificado de usuario, para la CA el valor es 4
	}
	
	/**
	* Metodo que genera la parejas de claves y el certificado autofirmado de la CA.
	* @throws OperatorCreationException
	* @throws IOException 
	*/
	public void generarClavesyCertificado() throws OperatorCreationException, IOException {
		// Generar una pareja de claves (clase GestionClaves) y guardarlas EN FORMATO PEM en los ficheros
        // indicados por NOMBRE_FICHERO_CLAVES (aniadiendo al nombre las cadenas "_pri.txt" y "_pu.txt")
        GestionClaves gc = new GestionClaves();
        AsymmetricCipherKeyPair pair = gc.generarClaves(BigInteger.valueOf(3),2048);

        clavePrivadaCA = (RSAKeyParameters)pair.getPrivate();
        clavePublicaCA = (RSAKeyParameters)pair.getPublic();

        PrivateKeyInfo prInfo = gc.getClavePrivadaPKCS8(clavePrivadaCA);
        SubjectPublicKeyInfo pbInfo = gc.getClavePublicaSPKI(clavePublicaCA);

        byte [] privateKey = prInfo.getEncoded();
        byte [] publicKey = pbInfo.getEncoded();

        GestionObjetosPEM.escribirObjetoPEM("PRIVATE KEY",privateKey, NOMBRE_FICHERO_CLAVES + "_pri.txt");
        GestionObjetosPEM.escribirObjetoPEM("PUBLIC KEY",publicKey, NOMBRE_FICHERO_CLAVES + "_pu.txt");

        // Generar un certificado autofirmado:
        Calendar c1 = GregorianCalendar.getInstance();
        Date fechaInicioCert = c1.getTime();
        c1.add(Calendar.YEAR, 4); //aniadir 4 anios al calendario Para la CA.
    	Date fechaFinCert=c1.getTime();
        // 	1. Configurar parametros para el certificado e instanciar objeto X509v3CertificateBuilder
        X509v3CertificateBuilder CetBldr = new X509v3CertificateBuilder(nombreEmisor, numSerie, fechaInicioCert, fechaFinCert,
        		                                                        nombreEmisor,gc.getClavePublicaSPKI(clavePublicaCA));
        BasicConstraints basicConstraints = new BasicConstraints(3);
        CetBldr.addExtension(Extension.basicConstraints,true,basicConstraints.getEncoded());

        // 	2. Configurar hash para resumen y algoritmo firma (MIRAR DIAPOSITIVAS DE APOYO EN MOODLE)
        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();//Firma
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();//Resumen
        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
        BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

        //	3. Generar certificado
        X509CertificateHolder holder = CetBldr.build(csBuilder.build(this.clavePrivadaCA));

        //	4. Guardar el certificado en formato PEM como un fichero con extension crt (NOMBRE_FICHERO_CRT)
        GestionObjetosPEM.escribirObjetoPEM("CERTIFICATE", holder.getEncoded(), NOMBRE_FICHERO_CRT);
	}




	/**
	 * Metodo que carga la parejas de claves
	 * @throws IOException 
	 */
	public void cargarClaves () throws IOException{
		// Carga la pareja de claves de los ficheros indicados por NOMBRE_FICHERO_CLAVES 
        // (aniadiendo al nombre las cadenas "_pri.txt" y "_pu.txt")
		// No carga el certificado porque se lee de fichero cuando se necesita.
		
		GestionClaves gc = new GestionClaves();
		//COMPLETAR POR EL ESTUDIANTE

        SubjectPublicKeyInfo publicInfo = (SubjectPublicKeyInfo) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES + "_pu.txt");
        PrivateKeyInfo privateInfo = (PrivateKeyInfo) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES + "_pri.txt");

        clavePublicaCA = gc.getClavePublicaMotor(publicInfo);
        clavePrivadaCA = gc.getClavePrivadaMotor(privateInfo);
	}


	
	/**
	 * Metodo que genera el certificado de un usuario a partir de una peticion de certificacion
	 * @param ficheroPeticion:String. Parametro con la peticion de certificacion
	 * @param ficheroCertUsu:String. Parametro con el nombre del fichero en el que se guardara el certificado del usuario
	 * @throws IOException 
	 * @throws PKCSException 
	 * @throws OperatorCreationException
	 */
	public boolean certificarPeticion(String ficheroPeticion, String ficheroCertUsu) throws IOException, OperatorCreationException, PKCSException{
		
		boolean peticionCertificada = false;
		GestionClaves gc = new GestionClaves();
		RSAKeyParameters clavePublicaUsuario = null;
		boolean firmaVerificada = false;
		
		//1. Verificar que las claves de la CA estan generadas
		cargarClaves();
		
		//2. Obtener la informacion necesaria del solicitante contenida en la peticion (ficheroPeticion)
		PKCS10CertificationRequest certCA = (PKCS10CertificationRequest) GestionObjetosPEM.leerObjetoPEM(ficheroPeticion);
        SubjectPublicKeyInfo publicKeyInfoUsu = certCA.getSubjectPublicKeyInfo();
        clavePublicaUsuario = gc.getClavePublicaMotor(publicKeyInfoUsu);
		
		//3. Verificar la firma del solicitante de la peticion. Si la verificacion es OK: pasamos punto 4
        DefaultDigestAlgorithmIdentifierFinder signer = new DefaultDigestAlgorithmIdentifierFinder();
        ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(signer).build(clavePublicaUsuario);

        firmaVerificada = certCA.isSignatureValid(contentVerifierProvider);
        
        if(firmaVerificada) {
    		//4. Configurar e instanciar el builder o contenedor del certificado
        	Calendar c1 = GregorianCalendar.getInstance();
            Date fechaInicioCert = c1.getTime();
            c1.add(Calendar.YEAR, aniosValidez); //aniadir 4 anios al calendario Para la CA.
        	Date fechaFinCert=c1.getTime(); 
    		X509v3CertificateBuilder certBldr = new X509v3CertificateBuilder(nombreEmisor, numSerie, fechaInicioCert, fechaFinCert,
    																		 nombreEmisor, gc.getClavePublicaSPKI(clavePublicaCA));
    		
    		
    		//5. Configurar la firma y firmar el certificado con la clave privada de la CA
    		DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();//Firma
    		DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();//Resumen
    		AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
    		AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
    		BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
    		
    		//Generamos el certificado
    		X509CertificateHolder holder = certBldr.build(csBuilder.build(this.clavePrivadaCA));
    		
    		//6. Guardar certificado en formato PEM (ficheroCertUsu)
    		GestionObjetosPEM.escribirObjetoPEM("CERTIFICATE", holder.getEncoded(), ficheroCertUsu);
    		
    		//LA PETICION HA SIDO VERIFICADA
    		peticionCertificada = true;
    		
    		System.out.println("Peticion Certificada");
        	
        }
		
		return peticionCertificada;
	
	}

}
