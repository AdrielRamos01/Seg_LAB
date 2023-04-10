
import java.util.Scanner;


public class Principal {
	
	public static void main(String[] args) throws Exception {
		// Se pueden tratar las exceptiones en lugar de implementar throws

		Usuario u = new Usuario();
		CA ca = new CA();
		
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		String fichero;
		
		//Para trabajo como usuario
		String ficheroClavePrivada;
		String ficheroClavePublica;
		
		//Para trabajo como CA
		String ficheroCA=null;
		String ficheroCertUsu=null;
		
		do {
		  	System.out.println("¿Con que rol desea trabajar?");
			System.out.println("1. Trabajar como usuario.");
			System.out.println("2. Trabajar como Autoridad de Certificacion.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opcion para trabajar como USUARIO:");
						System.out.println("0. Volver al menu anterior.");
						System.out.println("1. Generar pareja de claves en formato PEM.");
						System.out.println("2. Crear peticion de certificacion.");
						System.out.println("3. Verificar certificado externo.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1://Generar pareja de claves.
								System.out.println("OPCION GENERA PAREJA DE CLAVES");
								System.out.println("Escriba el nombre del fichero que contendra la clave privada:");
								ficheroClavePrivada = sc.next();
								System.out.println("Escriba el nombre del fichero que contendra la clave publica:");
								ficheroClavePublica = sc.next();
								u.generarClavesUsuario(ficheroClavePrivada, ficheroClavePublica);
								
								
							break;
							case 2://Crear peticion de certificado.
								System.out.println("Escriba nombre fichero para la peticion de certificacion:");
								fichero= sc.next();
								//COMPLETAR POR EL ESTUDIANTE
								u.crearPetCertificado(fichero);

							    	
								
							break;
							case 3://Verificar certificado externo.
							    	System.out.println("Escriba el nombre del fichero que contiene el certificado del usuario:");
								fichero = sc.next();
							    	System.out.println("Escriba el nombre del fichero que contiene el certificado de la CA:");
								ficheroCA = sc.next();
								//COMPLETAR POR EL ESTUDIANTE 
								if(u.verificarCertificadoExterno(ficheroCA, fichero)) {
									System.out.println("Se ha verificado el certificado correctamente");
								} else {
									System.out.println("No se ha verificado el certificado");
								}
				        
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opcion para trabajar como CA:");
						System.out.println("0. Volver al menu anterior.");
						System.out.println("1. Generar pareja de claves y certificado autofirmado.");
						System.out.println("2. Cargar pareja de claves.");
						System.out.println("3. Generar un certificado a partir de una peticion.");
						menu2 = sc.nextInt();
						switch(menu2){
							case 1:	//Generar pareja de claves, el certificado X509 y guardar en ficheros.
								//COMPLETAR POR EL ESTUDIANTE   
								ca.generarClavesyCertificado();
								System.out.println("Claves y certificados X509 GENERADOS");
								System.out.println("Se han guardado en " + CA.NOMBRE_FICHERO_CRT + ", " + CA.NOMBRE_FICHERO_CLAVES + "-*.txt");									
							break;
							case 2: //Cargar de fichero pareja de claves
								//COMPLETAR POR EL ESTUDIANTE  
								ca.cargarClaves();
								System.out.println("Claves CARGADAS");
								System.out.println("Se han cargado de " + CA.NOMBRE_FICHERO_CLAVES + "-*.txt");		
							break;
							case 3:// Generar certificado a partir de una peticion
								    System.out.println("Escriba el nombre del fichero que contiene la peticion de certificacion del usuario:");
								    fichero = sc.next();
								    System.out.println("Escriba el nombre del fichero que contendra el certificado emitido por la CA para el usuario:");
								    ficheroCertUsu = sc.next();
								    // A COMPLETAR ESTUDIANTE
								    if(ca.certificarPeticion(fichero, ficheroCertUsu)) {
								    	System.out.println("Se ha generado el certificado de la peticion correctamente");
								    } else {
								    	System.out.println("No se ha generado el certificado de la peticion");
								    }
								    
							break;							
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
     
		sc.close();         
	}	
}
